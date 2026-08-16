#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { printf 'test failure: %s\n' "$*" >&2; exit 1; }
new_fixture() {
  FIXTURE="$(mktemp -d)"
  mkdir -p "$FIXTURE/scripts"
  cp "$ROOT/scripts/setup.sh" "$ROOT/scripts/certbot-auth.sh" "$ROOT/scripts/certbot-cleanup.sh" "$FIXTURE/scripts/"
  cat > "$FIXTURE/.env" <<EOF
TUNNEL_DOMAIN=example.test
SSH_HOST=ssh.example.test
CONTROL_PLANE_SUBDOMAIN=console
DISCORD_CLIENT_ID=id
DISCORD_CLIENT_SECRET=discord-secret
ADMIN_DISCORD_IDS=1
VERCEL_TOKEN=vercel-secret
SISH_CONTROL_PLANE_MODE=required
CONTROL_PLANE_UID=$(id -u)
CONTROL_PLANE_GID=$(id -g)
EOF
}
cleanup() { rm -rf "${FIXTURE:-}"; }
trap cleanup EXIT

new_fixture
"$FIXTURE/scripts/setup.sh" > "$FIXTURE/first.out"
for path in data pubkeys keys ssl secrets secrets/control-plane-internal-token secrets/sish-management-token secrets/session-secret secrets/discord-client-secret secrets/vercel-token secrets/control-plane-tunnel-key secrets/control-plane-tunnel-key.pub secrets/sish-known-hosts keys/ssh_key pubkeys/system-control-plane.pub; do
  [[ -e "$FIXTURE/$path" ]] || fail "first run did not create $path"
done
grep -q 'https://console.example.test' "$FIXTURE/first.out" || fail "generated control-plane host missing"
[[ "$(stat -c %a "$FIXTURE/secrets/control-plane-tunnel-key")" == 600 ]] || fail "private key mode"
[[ "$(stat -c %a "$FIXTURE/secrets/control-plane-tunnel-key.pub")" == 640 ]] || fail "public key mode"
[[ "$(stat -c %a "$FIXTURE/keys/ssh_key")" == 640 ]] || fail "sish host key mode"
[[ "$(stat -c %a "$FIXTURE/secrets/control-plane-internal-token")" == 640 ]] || fail "internal token mode"
[[ "$(stat -c %a "$FIXTURE/secrets/sish-management-token")" == 640 ]] || fail "management token mode"
for file in session-secret discord-client-secret vercel-token control-plane-tunnel-key sish-known-hosts; do
  [[ "$(stat -c %a "$FIXTURE/secrets/$file")" == 600 ]] || fail "$file mode"
done
[[ "$(stat -c %u:%g "$FIXTURE/data")" == "$(id -u):$(id -g)" ]] || fail "directory owner"
ssh-keygen -F '[ssh.example.test]:2222' -f "$FIXTURE/secrets/sish-known-hosts" >/dev/null || fail "known_hosts host/port"
cp "$FIXTURE/keys/ssh_key" "$FIXTURE/host-private-for-test"
chmod 0600 "$FIXTURE/host-private-for-test"
cmp -s <(ssh-keygen -y -f "$FIXTURE/host-private-for-test" | awk '{print $1, $2}') <(awk 'NR == 1 {print $2, $3}' "$FIXTURE/secrets/sish-known-hosts") || fail "known_hosts key material"
rm "$FIXTURE/host-private-for-test"
cp "$FIXTURE/keys/ssh_key.pub" "$FIXTURE/host-public.expected"
find "$FIXTURE/secrets" "$FIXTURE/keys" "$FIXTURE/pubkeys" -type f -exec sha256sum {} + | sort > "$FIXTURE/before.sha"
"$FIXTURE/scripts/setup.sh" >/dev/null
find "$FIXTURE/secrets" "$FIXTURE/keys" "$FIXTURE/pubkeys" -type f -exec sha256sum {} + | sort > "$FIXTURE/after.sha"
cmp -s "$FIXTURE/before.sha" "$FIXTURE/after.sha" || fail "rerun overwrote generated files"
cmp -s "$FIXTURE/host-public.expected" "$FIXTURE/keys/ssh_key.pub" || fail "existing host public key overwritten"
printf 'keep-me' > "$FIXTURE/secrets/session-secret"
cp "$FIXTURE/secrets/sish-known-hosts" "$FIXTURE/known-hosts.expected"
rm "$FIXTURE/secrets/control-plane-internal-token" "$FIXTURE/secrets/control-plane-tunnel-key.pub" "$FIXTURE/secrets/sish-known-hosts"
"$FIXTURE/scripts/setup.sh" >/dev/null
[[ "$(cat "$FIXTURE/secrets/session-secret")" == keep-me ]] || fail "existing secret overwritten"
[[ -s "$FIXTURE/secrets/control-plane-internal-token" && -s "$FIXTURE/secrets/control-plane-tunnel-key.pub" ]] || fail "missing secret or public key not restored"
cmp -s "$FIXTURE/known-hosts.expected" "$FIXTURE/secrets/sish-known-hosts" || fail "known_hosts not restored"
cleanup

new_fixture
sed -i '/^VERCEL_TOKEN=/d' "$FIXTURE/.env"
if "$FIXTURE/scripts/setup.sh" >/dev/null 2>&1; then fail "missing env accepted"; fi
[[ ! -e "$FIXTURE/data" ]] || fail "env validation was not fail-fast"
cleanup

new_fixture
sed -i 's/^CONTROL_PLANE_UID=.*/CONTROL_PLANE_UID=not-a-number/' "$FIXTURE/.env"
if "$FIXTURE/scripts/setup.sh" >/dev/null 2>&1; then fail "invalid UID accepted"; fi
cleanup

new_fixture
sed -i 's/^CONTROL_PLANE_GID=.*/CONTROL_PLANE_GID=99999/' "$FIXTURE/.env"
if "$FIXTURE/scripts/setup.sh" >/dev/null 2>&1; then fail "mismatched GID accepted"; fi
cleanup

new_fixture
sed -i 's/^CONTROL_PLANE_UID=.*/CONTROL_PLANE_UID=0/' "$FIXTURE/.env"
if "$FIXTURE/scripts/setup.sh" >/dev/null 2>&1; then fail "root UID accepted"; fi
[[ ! -e "$FIXTURE/data" ]] || fail "root UID validation was not fail-fast"
cleanup

new_fixture
sed -i 's/^CONTROL_PLANE_GID=.*/CONTROL_PLANE_GID=0/' "$FIXTURE/.env"
if "$FIXTURE/scripts/setup.sh" >/dev/null 2>&1; then fail "root GID accepted"; fi
[[ ! -e "$FIXTURE/data" ]] || fail "root GID validation was not fail-fast"
cleanup

long_domain="$(printf 'a%.0s' {1..63}).$(printf 'b%.0s' {1..63}).$(printf 'c%.0s' {1..63}).$(printf 'd%.0s' {1..63})"
for invalid_domain in 'single' 'example..test' '-bad.test' 'bad-.test' 'example.test.' "$(printf 'a%.0s' {1..64}).test" "$long_domain"; do
  new_fixture
  sed -i "s/^TUNNEL_DOMAIN=.*/TUNNEL_DOMAIN=$invalid_domain/" "$FIXTURE/.env"
  if "$FIXTURE/scripts/setup.sh" >/dev/null 2>&1; then fail "invalid TUNNEL_DOMAIN accepted: $invalid_domain"; fi
  [[ ! -e "$FIXTURE/data" ]] || fail "domain validation was not fail-fast"
  cleanup
done
for invalid_host in 'ssh' 'ssh..example.test' '-ssh.example.test' 'ssh-.example.test' 'ssh.example.test.' "$(printf 'a%.0s' {1..64}).example.test"; do
  new_fixture
  sed -i "s/^SSH_HOST=.*/SSH_HOST=$invalid_host/" "$FIXTURE/.env"
  if "$FIXTURE/scripts/setup.sh" >/dev/null 2>&1; then fail "invalid SSH_HOST accepted: $invalid_host"; fi
  [[ ! -e "$FIXTURE/data" ]] || fail "host validation was not fail-fast"
  cleanup
done

new_fixture
outside="$(mktemp -d)"
printf 'outside' > "$outside/marker"
ln -s "$outside" "$FIXTURE/data"
if "$FIXTURE/scripts/setup.sh" >/dev/null 2>&1; then fail "persistent directory symlink accepted"; fi
[[ "$(cat "$outside/marker")" == outside ]] || fail "symlink target changed"
rm -rf "$outside"
cleanup

new_fixture
outside="$(mktemp -d)"
mkdir "$FIXTURE/data"
printf 'outside' > "$outside/file"
ln "$outside/file" "$FIXTURE/data/hardlink"
if "$FIXTURE/scripts/setup.sh" >/dev/null 2>&1; then fail "persistent hard link accepted"; fi
[[ "$(cat "$outside/file")" == outside ]] || fail "hard link target changed"
rm -rf "$outside"
cleanup

new_fixture
"$FIXTURE/scripts/setup.sh" >/dev/null
mkdir "$FIXTURE/fake-bin"
cat > "$FIXTURE/fake-bin/curl" <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *' -X DELETE '* ]]; then
  [[ "${FAIL_DELETE:-0}" != 1 ]] || exit 22
  exit 0
fi
printf '{"uid":"record_123"}'
EOF
cat > "$FIXTURE/fake-bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$FIXTURE/fake-bin/curl" "$FIXTURE/fake-bin/sleep"
CERTBOT_VALIDATION=challenge PATH="$FIXTURE/fake-bin:$PATH" "$FIXTURE/scripts/certbot-auth.sh"
state="$FIXTURE/secrets/.certbot-vercel-record-id"
[[ "$(cat "$state")" == record_123 && "$(stat -c %a "$state")" == 600 ]] || fail "certbot state not stored securely"
if CERTBOT_VALIDATION=challenge PATH="$FIXTURE/fake-bin:$PATH" "$FIXTURE/scripts/certbot-auth.sh" >/dev/null 2>&1; then fail "certbot auth overwrote previous state"; fi
if FAIL_DELETE=1 PATH="$FIXTURE/fake-bin:$PATH" "$FIXTURE/scripts/certbot-cleanup.sh" >/dev/null 2>&1; then fail "certbot cleanup ignored DELETE failure"; fi
[[ -f "$state" ]] || fail "certbot cleanup removed retry state on failure"
PATH="$FIXTURE/fake-bin:$PATH" "$FIXTURE/scripts/certbot-cleanup.sh"
[[ ! -e "$state" ]] || fail "certbot cleanup kept state after successful DELETE"
ln -s "$FIXTURE/.env" "$state"
if PATH="$FIXTURE/fake-bin:$PATH" "$FIXTURE/scripts/certbot-cleanup.sh" >/dev/null 2>&1; then fail "certbot cleanup accepted symlink state"; fi
[[ -L "$state" ]] || fail "certbot cleanup changed symlink state"
cleanup
printf 'setup tests: ok\n'
