#!/usr/bin/env bash
set -euo pipefail
umask 077

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$BASE_DIR/.env"
fail() { printf 'setup error: %s\n' "$*" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required"; }

[[ -f "$ENV_FILE" ]] || fail ".env not found (copy .env.example first)"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

for name in TUNNEL_DOMAIN SSH_HOST CONTROL_PLANE_SUBDOMAIN DISCORD_CLIENT_ID DISCORD_CLIENT_SECRET ADMIN_DISCORD_IDS VERCEL_TOKEN CONTROL_PLANE_UID CONTROL_PLANE_GID; do
  [[ -n "${!name:-}" ]] || fail "$name is required"
done
[[ "$CONTROL_PLANE_UID" =~ ^[0-9]+$ ]] || fail "CONTROL_PLANE_UID must be numeric"
[[ "$CONTROL_PLANE_GID" =~ ^[0-9]+$ ]] || fail "CONTROL_PLANE_GID must be numeric"
[[ "$CONTROL_PLANE_UID" != 0 && "$CONTROL_PLANE_GID" != 0 ]] || fail "CONTROL_PLANE_UID/GID must be non-zero"
[[ "$CONTROL_PLANE_SUBDOMAIN" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || fail "CONTROL_PLANE_SUBDOMAIN is invalid"
valid_hostname() {
  local hostname="$1" min_labels="$2" label
  local -a labels
  [[ ${#hostname} -le 253 && "$hostname" != .* && "$hostname" != *. && "$hostname" != *..* ]] || return 1
  IFS='.' read -r -a labels <<< "$hostname"
  [[ ${#labels[@]} -ge $min_labels ]] || return 1
  for label in "${labels[@]}"; do
    [[ ${#label} -le 63 && "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
}
valid_hostname "$TUNNEL_DOMAIN" 2 || fail "TUNNEL_DOMAIN is invalid"
valid_hostname "$SSH_HOST" 2 || fail "SSH_HOST is invalid"
[[ "$ADMIN_DISCORD_IDS" =~ ^[0-9]+([[:space:]]*,[[:space:]]*[0-9]+)*$ ]] || fail "ADMIN_DISCORD_IDS is invalid"
case "${SISH_CONTROL_PLANE_MODE:-required}" in audit|required) ;; *) fail "SISH_CONTROL_PLANE_MODE must be audit or required" ;; esac

current_uid="$(id -u)"; current_gid="$(id -g)"
if [[ "$current_uid" != 0 && ( "$CONTROL_PLANE_UID" != "$current_uid" || "$CONTROL_PLANE_GID" != "$current_gid" ) ]]; then
  fail "CONTROL_PLANE_UID/GID must match the current user (or run setup as root)"
fi
for cmd in install openssl ssh-keygen cmp stat find chown; do require_command "$cmd"; done

install_dir() {
  local path="$1" unexpected root_device
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -d "$path" && ! -L "$path" ]] || fail "persistent path must be a real directory: $path"
  else
    install -d -m 0750 "$path"
  fi
  chmod 0750 "$path"
  unexpected="$(find -P "$path" -xdev -mindepth 1 \( -type l -o \( -type f -links +1 \) \) -print -quit)"
  [[ -z "$unexpected" ]] || fail "unsafe symlink or hard link in persistent directory: $unexpected"
  root_device="$(stat -c %d "$path")"
  unexpected="$(
    while IFS= read -r -d '' entry; do
      [[ "$(stat -c %d "$entry")" == "$root_device" ]] || { printf '%s' "$entry"; break; }
    done < <(find -P "$path" -xdev -mindepth 1 -print0)
  )"
  [[ -z "$unexpected" ]] || fail "mounted filesystem in persistent directory: $unexpected"
  if [[ "$current_uid" == 0 ]]; then
    find -P "$path" -xdev -exec chown -h "$CONTROL_PLANE_UID:$CONTROL_PLANE_GID" -- {} +
  fi
  unexpected="$(find -P "$path" -xdev \( ! -uid "$CONTROL_PLANE_UID" -o ! -gid "$CONTROL_PLANE_GID" \) -print -quit)"
  [[ -z "$unexpected" ]] || fail "wrong owner: $unexpected"
  [[ "$(stat -c %a "$path")" == 750 ]] || fail "wrong mode: $path"
}
for dir in data pubkeys keys ssl secrets; do install_dir "$BASE_DIR/$dir"; done

own_file() {
  local path="$1" mode="$2"
  if [[ "$current_uid" == 0 ]]; then chown "$CONTROL_PLANE_UID:$CONTROL_PLANE_GID" "$path"; fi
  chmod "$mode" "$path"
  [[ "$(stat -c %u "$path")" == "$CONTROL_PLANE_UID" && "$(stat -c %g "$path")" == "$CONTROL_PLANE_GID" ]] || fail "wrong owner: $path"
  [[ "$(stat -c %a "$path")" == "${mode#0}" ]] || fail "wrong mode: $path"
}
create_random() {
  local path="$1" mode="$2"
  if [[ ! -e "$path" ]]; then
    local tmp; tmp="$(mktemp "$BASE_DIR/secrets/.setup.XXXXXX")"
    openssl rand -base64 48 > "$tmp" || { rm -f "$tmp"; fail "secret generation failed"; }
    mv "$tmp" "$path"
  fi
  [[ -f "$path" && -s "$path" ]] || fail "invalid secret file: $path"
  own_file "$path" "$mode"
}
copy_secret() {
  local value="$1" path="$2"
  if [[ ! -e "$path" ]]; then
    local tmp; tmp="$(mktemp "$BASE_DIR/secrets/.setup.XXXXXX")"
    printf '%s' "$value" > "$tmp" || { rm -f "$tmp"; fail "secret copy failed"; }
    mv "$tmp" "$path"
  fi
  [[ -f "$path" && -s "$path" ]] || fail "invalid secret file: $path"
  own_file "$path" 0600
}
for name in control-plane-internal-token sish-management-token; do create_random "$BASE_DIR/secrets/$name" 0640; done
create_random "$BASE_DIR/secrets/session-secret" 0600
copy_secret "$DISCORD_CLIENT_SECRET" "$BASE_DIR/secrets/discord-client-secret"
copy_secret "$VERCEL_TOKEN" "$BASE_DIR/secrets/vercel-token"

if [[ ! -e "$BASE_DIR/keys/ssh_key" ]]; then
  ssh-keygen -q -t ed25519 -N '' -C sish-host -f "$BASE_DIR/keys/ssh_key"
fi
[[ -f "$BASE_DIR/keys/ssh_key" && -s "$BASE_DIR/keys/ssh_key" ]] || fail "invalid sish host key"
# OpenSSH refuses group-readable private keys, so validate while temporarily
# owner-only, then restore the group-readable mode required by sish's GID.
own_file "$BASE_DIR/keys/ssh_key" 0600
host_public="$(ssh-keygen -y -f "$BASE_DIR/keys/ssh_key")" || fail "invalid sish host key"
host_key_pub="$BASE_DIR/keys/ssh_key.pub"
if [[ -e "$host_key_pub" ]]; then
  [[ -f "$host_key_pub" && -s "$host_key_pub" ]] || fail "invalid sish host public key"
  cmp -s <(printf '%s\n' "$host_public" | awk '{print $1, $2}') <(awk '{print $1, $2}' "$host_key_pub") || fail "sish host key pair does not match"
  own_file "$host_key_pub" 0640
fi
own_file "$BASE_DIR/keys/ssh_key" 0640

control_key="$BASE_DIR/secrets/control-plane-tunnel-key"
if [[ ! -e "$control_key" && ! -e "$control_key.pub" ]]; then
  ssh-keygen -q -t ed25519 -N '' -C control-plane-tunnel -f "$control_key"
elif [[ -f "$control_key" && -s "$control_key" && ! -e "$control_key.pub" ]]; then
  ssh-keygen -y -f "$control_key" | awk '{print $1, $2, "control-plane-tunnel"}' > "$control_key.pub"
fi
[[ -f "$control_key" && -s "$control_key" && -f "$control_key.pub" && -s "$control_key.pub" ]] || fail "control-plane key pair is incomplete"
cmp -s <(ssh-keygen -y -f "$control_key" | awk '{print $1, $2}') <(awk '{print $1, $2}' "$control_key.pub") || fail "control-plane key pair does not match"
own_file "$control_key" 0600
own_file "$control_key.pub" 0640

sish_pub="$BASE_DIR/pubkeys/system-control-plane.pub"
if [[ ! -e "$sish_pub" ]]; then install -m 0640 "$control_key.pub" "$sish_pub"; fi
cmp -s "$control_key.pub" "$sish_pub" || fail "$sish_pub does not match the system key"
own_file "$sish_pub" 0640

known_hosts="$BASE_DIR/secrets/sish-known-hosts"
printf '[%s]:2222 %s\n' "$SSH_HOST" "$host_public" > "$known_hosts.expected"
if [[ ! -e "$known_hosts" ]]; then mv "$known_hosts.expected" "$known_hosts"
elif ! cmp -s "$known_hosts.expected" "$known_hosts"; then rm -f "$known_hosts.expected"; fail "$known_hosts does not match SSH_HOST and the persistent sish host key"
else rm -f "$known_hosts.expected"
fi
own_file "$known_hosts" 0600

printf 'Setup complete. Docker was not started.\n'
printf 'Control Plane: https://%s.%s\n' "$CONTROL_PLANE_SUBDOMAIN" "$TUNNEL_DOMAIN"
printf 'SSH host fingerprint: '
ssh-keygen -lf "$BASE_DIR/keys/ssh_key" | awk '{print $2 " (" $4 ")"}'
if [[ ! -s "$BASE_DIR/ssl/$TUNNEL_DOMAIN.crt" || ! -s "$BASE_DIR/ssl/$TUNNEL_DOMAIN.key" ]]; then
  printf 'TLS certificate is not installed. Complete the README TLS step before docker compose up -d.\n'
else
  printf 'Next: docker compose up -d\n'
fi
