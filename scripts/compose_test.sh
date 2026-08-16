#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="$(mktemp)"; output="$(mktemp)"
trap 'rm -f "$env_file" "$output"' EXIT
cat > "$env_file" <<EOF
TUNNEL_DOMAIN=example.test
SSH_HOST=ssh.example.test
CONTROL_PLANE_SUBDOMAIN=console
DISCORD_CLIENT_ID=test-client
ADMIN_DISCORD_IDS=1
SISH_CONTROL_PLANE_MODE=required
CONTROL_PLANE_UID=$(id -u)
CONTROL_PLANE_GID=$(id -g)
EOF
docker compose -f "$ROOT/compose.yml" --env-file "$env_file" config > "$output"
grep -Fq 'CONTROL_PLANE_HOST: console.example.test' "$output"
grep -Fq 'DISCORD_REDIRECT_URI: https://console.example.test/auth/callback' "$output"
grep -Fq 'REMOTE_LABEL: console' "$output"
grep -Fq 'CONTROL_PLANE_ADDR: 127.0.0.1:8080' "$output"
if grep -Eq '^[[:space:]]+(ports|expose):' "$output"; then
  printf 'compose test: internal ports are exposed\n' >&2
  exit 1
fi
printf 'compose tests: ok\n'
