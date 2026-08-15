#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

set -a
source "$BASE_DIR/.env"
set +a

: "${TUNNEL_DOMAIN:?TUNNEL_DOMAIN is required}"
: "${CONTROL_PLANE_UID:=1000}"
: "${CONTROL_PLANE_GID:=1000}"
[[ "$CONTROL_PLANE_UID" =~ ^[0-9]+$ ]] || { echo "CONTROL_PLANE_UID must be numeric" >&2; exit 1; }
[[ "$CONTROL_PLANE_GID" =~ ^[0-9]+$ ]] || { echo "CONTROL_PLANE_GID must be numeric" >&2; exit 1; }

HOOK_PATH="/etc/letsencrypt/renewal-hooks/deploy/sish-cert.sh"
TMP_FILE="$(mktemp)"

trap 'rm -f "$TMP_FILE"' EXIT

cat > "$TMP_FILE" <<EOF
#!/usr/bin/env bash
set -euo pipefail

install -o "${CONTROL_PLANE_UID}" -g "${CONTROL_PLANE_GID}" -m 0644 \
  "/etc/letsencrypt/live/${TUNNEL_DOMAIN}/fullchain.pem" \
  "${BASE_DIR}/ssl/${TUNNEL_DOMAIN}.crt"

install -o "${CONTROL_PLANE_UID}" -g "${CONTROL_PLANE_GID}" -m 0640 \
  "/etc/letsencrypt/live/${TUNNEL_DOMAIN}/privkey.pem" \
  "${BASE_DIR}/ssl/${TUNNEL_DOMAIN}.key"

docker compose \
  -f "${BASE_DIR}/compose.yml" \
  restart sish
EOF

sudo install -m 755 "$TMP_FILE" "$HOOK_PATH"

echo "Installed Certbot deploy hook:"
echo "  $HOOK_PATH"
