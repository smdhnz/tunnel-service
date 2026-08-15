#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

set -a
source "$BASE_DIR/.env"
set +a

: "${TUNNEL_DOMAIN:?TUNNEL_DOMAIN is required}"

HOOK_PATH="/etc/letsencrypt/renewal-hooks/deploy/sish-cert.sh"
TMP_FILE="$(mktemp)"

trap 'rm -f "$TMP_FILE"' EXIT

cat > "$TMP_FILE" <<EOF
#!/usr/bin/env bash
set -euo pipefail

cp "/etc/letsencrypt/live/${TUNNEL_DOMAIN}/fullchain.pem" \
   "${BASE_DIR}/ssl/${TUNNEL_DOMAIN}.crt"

cp "/etc/letsencrypt/live/${TUNNEL_DOMAIN}/privkey.pem" \
   "${BASE_DIR}/ssl/${TUNNEL_DOMAIN}.key"

docker compose \
  -f "${BASE_DIR}/compose.yml" \
  restart sish
EOF

sudo install -m 755 "$TMP_FILE" "$HOOK_PATH"

echo "Installed Certbot deploy hook:"
echo "  $HOOK_PATH"
