#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

set -a
source "$BASE_DIR/.env"
set +a

RECORD_ID_FILE="/tmp/certbot-vercel-record-id"

if [ -f "$RECORD_ID_FILE" ]; then
  RECORD_ID="$(cat "$RECORD_ID_FILE")"

  curl -sS -X DELETE \
    -H "Authorization: Bearer $VERCEL_TOKEN" \
    "https://api.vercel.com/v2/domains/${TUNNEL_DOMAIN}/records/$RECORD_ID" \
    >/dev/null

  rm -f "$RECORD_ID_FILE"
fi
