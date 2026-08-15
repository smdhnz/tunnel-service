#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

set -a
source "$BASE_DIR/.env"
set +a

RESPONSE="$(
  curl -sS -X POST \
    -H "Authorization: Bearer $VERCEL_TOKEN" \
    -H "Content-Type: application/json" \
    "https://api.vercel.com/v2/domains/${TUNNEL_DOMAIN}/records" \
    -d "{\"name\":\"_acme-challenge\",\"type\":\"TXT\",\"value\":\"${CERTBOT_VALIDATION}\",\"ttl\":60}"
)"

RECORD_ID="$(
  printf '%s' "$RESPONSE" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["uid"])'
)"

printf '%s' "$RECORD_ID" > /tmp/certbot-vercel-record-id

sleep 30
