#!/usr/bin/env bash
set -euo pipefail
umask 077

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="$BASE_DIR/secrets"
STATE_FILE="$STATE_DIR/.certbot-vercel-record-id"

set -a
# shellcheck disable=SC1091
source "$BASE_DIR/.env"
set +a

[[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || { printf 'certbot auth error: secrets must be a real directory\n' >&2; exit 1; }
if [[ -e "$STATE_FILE" || -L "$STATE_FILE" ]]; then
  printf 'certbot auth error: previous DNS record state still exists; run cleanup first\n' >&2
  exit 1
fi

RESPONSE="$(
  curl --fail-with-body -sS -X POST \
    -H "Authorization: Bearer $VERCEL_TOKEN" \
    -H "Content-Type: application/json" \
    "https://api.vercel.com/v2/domains/${TUNNEL_DOMAIN}/records" \
    -d "{\"name\":\"_acme-challenge\",\"type\":\"TXT\",\"value\":\"${CERTBOT_VALIDATION}\",\"ttl\":60}"
)"

RECORD_ID="$(
  printf '%s' "$RESPONSE" |
    python3 -c 'import json,sys; value=json.load(sys.stdin)["uid"]; assert isinstance(value,str) and value; print(value)'
)"
[[ "$RECORD_ID" =~ ^[A-Za-z0-9_-]+$ ]] || { printf 'certbot auth error: invalid record ID\n' >&2; exit 1; }

tmp="$(mktemp "$STATE_DIR/.certbot-vercel-record-id.XXXXXX")"
trap 'rm -f -- "$tmp"' EXIT
printf '%s' "$RECORD_ID" > "$tmp"
chmod 0600 "$tmp"
if ! ln -- "$tmp" "$STATE_FILE"; then
  curl --fail-with-body -sS -X DELETE \
    -H "Authorization: Bearer $VERCEL_TOKEN" \
    "https://api.vercel.com/v2/domains/${TUNNEL_DOMAIN}/records/$RECORD_ID" \
    >/dev/null || true
  printf 'certbot auth error: could not save DNS record state\n' >&2
  exit 1
fi
rm -f -- "$tmp"
trap - EXIT

sleep 30
