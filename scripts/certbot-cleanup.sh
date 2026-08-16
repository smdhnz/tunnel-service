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

[[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || { printf 'certbot cleanup error: secrets must be a real directory\n' >&2; exit 1; }
[[ ! -L "$STATE_FILE" ]] || { printf 'certbot cleanup error: record state must not be a symlink\n' >&2; exit 1; }
if [[ -e "$STATE_FILE" ]]; then
  [[ -f "$STATE_FILE" && "$(stat -c %a "$STATE_FILE")" == 600 ]] || { printf 'certbot cleanup error: invalid record state file\n' >&2; exit 1; }
  RECORD_ID="$(cat -- "$STATE_FILE")"
  [[ "$RECORD_ID" =~ ^[A-Za-z0-9_-]+$ ]] || { printf 'certbot cleanup error: invalid record ID\n' >&2; exit 1; }

  # Keep the record ID on API failure so cleanup can be retried safely.
  curl --fail-with-body -sS -X DELETE \
    -H "Authorization: Bearer $VERCEL_TOKEN" \
    "https://api.vercel.com/v2/domains/${TUNNEL_DOMAIN}/records/$RECORD_ID" \
    >/dev/null

  [[ ! -L "$STATE_FILE" && -f "$STATE_FILE" && "$(cat -- "$STATE_FILE")" == "$RECORD_ID" ]] || {
    printf 'certbot cleanup error: record state changed during cleanup\n' >&2
    exit 1
  }
  rm -f -- "$STATE_FILE"
fi
