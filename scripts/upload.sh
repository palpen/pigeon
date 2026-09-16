#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then
  echo 'Usage: upload.sh /path/to/report.md' >&2
  exit 2
fi
PIGEON_URL=${PIGEON_URL:-${RELAY_URL:-http://127.0.0.1:8787}}
# curl quote syntax protects special characters in local paths.
PIGEON_FILE=$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')
if [ -n "${PIGEON_TOKEN_FILE:-}" ]; then
  # Keep the token out of curl's command-line arguments and output.
  PIGEON_TOKEN=$(tr -d '\r\n' < "$PIGEON_TOKEN_FILE")
  if [ "${#PIGEON_TOKEN}" -lt 32 ] || [ "${#PIGEON_TOKEN}" -gt 256 ]; then
    echo 'Invalid token file.' >&2; exit 2
  fi
  case "$PIGEON_TOKEN" in
    ''|*[!A-Za-z0-9_-]*) echo 'Invalid token file.' >&2; exit 2 ;;
  esac
  printf 'Authorization: Bearer %s\n' "$PIGEON_TOKEN" |
    curl --disable --connect-timeout 10 --max-time 125 --fail-with-body --silent --show-error --header @- -H 'X-Pigeon-Request: 1' -F "file=@\"$PIGEON_FILE\"" "$PIGEON_URL/api/files"
else
  curl --disable --connect-timeout 10 --max-time 125 --fail-with-body --silent --show-error -H 'X-Pigeon-Request: 1' -F "file=@\"$PIGEON_FILE\"" "$PIGEON_URL/api/files"
fi
