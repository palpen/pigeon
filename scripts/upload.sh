#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then
  echo 'Usage: upload.sh /path/to/report.md' >&2
  exit 2
fi
PIGEON_URL=${PIGEON_URL:-${RELAY_URL:-http://127.0.0.1:8787}}
# curl quote syntax protects special characters in local paths.
PIGEON_FILE=$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')
curl --fail-with-body --silent --show-error -H 'X-Pigeon-Request: 1' -F "file=@\"$PIGEON_FILE\"" "$PIGEON_URL/api/files"
