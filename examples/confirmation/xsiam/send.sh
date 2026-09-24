#!/bin/sh
# Send one XSIAM confirmation case's sample.log to a Custom - HTTP based Collector (Raw format).
# Usage: XSIAM_COLLECTOR_KEY=<api key> ./send.sh <collector-url> <case-directory>
#   collector-url: https://api-<tenant>/logs/v1/event (copy it from the Custom Collectors page)
# The collector's Vendor/Product must be the case's (see its README.md), e.g. rosettalog/rl_x01.
set -eu
if [ "$#" -ne 2 ] || [ -z "${XSIAM_COLLECTOR_KEY:-}" ]; then
  echo "usage: XSIAM_COLLECTOR_KEY=<key> $0 <collector-url> <case-directory>" >&2
  exit 1
fi
curl -sS --fail -X POST "$1" \
  -H "Authorization: $XSIAM_COLLECTOR_KEY" \
  -H "Content-Type: text/plain" \
  --data-binary "@$2/sample.log"
echo "sent $(grep -c . "$2/sample.log") line(s) from $2"
