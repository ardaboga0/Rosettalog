#!/bin/sh
# Send one confirmation case's sample.log to QRadar over syslog/UDP, one event per second.
# Usage: ./send.sh <qradar-host> <case-directory> [port]
# Requires `nc` (netcat). Alternative: logger --server HOST --port 514 --udp --rfc3164 ...
set -eu
if [ "$#" -lt 2 ]; then
  echo "usage: $0 <qradar-host> <case-directory> [port]" >&2
  exit 1
fi
host=$1
dir=$2
port=${3:-514}
while IFS= read -r line || [ -n "$line" ]; do
  [ -n "$line" ] || continue
  printf '%s\n' "$line" | nc -u -w1 "$host" "$port"
  echo "sent: $line"
  sleep 1
done < "$dir/sample.log"
