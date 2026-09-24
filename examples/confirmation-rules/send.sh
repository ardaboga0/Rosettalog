#!/bin/sh
# Send one rule confirmation case's sample.log to QRadar over syslog/UDP, one event per second.
# A line "# sleep N" pauses N seconds instead (used by counter/sequence cases).
# Usage: ./send.sh <qradar-host> <case-directory> [port]
# Requires `nc` (netcat).
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
  case $line in
    "# sleep "*)
      secs=${line#"# sleep "}
      echo "sleeping ${secs}s"
      sleep "$secs"
      continue
      ;;
  esac
  # The syslog header time in sample.log is a placeholder: send the current time instead, so
  # that the pauses above are also visible in the events' own timestamps.
  now=$(LC_ALL=C date '+%b %e %H:%M:%S')
  line=$(printf '%s' "$line" | sed "s/^<13>Mar 24 10:00:00 /<13>$now /")
  printf '%s\n' "$line" | nc -u -w1 "$host" "$port"
  echo "sent: $line"
  sleep 1
done < "$dir/sample.log"
