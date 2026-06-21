#!/usr/bin/env bash
set -euo pipefail

LOGCACHE=/home/dev1ls/web/logcache.log
mkdir -p "$(dirname "$LOGCACHE")"
touch "$LOGCACHE"
chmod 644 "$LOGCACHE"

# Tail any readable /var/log files in background so we capture messages
for f in /var/log/auth.log /var/log/syslog /var/log/messages /var/log/secure; do
  if [ -r "$f" ]; then
    nohup tail -n 0 -F "$f" >> "$LOGCACHE" 2>/dev/null &
  fi
done

# Exit; tails run in background via nohup
exit 0
