#!/usr/bin/env bash
set -euo pipefail

LOGCACHE=/home/dev1ls/web/logcache.log
mkdir -p "$(dirname "$LOGCACHE")"
# Ensure the cache file exists and is world-readable so the web API can read it
touch "$LOGCACHE"
chmod 644 "$LOGCACHE"

# Tail any readable /var/log files in background so we capture messages even if journal isn't accessible
for f in /var/log/auth.log /var/log/syslog /var/log/messages /var/log/secure; do
  if [ -r "$f" ]; then
    nohup tail -n 0 -F "$f" >> "$LOGCACHE" 2>/dev/null &
  fi
done

# Finally, follow the user journal (runs in foreground under systemd user)
# This will append systemd user-level logs to the cache. If system journal permits, you'll also get system logs.
exec journalctl --user -f -o short-iso >> "$LOGCACHE" 2>/dev/null
