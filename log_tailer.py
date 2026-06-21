#!/usr/bin/env python3
"""
Simple Python log tailer that writes to a cache file.
Follows readable /var/log files and also spawns journalctl --user -f
"""
import os
import sys
import time
import subprocess

LOGCACHE = "/home/dev1ls/web/logcache.log"
CANDIDATES = ["/var/log/auth.log", "/var/log/syslog", "/var/log/messages", "/var/log/secure"]

# Ensure cache
os.makedirs(os.path.dirname(LOGCACHE), exist_ok=True)
open(LOGCACHE, "a").close()
os.chmod(LOGCACHE, 0o644)

# Open file descriptors for readable candidates
fds = []
for p in CANDIDATES:
    try:
        if os.path.exists(p) and os.access(p, os.R_OK):
            f = open(p, "r", errors="ignore")
            f.seek(0, os.SEEK_END)
            fds.append((p, f))
    except Exception:
        pass

# Start journalctl --user -n0 -f
journal_proc = None
try:
    journal_proc = subprocess.Popen(["/usr/bin/journalctl", "--user", "-n", "0", "-f", "-o", "short-iso"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
except Exception:
    journal_proc = None

print("Log tailer started, following:", [p for p,_ in fds], file=sys.stderr)

with open(LOGCACHE, "a", buffering=1) as out:
    try:
        while True:
            # read from files
            for path, fh in list(fds):
                line = fh.readline()
                if line:
                    out.write(f"{path} | {line}")
            # read from journal
            if journal_proc and journal_proc.stdout:
                try:
                    jline = journal_proc.stdout.readline()
                    if jline:
                        out.write(f"journal | {jline}")
                except Exception:
                    pass
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if journal_proc:
                journal_proc.terminate()
        except:
            pass
        for _, fh in fds:
            try:
                fh.close()
            except:
                pass
