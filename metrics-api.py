#!/usr/bin/env python3
"""
System Metrics API v2.0 - Sirve datos del sistema para el panel web
"""
import os
import re
import json
import subprocess
import socket
import time
import threading
import hashlib
import base64
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Load config ──────────────────────────────────────────────────────
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
try:
    with open(CONFIG_PATH) as f:
        CONFIG = json.load(f)
except:
    CONFIG = {}

PORT = int(os.environ.get("METRICS_PORT", CONFIG.get("port", 8090)))
AUTH_USER = CONFIG.get("auth_user", "dev1ls")
AUTH_PASS = CONFIG.get("auth_password", "")
RATE_LIMIT_REQ = CONFIG.get("rate_limit_requests", 60)
RATE_LIMIT_WIN = CONFIG.get("rate_limit_window", 60)
GEOIP_TTL = CONFIG.get("geoip_ttl", 3600)
GEOIP_MAX = CONFIG.get("geoip_max_lookups", 30)
CPU_DELTA_INT = CONFIG.get("cpu_delta_interval", 5)
CRITICAL_SERVICES = CONFIG.get("critical_services", ["docker", "tailscale", "fail2ban", "sshd", "nftables"])
LOG_LINES = CONFIG.get("log_lines", 200)

# ── Logging ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger("metrics-api")

# ── Rate limiter ─────────────────────────────────────────────────────
_rate_lock = threading.Lock()
_rate_data = {}  # ip -> [timestamps]

def rate_limit_check(ip):
    """Returns True if request is allowed, False if rate limited."""
    now = time.time()
    with _rate_lock:
        if ip not in _rate_data:
            _rate_data[ip] = []
        # Remove old entries
        _rate_data[ip] = [t for t in _rate_data[ip] if now - t < RATE_LIMIT_WIN]
        if len(_rate_data[ip]) >= RATE_LIMIT_REQ:
            return False
        _rate_data[ip].append(now)
        return True

# ── Auth ─────────────────────────────────────────────────────────────
def check_auth(headers):
    """Check basic auth. Returns True if valid or no auth configured."""
    if not AUTH_PASS:
        return True
    auth_header = headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:]).decode()
        user, passwd = decoded.split(":", 1)
        return user == AUTH_USER and passwd == AUTH_PASS
    except:
        return False

# ── GeoIP cache con TTL ──────────────────────────────────────────────
_geoip_cache = {}
_geoip_lock = threading.Lock()
_last_geoip_cleanup = 0

def geoip_lookup(ip):
    """Single geoIP lookup."""
    result = {"country": "", "city": "", "isp": "", "lat": 0, "lon": 0, "org": ""}
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon"
        resp = urllib.request.urlopen(url, timeout=5)
        data = json.loads(resp.read())
        if data.get("status") == "success":
            result = {
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "org": data.get("org", ""),
            }
    except:
        pass
    return result

def geoip_get(ip):
    """Get geoIP con cache TTL."""
    global _last_geoip_cleanup
    now = time.time()
    
    with _geoip_lock:
        if now - _last_geoip_cleanup > 600:
            expired = [k for k, v in _geoip_cache.items() if now - v.get("_ts", 0) > GEOIP_TTL]
            for k in expired:
                del _geoip_cache[k]
            _last_geoip_cleanup = now
        
        if ip in _geoip_cache:
            entry = _geoip_cache[ip]
            if now - entry.get("_ts", 0) <= GEOIP_TTL:
                return {k: v for k, v in entry.items() if k != "_ts"}
    
    result = geoip_lookup(ip)
    
    with _geoip_lock:
        _geoip_cache[ip] = {**result, "_ts": now}
    
    return result

def geoip_get_cache_snapshot():
    return {k: {kk: vv for kk, vv in v.items() if kk != "_ts"} 
            for k, v in _geoip_cache.items()}

# ── CPU delta en background ─────────────────────────────────────────
_cpu_lock = threading.Lock()
_cpu_usage = 0.0

def _cpu_monitor_loop():
    """Background thread que actualiza CPU usage cada CPU_DELTA_INT segundos."""
    global _cpu_usage
    def read_stat():
        with open("/proc/stat") as f:
            fields = list(map(int, f.readline().split()[1:]))
        return fields[3], sum(fields)  # idle, total
    
    # Primera lectura
    idle1, total1 = read_stat()
    
    while True:
        time.sleep(CPU_DELTA_INT)
        try:
            idle2, total2 = read_stat()
            total_delta = total2 - total1
            idle_delta = idle2 - idle1
            usage = ((total_delta - idle_delta) / total_delta * 100) if total_delta > 0 else 0
            with _cpu_lock:
                _cpu_usage = round(usage, 1)
            idle1, total1 = idle2, total2
        except:
            pass

_cpu_thread = threading.Thread(target=_cpu_monitor_loop, daemon=True)
_cpu_thread.start()

# ── Bandwidth tracking ───────────────────────────────────────────────
_bw_lock = threading.Lock()
_bw_prev = {}  # iface -> (rx_bytes, tx_bytes, timestamp)

def _get_bandwidth(iface, rx, tx):
    """Calculate RX/TX rate in bytes/sec."""
    now = time.time()
    with _bw_lock:
        if iface in _bw_prev:
            prev_rx, prev_tx, prev_ts = _bw_prev[iface]
            dt = now - prev_ts
            if dt > 0:
                rx_rate = max(0, (rx - prev_rx) / dt)
                tx_rate = max(0, (tx - prev_tx) / dt)
            else:
                rx_rate = tx_rate = 0
        else:
            rx_rate = tx_rate = 0
        _bw_prev[iface] = (rx, tx, now)
    return round(rx_rate), round(tx_rate)

# ── Helpers ──────────────────────────────────────────────────────────

def run_cmd(cmd, needs_sudo=False):
    if needs_sudo:
        cmd = f"sudo {cmd}"
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5).decode().strip()
    except:
        return ""

def ip_is_private(ip):
    try:
        parts = ip.split('.')
        if len(parts) != 4: return False
        a, b = int(parts[0]), int(parts[1])
        if a == 10: return True
        if a == 127: return True
        if a == 192 and b == 168: return True
        if a == 172 and 16 <= b <= 31: return True
        if a == 100 and 64 <= b <= 127: return True
        return False
    except:
        return False

# ── Collectors ───────────────────────────────────────────────────────

def get_uptime():
    try:
        with open("/proc/uptime") as f:
            secs = float(f.read().split()[0])
        d = int(secs // 86400)
        h = int((secs % 86400) // 3600)
        m = int((secs % 3600) // 60)
        return {"days": d, "hours": h, "minutes": m, "seconds": int(secs)}
    except:
        return {"days": 0, "hours": 0, "minutes": 0, "seconds": 0}

def get_cpu():
    try:
        with open("/proc/cpuinfo") as f:
            info = f.read()
        model = [l for l in info.split("\n") if "model name" in l]
        model = model[0].split(":")[1].strip() if model else "Unknown"
        cores = int(run_cmd("nproc") or "1")
        
        with _cpu_lock:
            usage = _cpu_usage
        
        temp = run_cmd("cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null")
        temp_c = round(int(temp) / 1000, 1) if temp.isdigit() else None
        
        load = os.getloadavg()
        
        return {
            "model": model, "cores": cores, "usage_percent": usage,
            "temperature_c": temp_c,
            "load_1m": round(load[0], 2), "load_5m": round(load[1], 2), "load_15m": round(load[2], 2),
        }
    except:
        return {}

def get_memory():
    try:
        with open("/proc/meminfo") as f:
            lines = f.readlines()
        mem = {}
        for l in lines:
            parts = l.split(":")
            if len(parts) == 2:
                mem[parts[0].strip()] = int(parts[1].strip().split()[0])
        total = mem.get("MemTotal", 0)
        avail = mem.get("MemAvailable", 0)
        used = total - avail
        st = mem.get("SwapTotal", 0)
        sf = mem.get("SwapFree", 0)
        return {
            "total_mb": round(total / 1024), "used_mb": round(used / 1024),
            "available_mb": round(avail / 1024),
            "percent": round(used / total * 100, 1) if total > 0 else 0,
            "swap_total_mb": round(st / 1024), "swap_used_mb": round((st - sf) / 1024),
        }
    except:
        return {}

def get_disk():
    try:
        output = run_cmd("df -h / /home 2>/dev/null")
        disks = []
        for line in output.split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 6:
                disks.append({
                    "filesystem": parts[0], "size": parts[1], "used": parts[2],
                    "available": parts[3], "percent": int(parts[4].replace("%", "")),
                    "mount": parts[5],
                })
        return disks
    except:
        return []

def get_disk_temp():
    """Try to get disk temperature via smartctl or hddtemp."""
    temps = {}
    try:
        # Try smartctl for all disks
        output = run_cmd("lsblk -d -o NAME -n 2>/dev/null", needs_sudo=True)
        for disk in output.split():
            if disk.startswith(("sd", "nvme", "vd")):
                smart = run_cmd(f"smartctl -A /dev/{disk} 2>/dev/null | grep -i 'temperature' | head -1", needs_sudo=True)
                if smart:
                    # Extract temperature value
                    match = re.search(r'(\d+)\s+\(Min/Max', smart)
                    if not match:
                        match = re.search(r'(\d+)', smart)
                    if match:
                        temps[disk] = int(match.group(1))
    except:
        pass
    return temps

def get_network():
    try:
        interfaces = []
        output = run_cmd("ip -4 -o addr show 2>/dev/null")
        for line in output.split("\n"):
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[1]
                addr = parts[3]
                if iface != "lo":
                    rx = run_cmd(f"cat /sys/class/net/{iface}/statistics/rx_bytes 2>/dev/null")
                    tx = run_cmd(f"cat /sys/class/net/{iface}/statistics/tx_bytes 2>/dev/null")
                    rx_val = int(rx) if rx.isdigit() else 0
                    tx_val = int(tx) if tx.isdigit() else 0
                    rx_rate, tx_rate = _get_bandwidth(iface, rx_val, tx_val)
                    interfaces.append({
                        "name": iface, "address": addr,
                        "rx_bytes": rx_val, "tx_bytes": tx_val,
                        "rx_rate": rx_rate, "tx_rate": tx_rate,
                        "status": run_cmd(f"cat /sys/class/net/{iface}/operstate 2>/dev/null").upper() or "UNKNOWN",
                    })
        return {"interfaces": interfaces}
    except:
        return {"interfaces": []}

def get_services():
    """Status of critical systemd services using pgrep."""
    services = []
    for svc in CRITICAL_SERVICES:
        # Map service name to process name
        proc_map = {
            "docker": "dockerd",
            "tailscale": "tailscaled",
            "fail2ban": "fail2ban-server",
            "sshd": "sshd",
        }
        proc = proc_map.get(svc, svc)
        
        # nftables is not a daemon — check if rules are loaded instead
        if svc == "nftables":
            ps_check = run_cmd("nft list ruleset 2>/dev/null | grep -q 'chain' && echo active || echo inactive", needs_sudo=True)
        else:
            ps_check = run_cmd(f"pgrep -x {proc} > /dev/null 2>&1 && echo active || echo inactive")
        status = ps_check.strip() if ps_check else "unknown"
        
        # Check if enabled via systemctl (best effort, may fail without sudo)
        enabled = run_cmd(f"systemctl is-enabled {svc} 2>/dev/null")
        if not enabled:
            enabled = run_cmd(f"systemctl --user is-enabled {svc} 2>/dev/null")
        
        services.append({
            "name": svc,
            "active": status == "active",
            "enabled": enabled.strip() == "enabled" if enabled else False,
            "status": status,
        })
    return services

def get_firewall():
    try:
        rules_text = run_cmd("nft list ruleset 2>/dev/null", needs_sudo=True)
        if not rules_text:
            return {"enabled": False, "rules_count": 0, "chains": [], "total_drops": 0, "total_drop_bytes": 0, "total_rejects": 0, "total_reject_bytes": 0}
        
        chains = []
        current_chain = None
        total_dp = 0
        total_db = 0
        total_rp = 0
        total_rb = 0
        rule_count = 0
        
        for line in rules_text.split("\n"):
            s = line.strip()
            if not s or s.startswith("#"): continue
            if s.startswith("chain "):
                current_chain = s.split()[1].strip("{")
                chains.append({"name": current_chain, "policy": ""})
                rule_count += 1
                continue
            if "policy" in s and current_chain:
                p = s.split("policy")
                if len(p) > 1 and chains:
                    chains[-1]["policy"] = p[1].strip().rstrip(";").strip()
                continue
            if current_chain and any(s.startswith(x) for x in ["iif","oif","tcp","udp","ip ","ct ","meta","log ","counter"]):
                rule_count += 1
                cm = re.search(r'counter packets (\d+) bytes (\d+)', s)
                pk = int(cm.group(1)) if cm else 0
                bv = int(cm.group(2)) if cm else 0
                if "drop" in s.lower(): total_dp += pk; total_db += bv
                if "reject" in s.lower(): total_rp += pk; total_rb += bv
                if s.endswith(("drop","drop;")) and pk == 0: total_dp += 1
                if s.endswith(("reject","reject;")) and pk == 0: total_rp += 1
        
        return {
            "enabled": True, "rules_count": rule_count, "chains": chains,
            "total_drops": total_dp, "total_drop_bytes": total_db,
            "total_rejects": total_rp, "total_reject_bytes": total_rb,
        }
    except:
        return {"enabled": False, "rules_count": 0, "chains": [], "total_drops": 0, "total_drop_bytes": 0, "total_rejects": 0, "total_reject_bytes": 0}

def get_fail2ban():
    try:
        output = run_cmd("fail2ban-client status 2>/dev/null", needs_sudo=True)
        if not output:
            svc = run_cmd("systemctl is-active fail2ban 2>/dev/null", needs_sudo=True)
            return {"enabled": svc.strip() == "active", "jails": [], "banned_total": 0, "failed_total": 0, "banned_ips": []}
        
        jails = []
        banned_total = 0
        failed_total = 0
        all_banned = []
        jail_names = []
        
        for line in output.split("\n"):
            if "Jail list" in line:
                p = line.split(":", 1)
                if len(p) > 1:
                    jail_names = [j.strip().strip("'") for j in p[1].strip().split(",") if j.strip()]
        
        for jn in jail_names:
            js = run_cmd(f"fail2ban-client status {jn} 2>/dev/null", needs_sudo=True)
            jd = {"name": jn, "banned": 0, "banned_ips": [], "failed": 0, "failed_total": 0}
            for line in js.split("\n"):
                line = line.strip()
                if line.startswith("Currently failed:"):
                    try: jd["failed"] = int(line.split(":")[1].strip())
                    except: pass
                elif line.startswith("Total failed:"):
                    try: jd["failed_total"] = int(line.split(":")[1].strip())
                    except: pass
                elif line.startswith("Currently banned:"):
                    try: jd["banned"] = int(line.split(":")[1].strip())
                    except: pass
                elif line.startswith("Total banned:"):
                    try: jd["total_banned"] = int(line.split(":")[1].strip())
                    except: pass
                elif "Banned IP list" in line:
                    p = line.split(":", 1)
                    if len(p) > 1:
                        ips_str = p[1].strip()
                        if ips_str and ips_str != "-":
                            ips = [i.strip() for i in ips_str.split() if i.strip()]
                            jd["banned_ips"] = ips
                            all_banned.extend(ips)
            banned_total += jd["banned"]
            failed_total += jd.get("failed", 0)
            jails.append(jd)
        
        return {"enabled": True, "jails": jails, "banned_total": banned_total, "failed_total": failed_total, "banned_ips": list(set(all_banned))}
    except:
        return {"enabled": False, "jails": [], "banned_total": 0, "failed_total": 0, "banned_ips": []}

def get_connections():
    try:
        output = run_cmd("ss -tunap 2>/dev/null")
        tcp_c = udp_c = 0
        listening = []
        established = []
        for line in output.split("\n")[1:]:
            parts = line.split()
            if len(parts) < 5: continue
            proto, state, local = parts[0], parts[1], parts[4]
            peer = parts[5] if len(parts) > 5 else "-"
            if proto == "tcp": tcp_c += 1
            elif proto == "udp": udp_c += 1
            if state == "LISTEN":
                port = local.split(":")[-1] if ":" in local else local
                listening.append({"port": port, "address": local})
            elif state == "ESTAB":
                established.append({"local": local, "peer": peer})
        return {"tcp": tcp_c, "udp": udp_c, "listening": listening[:15], "established": established[:15]}
    except:
        return {"tcp": 0, "udp": 0, "listening": [], "established": []}

def get_processes():
    try:
        output = run_cmd("ps aux --sort=-%cpu 2>/dev/null | head -15")
        procs = []
        for line in output.split("\n")[1:]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({"user": parts[0], "pid": parts[1], "cpu": float(parts[2]), "mem": float(parts[3]), "command": parts[10][:80]})
        return procs
    except:
        return []

def get_logs(lines=None):
    """Collect recent logs with configurable line count."""
    if lines is None:
        lines = LOG_LINES
    logs = {"journal": "", "files": {}, "alerts": []}
    
    try:
        lc = "/home/dev1ls/web/logcache.log"
        if os.path.exists(lc) and os.access(lc, os.R_OK):
            logs["files"][lc] = run_cmd(f"tail -n {lines} {lc}")
    except: pass
    
    # System journal (running as root, so no sudo needed)
    try:
        logs["journal"] = run_cmd(f"journalctl -n {lines} --no-pager")
    except: pass
    # Kernel journal for firewall drops and other kernel alerts
    try:
        logs["journal_kern"] = run_cmd(f"journalctl -k -n {lines} --no-pager")
    except: pass
    # User journal for user-space alerts
    try:
        logs["journal_user"] = run_cmd(f"journalctl --user -n {lines} --no-pager")
    except: pass
    
    keywords = ["fail","failed","error","denied","invalid","panic","segfault","reject","drop","authentication","unauthorized","critical"]
    noise_patterns = [
        ["sudo", "fail2ban-client"],
        ["sudo", "command="],
        ["pam_systemd", "sudo"],
        ["sudo", "pam_unix", "session"],
        ["sudo", "nft", "list"],
        ["sudo", "systemctl", "is-active"],
        ["sudo", "systemctl", "is-enabled"],
    ]
    matches = []
    recent = []
    def scan(src, name):
        lns = src.split('\n') if src else []
        recent.extend([(name, l) for l in lns[-lines:] if l.strip()])
        for l in lns[-lines:]:
            if not l.strip(): continue
            # Skip expected noise from the metrics API
            skip = False
            for pattern in noise_patterns:
                if all(p in l.lower() for p in pattern):
                    skip = True
                    break
            if skip: continue
            if any(k in l.lower() for k in keywords):
                matches.append({"source": name, "line": l})
    scan(logs.get("journal", ""), "journal")
    scan(logs.get("journal_kern", ""), "kernel")
    scan(logs.get("journal_user", ""), "user")
    for path, txt in logs["files"].items():
        scan(txt, path)
    logs["alerts"] = matches[-500:]
    logs["recent_lines"] = [f"{s} | {l}" for s, l in recent[-400:]]
    return logs

# ── History ring buffer ──────────────────────────────────────────────
HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "history.json")
HISTORY_MAX = 300
HISTORY_INTERVAL = 10
_history_lock = threading.Lock()
_history = []

def _load_history():
    global _history
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE) as f:
                _history = json.load(f)[-HISTORY_MAX:]
    except:
        _history = []

def _save_history():
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(_history[-HISTORY_MAX:], f)
    except:
        pass

def _record_snapshot():
    global _history
    try:
        cpu_p = _cpu_usage

        with open("/proc/meminfo") as f:
            mem_lines = f.readlines()
        mem = {}
        for l in mem_lines:
            parts = l.split(":")
            if len(parts) == 2:
                mem[parts[0].strip()] = int(parts[1].strip().split()[0])
        mem_total = mem.get("MemTotal", 0)
        mem_avail = mem.get("MemAvailable", 0)
        mem_pct = round((mem_total - mem_avail) / mem_total * 100, 1) if mem_total else 0

        disk_out = run_cmd("df / 2>/dev/null | tail -1")
        disk_pct = 0
        if disk_out:
            parts = disk_out.split()
            if len(parts) >= 5:
                disk_pct = int(parts[4].replace("%", ""))

        net_rx = net_tx = 0
        for iface_dir in os.listdir("/sys/class/net"):
            if iface_dir == "lo": continue
            rx_path = f"/sys/class/net/{iface_dir}/statistics/rx_bytes"
            tx_path = f"/sys/class/net/{iface_dir}/statistics/tx_bytes"
            if os.path.exists(rx_path):
                with open(rx_path) as f: net_rx += int(f.read().strip())
            if os.path.exists(tx_path):
                with open(tx_path) as f: net_tx += int(f.read().strip())

        ts = time.time()
        with _history_lock:
            _history.append({
                "t": ts, "cpu": cpu_p, "mem": mem_pct, "disk": disk_pct,
                "net_rx": net_rx, "net_tx": net_tx
            })
            if len(_history) > HISTORY_MAX:
                _history = _history[-HISTORY_MAX:]
    except Exception as e:
        log.error(f"History snapshot error: {e}")
        import traceback
        log.error(traceback.format_exc())

def _history_loop():
    _load_history()
    while True:
        time.sleep(HISTORY_INTERVAL)
        _record_snapshot()
        _save_history()

_history_thread = threading.Thread(target=_history_loop, daemon=True)
_history_thread.start()

def get_history():
    with _history_lock:
        return list(_history)

# ── Docker info ──────────────────────────────────────────────────────
DOCKER_HOST = "unix:///run/user/1000/docker.sock"

def get_docker_info():
    try:
        prefix = f"DOCKER_HOST={DOCKER_HOST}"
        containers = run_cmd(f"{prefix} docker ps -a --format '{{{{.ID}}}}|{{{{.Names}}}}|{{{{.Image}}}}|{{{{.Status}}}}|{{{{.Ports}}}}' 2>/dev/null")
        clist = []
        for line in containers.strip().split("\n"):
            if not line: continue
            parts = line.split("|")
            if len(parts) >= 5:
                running = "Up" in parts[3] or "running" in parts[3].lower()
                clist.append({
                    "id": parts[0][:12], "name": parts[1], "image": parts[2],
                    "status": parts[3], "ports": parts[4], "running": running
                })

        images = run_cmd(f"{prefix} docker images --format '{{{{.Repository}}}}:{{{{.Tag}}}}|{{{{.Size}}}}' 2>/dev/null")
        ilist = [{"name": l.split("|")[0], "size": l.split("|")[1] if "|" in l else ""}
                 for l in images.strip().split("\n") if l]

        return {"containers": clist, "images": ilist,
                "running": sum(1 for c in clist if c["running"]),
                "total": len(clist), "images_count": len(ilist)}
    except:
        return {"containers": [], "images": [], "running": 0, "total": 0, "images_count": 0}

# ── Available updates ────────────────────────────────────────────────
def get_updates():
    try:
        out = run_cmd("pacman -Qu 2>/dev/null")
        pkgs = [l for l in out.strip().split("\n") if l] if out else []
        return {"count": len(pkgs), "packages": pkgs[:50]}
    except:
        return {"count": 0, "packages": []}

# ── Listening ports enhanced ─────────────────────────────────────────
def get_listening_ports():
    try:
        out = run_cmd("ss -tlnp4 2>/dev/null")
        ports = []
        for line in out.strip().split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3]
                proc = parts[5] if len(parts) > 5 else ""
                port = addr.rsplit(":", 1)[-1]
                ports.append({"address": addr, "port": port, "process": proc})
        return ports
    except:
        return []

# ── Build metrics ────────────────────────────────────────────────────

def get_system_metrics():
    metrics = {
        "timestamp": datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "uptime": get_uptime(),
        "cpu": get_cpu(),
        "memory": get_memory(),
        "disk": get_disk(),
        "disk_temp": get_disk_temp(),
        "network": get_network(),
        "firewall": get_firewall(),
        "fail2ban": get_fail2ban(),
        "services": get_services(),
        "connections": get_connections(),
        "processes": get_processes(),
        "docker": get_docker_info(),
        "updates": get_updates(),
        "ports": get_listening_ports(),
    }
    
    # GeoIP lookups en paralelo para conexiones públicas
    mapped = []
    private_sample = []
    private_count = 0
    public_ips = []
    
    for conn in metrics["connections"]["established"]:
        try:
            peer = conn.get("peer", "")
            local = conn.get("local", "")
            ip = peer.rsplit(":", 1)[0] if ":" in peer else peer
            if not ip: continue
            if ip_is_private(ip):
                private_count += 1
                if len(private_sample) < 10:
                    private_sample.append({"local": local, "peer": peer, "ip": ip})
                continue
            public_ips.append((ip, local, peer))
        except: continue
    
    # Limitar lookups
    public_ips = public_ips[:GEOIP_MAX]
    
    # Lookups en paralelo
    if public_ips:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(geoip_get, ip): (ip, local, peer) for ip, local, peer in public_ips}
            for future in as_completed(futures):
                ip, local, peer = futures[future]
                try:
                    g = future.result()
                    lat = float(g.get("lat") or 0)
                    lon = float(g.get("lon") or 0)
                    is_ssh = False
                    try:
                        pp = int(peer.rsplit(':', 1)[1]) if ':' in peer else None
                        lp = int(local.rsplit(':', 1)[1]) if ':' in local else None
                        if pp == 22 or lp == 22: is_ssh = True
                    except: pass
                    mapped.append({
                        "local": local, "peer": peer, "ip": ip,
                        "lat": lat, "lon": lon,
                        "city": g.get("city", ""), "country": g.get("country", ""),
                        "isp": g.get("isp", ""), "is_private": False, "is_ssh": is_ssh,
                    })
                except: pass
    
    metrics["connections"]["mapped"] = mapped
    metrics["connections"]["private_count"] = private_count
    metrics["connections"]["private_sample"] = private_sample
    metrics["geoip"] = geoip_get_cache_snapshot()
    
    return metrics

# ── HTTP Handler ─────────────────────────────────────────────────────

class APIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        
        # Rate limiting
        if not rate_limit_check(client_ip):
            self.send_json(429, {"error": "Rate limit exceeded"})
            return
        
        # Auth
        if not check_auth(self.headers):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Metrics API"')
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Authentication required"}).encode())
            return
        
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        
        if parsed.path == "/api/metrics":
            self.send_json(200, get_system_metrics())
        
        elif parsed.path == "/api/logs":
            lines = int(qs.get("lines", [LOG_LINES])[0])
            self.send_json(200, get_logs(lines=lines))
        
        elif parsed.path == "/api/health":
            health = {
                "status": "ok",
                "timestamp": datetime.now().isoformat(),
                "version": "2.0",
                "checks": {
                    "cpu": _cpu_usage is not None,
                    "sudo_nft": bool(run_cmd("sudo nft list ruleset 2>/dev/null | head -1")),
                    "sudo_fail2ban": bool(run_cmd("sudo fail2ban-client status 2>/dev/null | head -1")),
                    "logcache": os.path.exists("/home/dev1ls/web/logcache.log"),
                }
            }
            self.send_json(200, health)
        
        elif parsed.path == "/api/history":
            self.send_json(200, get_history())
        
        elif parsed.path == "/api/docker":
            self.send_json(200, get_docker_info())
        
        elif parsed.path == "/api/updates":
            self.send_json(200, get_updates())
        
        elif parsed.path == "/api/ports":
            self.send_json(200, get_listening_ports())
        
        else:
            self.send_json(404, {"error": "Not found"})
    
    def send_json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    
    def log_message(self, format, *args):
        log.info(f"{self.client_address[0]} - {format % args}")

def main():
    log.info(f"Metrics API v2.0 starting on port {PORT}")
    log.info(f"Auth: {'enabled' if AUTH_PASS else 'disabled'}")
    log.info(f"Rate limit: {RATE_LIMIT_REQ} req/{RATE_LIMIT_WIN}s")
    log.info(f"CPU delta interval: {CPU_DELTA_INT}s")
    log.info(f"Critical services: {', '.join(CRITICAL_SERVICES)}")
    server = HTTPServer(("0.0.0.0", PORT), APIHandler)
    server.serve_forever()

if __name__ == "__main__":
    main()
