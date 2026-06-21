#!/usr/bin/env python3
"""
Web Panel Server v2.0 - Sirve el panel HTML y proxyea la API
"""
import os
import json
import base64
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import mimetypes
import logging

WEB_PORT = int(os.environ.get("WEB_PORT", "8000"))
API_PORT = int(os.environ.get("API_PORT", "8090"))
WEB_ROOT = os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.join(WEB_ROOT, "config.json")
try:
    with open(CONFIG_PATH) as f:
        CONFIG = json.load(f)
except:
    CONFIG = {}

AUTH_USER = CONFIG.get("auth_user", "dev1ls")
AUTH_PASS = CONFIG.get("auth_password", "")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("web-panel")

mimetypes.init()
mimetypes.add_type('text/css', '.css')
mimetypes.add_type('application/javascript', '.js')
mimetypes.add_type('image/png', '.png')
mimetypes.add_type('image/svg+xml', '.svg')

def check_auth(headers):
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

class WebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Auth check
        if not check_auth(self.headers):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Web Panel"')
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>401 Unauthorized</h1>")
            return
        
        parsed = urlparse(self.path)
        path = parsed.path.lstrip('/')
        
        # API proxy — forward to metrics-api on localhost
        if path.startswith("api/"):
            try:
                # Use server IP to avoid loopback being blocked by firewall
                local_ip = "172.16.0.240"
                api_url = f"http://{local_ip}:{API_PORT}/{path}"
                if parsed.query:
                    api_url += f"?{parsed.query}"
                req = urllib.request.Request(api_url)
                # Forward auth header from browser to API
                auth = self.headers.get("Authorization")
                if auth:
                    req.add_header("Authorization", auth)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except urllib.error.HTTPError as e:
                data = e.read()
                self.send_response(e.code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return
        
        # Serve index.html
        if path == '' or path == 'index.html':
            html_path = os.path.join(WEB_ROOT, 'index.html')
            if os.path.exists(html_path):
                with open(html_path, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-cache, no-store")
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, "index.html not found")
            return
        
        # Static files
        file_path = os.path.join(WEB_ROOT, path)
        if os.path.isfile(file_path):
            ct, _ = mimetypes.guess_type(file_path)
            if ct is None:
                ct = 'application/octet-stream'
            with open(file_path, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404, "Not found")
    
    def log_message(self, format, *args):
        log.info(f"{self.client_address[0]} - {format % args}")

def main():
    log.info(f"Web panel v2.0 on port {WEB_PORT}, proxying API to 127.0.0.1:{API_PORT}")
    server = ThreadingHTTPServer(("0.0.0.0", WEB_PORT), WebHandler)
    server.serve_forever()

if __name__ == "__main__":
    main()
