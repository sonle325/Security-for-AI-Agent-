import json
import os
import logging
from collections import deque
from http.server import HTTPServer, BaseHTTPRequestHandler

import config_loader

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("WebDashboard")

_HTML_FILE = os.path.join(os.path.dirname(__file__), "graph", "dashboard.html")
_FEED_FILE = os.path.join(os.path.dirname(__file__), "logs", "dashboard_feed.jsonl")

# Lấy cấu hình từ config.yaml
ports_cfg = config_loader.get("ports", default={})
neo4j_cfg = config_loader.get("neo4j", default={})

MAX_INCIDENTS = neo4j_cfg.get("max_incidents_cache", 200)

def get_incidents():
    incidents = deque(maxlen=MAX_INCIDENTS)
    if os.path.exists(_FEED_FILE):
        try:
            with open(_FEED_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            incidents.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            logger.error("Lỗi đọc file log: %s", e)
    return list(incidents)

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._serve_html()
        elif self.path == "/api/incidents":
            self._serve_json()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_html(self):
        try:
            with open(_HTML_FILE, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"<h1>Loi: Khong tim thay graph/dashboard.html</h1>")

    def _serve_json(self):
        data = json.dumps(get_incidents(), ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

def start_server(port=8888):
    try:
        server = HTTPServer(("0.0.0.0", port), DashboardHandler)
        logger.info("="*60)
        logger.info(" WEB DASHBOARD STANDALONE MODE")
        logger.info("="*60)
        logger.info("Dang theo doi file: %s", _FEED_FILE)
        logger.info("Truy cap Dashboard tai: http://localhost:%d", port)
        logger.info("Bam [Ctrl+C] de thoat.")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Dang tat Web Dashboard...")
        server.server_close()
    except OSError as e:
        logger.error("Khong khoi dong duoc Server (Port %d da bi chiem?): %s", port, e)

if __name__ == "__main__":
    port = ports_cfg.get("dashboard", 8888)
    start_server(port)
