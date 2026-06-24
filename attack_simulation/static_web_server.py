# Web server giả lập website bị chèn Prompt Injection trong HTML.

from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from attack_simulation.malicious_payload import HTML_TEMPLATE


class MaliciousWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(HTML_TEMPLATE.encode("utf-8"))

    def log_message(self, format, *args):
        pass


def run_server(port=8080):
    httpd = HTTPServer(('', port), MaliciousWebHandler)
    print(f"[*] Attacker Web Server đang chạy tại http://localhost:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    run_server()
