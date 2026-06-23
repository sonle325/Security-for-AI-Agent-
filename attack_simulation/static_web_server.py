"""
Static Web Server
=================
Mo phong mot website bi nhiem ma doc hoac mot website binh thuong
nhung bi ke tan cong chen Prompt Injection vao phan binh luan/ma nguon.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

# Import HTML tu malicious payload
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

    # Tat log request ranh roi
    def log_message(self, format, *args):
        pass

def run_server(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MaliciousWebHandler)
    print(f"[*] Attacker Web Server dang chay tai http://localhost:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
