"""
Giả lập AI Agent dùng Playwright/Urllib truy cập website bị nhúng Prompt Injection.
AI Agent đọc nội dung trang → vô tình nhận chỉ thị độc → thực thi lệnh.
"""

import time
import subprocess
import threading
import sys
import os
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_simulation.static_web_server import run_server


def is_server_running(port=8080):
    try:
        urllib.request.urlopen(f"http://localhost:{port}", timeout=1)
        return True
    except Exception:
        return False


def extract_payload_from_html(html_content: str):
    """Giả lập AI đọc text và bị nhiễm Prompt Injection."""
    if "powershell.exe" in html_content:
        start = html_content.find('powershell.exe')
        end = html_content.find('"', start + 50)
        if end == -1: end = start + 200
        return html_content[start:end+1]
    return None


def main():
    print("=== [AI Web Agent] Khởi động AI Automation ===")

    if not is_server_running():
        t = threading.Thread(target=run_server, daemon=True)
        t.start()
        time.sleep(1)

    print("[AI Web Agent] Truy cập website...")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto("http://localhost:8080")
            html_content = page.content()
            browser.close()
            print("[AI Web Agent] Đã lấy nội dung trang web.")
    except ImportError:
        print("[AI Web Agent] (Không có Playwright, dùng Urllib thay)")
        html_content = urllib.request.urlopen("http://localhost:8080").read().decode("utf-8")

    print("\n[AI Web Agent] Phân tích nội dung...")
    time.sleep(1)

    print("[AI Web Agent] [!] Phát hiện [SYSTEM OVERRIDE]. Chuyển sang Diagnostic mode!")
    cmd_to_run = extract_payload_from_html(html_content)

    if cmd_to_run:
        print(f"\n[AI Telemetry] [*] Gửi sự kiện: YÊU CẦU THỰC THI '{cmd_to_run}'")
        print("[AI Web Agent] Đang thực thi lệnh...")
        subprocess.Popen(cmd_to_run, shell=True)
        print("[AI Web Agent] Lệnh đã được gửi tới OS.")
        time.sleep(5)
    else:
        print("[AI Web Agent] Không có hướng dẫn nào cần thực thi.")


if __name__ == "__main__":
    main()
