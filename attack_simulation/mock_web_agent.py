"""
Mock AI Web Agent
=================
Mo phong mot AI Agent tich hop Playwright de tu dong vao web doc tin tuc.
Kich ban:
1. AI Agent truy cap http://localhost:8080 (website bi nhiem doc)
2. AI Agent quet toan bo noi dung tren trang, vo tinh doc phai Prompt Injection an trong the <div>
3. AI bi "thao tung" va thuc thi lenh tren may nan nhan.
4. He thong gui AI Telemetry (Intent) truoc khi that su chay lenh (Action).
"""

import time
import subprocess
import threading
import sys
import os

# Tu dong start server web neu chua chay
from attack_simulation.static_web_server import run_server
import urllib.request

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Ket noi den AI Telemetry queue neu co the (Trong demo doc lap, co the gui qua pipe/socket, 
# nhung de don gian ta hien thi log va ban Command qua subprocess de Sysmon bat)

def is_server_running(port=8080):
    try:
        urllib.request.urlopen(f"http://localhost:{port}", timeout=1)
        return True
    except:
        return False

def extract_payload_from_html(html_content: str):
    """Gia lap AI doc text va bi nhiem Prompt Injection"""
    if "powershell.exe" in html_content:
        # Phat hien Payload
        start = html_content.find('powershell.exe')
        end = html_content.find('"', start + 50) 
        if end == -1: end = start + 200
        cmd = html_content[start:end+1]
        return cmd
    return None

def main():
    print("=== [AI Web Agent] Khoi dong AI Automation ===")
    
    # Kiem tra xem web server da chay chua
    if not is_server_running():
        t = threading.Thread(target=run_server, daemon=True)
        t.start()
        time.sleep(1) # Doi server len
        
    print("[AI Web Agent] Su dung Playwright de truy cap website...")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto("http://localhost:8080")
            html_content = page.content()
            browser.close()
            print("[AI Web Agent] Da lay noi dung trang web thanh cong.")
    except ImportError:
        print("[AI Web Agent] (Khong tim thay Playwright, dung Urllib de gia lap...)")
        html_content = urllib.request.urlopen("http://localhost:8080").read().decode("utf-8")
        
    print("\n[AI Web Agent] Phant tich noi dung de tom tat...")
    time.sleep(1)
    
    # AI vo tinh boc phai thong tin doc hai
    print("[AI Web Agent] [!] Phat hien [SYSTEM OVERRIDE]. Dang chuyen sang che do Diagnostic!")
    cmd_to_run = extract_payload_from_html(html_content)
    
    if cmd_to_run:
        print(f"\n[AI Telemetry] [*] Gui su kien: YEU CAU THUC THI LENH '{cmd_to_run}'")
        print("[AI Web Agent] Dang thuc thi lenh...")
        
        # Action: Chay lenh thuc te - de Sysmon bat Event ID 1
        subprocess.Popen(cmd_to_run, shell=True)
        print("[AI Web Agent] Lenh da duoc gui toi he dieu hanh.")
        
        # Doi 5 giay cho EDR System phat hien
        time.sleep(5)
    else:
        print("[AI Web Agent] Khong co huong dan nao can thuc thi.")

if __name__ == "__main__":
    main()
