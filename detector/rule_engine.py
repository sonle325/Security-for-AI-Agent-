import queue
import threading
import json
import os

class DetectionEngine:
    def __init__(self, incident_queue: queue.Queue, action_queue: queue.Queue):
        self.incident_queue = incident_queue
        self.action_queue = action_queue
        self.running = False
        self.thread = None
        
        # Tạo thư mục alert_queue theo đúng thiết kế
        os.makedirs("alert_queue", exist_ok=True)
        
        # Danh sách từ khóa đặc trưng của Prompt Injection / RCE Payload
        self.dangerous_keywords = ["curl", "wget", "iex", "invoke-webrequest", "http", "payload", "nc.exe"]
        
        # Danh sách trắng (Allowlist) để chống chém nhầm (False Positive)
        self.allowed_domains = ["github.com", "viettel.com.vn", "localhost", "127.0.0.1", "pypi.org", "npm"]

    def _evaluate_risk(self, incident):
        sysmon_event = incident.get("sysmon_event", {})
        cmdline = sysmon_event.get("CommandLine", "").lower()
        
        # 1. Kiểm tra Allowlist trước
        for domain in self.allowed_domains:
            if domain in cmdline:
                incident["severity"] = "LOW"
                print(f"\n[DetectionEngine] [*] Bỏ qua vì dính Allowlist ({domain}). (Lệnh nội bộ/Hợp lệ).")
                return

        # 2. Quét mã độc theo công thức Risk Scoring
        ai_event = incident.get("ai_event", {})
        image = sysmon_event.get("Image", "").lower()
        
        rule_severity = 0
        process_weight = 0
        network_activity = 0
        correlation_confidence = 0
        matched_rules = []
        
        # 2.1 Rule Severity (cap tối đa 20 điểm để tránh vượt ngưỡng oan do nhiều keyword)
        matched_keywords = [kw for kw in self.dangerous_keywords if kw in cmdline]
        if matched_keywords:
            rule_severity = 20
            for kw in matched_keywords:
                matched_rules.append(f"Suspicious Keyword: {kw}")
                
        # 2.2 Process Weight
        if "powershell" in image:
            process_weight = 20
            matched_rules.append("Process: PowerShell")
        elif "cmd.exe" in image:
            process_weight = 10
            matched_rules.append("Process: CMD")
            
        # 2.3 Network Activity
        if any(nw in cmdline for nw in ["http", "ftp", "curl", "wget", "invoke-webrequest"]):
            network_activity = 20
            matched_rules.append("Network: Outbound Comm")
            
        # 2.4 Correlation Confidence
        if ai_event.get("agent") != "Background Script/AI":
            correlation_confidence = 30
            matched_rules.append("Correlation: Confirmed AI Match")
        else:
            correlation_confidence = 0
            
        # 2.5 TOTAL RISK SCORE
        total_risk_score = rule_severity + process_weight + network_activity + correlation_confidence
                
        if total_risk_score >= 60:
            incident["severity"] = "CRITICAL"
            incident["matched_rules"] = matched_rules
            print(f"\n[DetectionEngine] [!] CẢNH BÁO MỨC ĐỘ CRITICAL: {incident['incident_id']}")
            print(f"   [!] Công thức: Rule({rule_severity}) + Process({process_weight}) + Net({network_activity}) + Corr({correlation_confidence}) = {total_risk_score} điểm")
            print(f"   [!] Dấu hiệu: {', '.join(matched_rules)}")
            print(f"   [!] CommandLine: {cmdline}")
            # Ghi log ra file JSON đúng chuẩn yêu cầu
            filepath = os.path.join("alert_queue", f"{incident['incident_id']}.json")
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(incident, f, indent=4)
                
            # Đẩy sang Response Engine để chém
            self.action_queue.put(incident)
        else:
            incident["severity"] = "LOW"
            print(f"\n[DetectionEngine] [*] Incident {incident['incident_id']} an toàn (Risk Score: {total_risk_score}/100).")

    def _process_queue(self):
        while self.running:
            try:
                incident = self.incident_queue.get(timeout=1.0)
                self._evaluate_risk(incident)
                self.incident_queue.task_done()
            except queue.Empty:
                pass

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._process_queue, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
