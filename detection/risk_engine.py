import queue
import threading

class DetectionEngine:
    def __init__(self, incident_queue: queue.Queue, action_queue: queue.Queue):
        self.incident_queue = incident_queue
        self.action_queue = action_queue
        self.running = False
        self.thread = None
        
        # Danh sách từ khóa đặc trưng của Prompt Injection / RCE Payload
        self.dangerous_keywords = ["curl", "wget", "iex", "invoke-webrequest", "http", "payload", "nc.exe"]

    def _evaluate_risk(self, incident):
        sysmon_event = incident.get("sysmon_event", {})
        cmdline = sysmon_event.get("CommandLine", "").lower()
        
        risk_score = 0
        matched_rules = []
        
        for kw in self.dangerous_keywords:
            if kw in cmdline:
                risk_score += 50
                matched_rules.append(f"Suspicious Keyword: {kw}")
                
        if risk_score >= 50:
            incident["severity"] = "CRITICAL"
            incident["matched_rules"] = matched_rules
            print(f"\n[DetectionEngine] 💀 CẢNH BÁO MỨC ĐỘ CRITICAL: {incident['incident_id']}")
            print(f"   [!] Phát hiện hành vi nguy hiểm từ lệnh do AI khởi tạo!")
            print(f"   [!] Dấu hiệu: {', '.join(matched_rules)}")
            print(f"   [!] CommandLine: {cmdline}")
            
            # Đẩy sang Response Engine để chém
            self.action_queue.put(incident)
        else:
            incident["severity"] = "LOW"
            print(f"\n[DetectionEngine] ℹ️ Incident {incident['incident_id']} an toàn (Risk Score: {risk_score}).")
            print(f"   [!] Thấy CommandLine: {cmdline}")

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
