import queue
import threading
import datetime
import time
from datetime import timezone, timedelta

class CorrelationEngine:
    def __init__(self, sysmon_queue: queue.Queue, ai_event_queue: queue.Queue, incident_queue: queue.Queue):
        self.sysmon_queue = sysmon_queue
        self.ai_event_queue = ai_event_queue
        self.incident_queue = incident_queue
        self.running = False
        self.thread = None
        
        # Sliding windows
        self.sysmon_window = []
        self.ai_window = []
        self.incident_counter = 1

    def _parse_utc_time(self, time_str: str) -> datetime.datetime:
        """
        Chuẩn hoá timestamp từ hai nguồn về UTC-aware datetime (ISO 8601 + milliseconds).

        Nguồn 1 — Sysmon (Kernel): '2026-06-16T11:41:48.1234567Z' (7 chữ số thập phân)
        Nguồn 2 — AI Agent (Python): '2026-06-16T18:10:00.123456+00:00' hoặc '...Z'

        Cả hai đều được normalize về datetime có tzinfo=UTC để đảm bảo
        phép trừ abs(sys_time - ai_time) luôn chính xác, bất kể nguồn nào
        đến trước do cơ chế cache của IPC library.
        """
        if not time_str or not isinstance(time_str, str):
            return datetime.datetime.min.replace(tzinfo=timezone.utc)
        try:
            # Chuẩn hoá: thay 'Z' bằng '+00:00' để fromisoformat() hiểu được
            normalized = time_str.strip().replace("Z", "+00:00")

            # Sysmon trả về 7 chữ số thập phân — Python chỉ hỗ trợ tối đa 6
            # Cắt về 6 chữ số trước khi parse
            if "." in normalized:
                dot_pos = normalized.index(".")
                plus_pos = normalized.find("+", dot_pos)
                if plus_pos == -1:
                    plus_pos = len(normalized)
                frac = normalized[dot_pos+1:plus_pos]
                frac = frac[:6].ljust(6, "0")   # pad nếu thiếu
                normalized = normalized[:dot_pos+1] + frac + normalized[plus_pos:]

            dt = datetime.datetime.fromisoformat(normalized)

            # Đảm bảo luôn có tzinfo=UTC (xử lý trường hợp naive datetime)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)

            return dt
        except Exception:
            return datetime.datetime.min.replace(tzinfo=timezone.utc)

    def _clean_window(self, window: list, current_time: datetime.datetime):
        """Keep only events from the last 30 seconds, max 100 events."""
        cutoff_time = current_time - datetime.timedelta(seconds=30)
        cleaned = [e for e in window if self._parse_utc_time(e.get("TimestampUTC", e.get("timestamp", ""))) >= cutoff_time]
        return cleaned[-100:]

    def _process_queues(self):
        while self.running:
            # Pull AI Events
            while not self.ai_event_queue.empty():
                try:
                    event = self.ai_event_queue.get_nowait()
                    self.ai_window.append(event)

                    # Kiem tra anomaly tu PromptMonitor / ToolMonitor / ResponseMonitor
                    self._check_ai_event_anomalies(event)

                    self.ai_event_queue.task_done()
                except queue.Empty:
                    break
                    
            # Pull Sysmon Events
            while not self.sysmon_queue.empty():
                try:
                    event = self.sysmon_queue.get_nowait()
                    # Thu thap Event ID 1 (Process), 3 (Network), 11 (File), 13 (Registry), 22 (DNS)
                    if event.get("EventID") in [1, 3, 11, 13, 22]:
                        self.sysmon_window.append(event)
                    self.sysmon_queue.task_done()
                except queue.Empty:
                    break

            now = datetime.datetime.now(timezone.utc)
            self.ai_window = self._clean_window(self.ai_window, now)
            self.sysmon_window = self._clean_window(self.sysmon_window, now)
            
            # Correlate
            self._correlate()
            
            time.sleep(0.5)

    def _check_ai_event_anomalies(self, event: dict):
        """
        Kiem tra cac event AI da duoc enrich boi PromptMonitor / ToolMonitor / ResponseMonitor.
        Neu phat hien muc do CRITICAL/HIGH, tu dong tao Incident ma khong can doi Sysmon correlation.
        """
        event_type = event.get("event_type", "")

        # 1. Prompt Injection detected
        prompt_analysis = event.get("prompt_analysis", {})
        if prompt_analysis.get("is_injection") and prompt_analysis.get("risk_level") in ("CRITICAL", "HIGH"):
            incident_id = f"INC-{self.incident_counter:04d}"
            self.incident_counter += 1

            print(f"\n[CorrelationEngine] [!] PROMPT INJECTION DETECTED — Tao Incident: {incident_id}")
            print(f"   [!] Risk Level: {prompt_analysis['risk_level']} (Score: {prompt_analysis['injection_score']}/100)")
            print(f"   [!] Patterns: {', '.join(prompt_analysis.get('matched_patterns', []))}")

            incident = {
                "incident_id": incident_id,
                "incident_type": "PROMPT_INJECTION",
                "ai_event": event,
                "sysmon_event": {},  # Chua co Sysmon event tuong ung
                "prompt_analysis": prompt_analysis,
                "severity": "CRITICAL" if prompt_analysis["injection_score"] >= 60 else "HIGH",
            }
            self.incident_queue.put(incident)
            event["_correlated"] = True

        # 2. Tool anomaly detected (sensitive file, excessive usage...)
        tool_analysis = event.get("tool_analysis", {})
        if tool_analysis.get("has_anomaly") and tool_analysis.get("risk_level") in ("CRITICAL", "HIGH"):
            incident_id = f"INC-{self.incident_counter:04d}"
            self.incident_counter += 1

            print(f"\n[CorrelationEngine] [!] AI TOOL ANOMALY DETECTED — Tao Incident: {incident_id}")
            print(f"   [!] Risk Level: {tool_analysis['risk_level']} (Score: {tool_analysis['risk_score']}/100)")

            incident = {
                "incident_id": incident_id,
                "incident_type": "TOOL_ANOMALY",
                "ai_event": event,
                "sysmon_event": {},
                "tool_analysis": tool_analysis,
                "severity": "CRITICAL" if tool_analysis["risk_score"] >= 60 else "HIGH",
            }
            self.incident_queue.put(incident)
            event["_correlated"] = True

        # 3. Response data disclosure detected
        response_analysis = event.get("response_analysis", {})
        if response_analysis.get("has_sensitive_data") and response_analysis.get("risk_level") in ("CRITICAL", "HIGH"):
            incident_id = f"INC-{self.incident_counter:04d}"
            self.incident_counter += 1

            print(f"\n[CorrelationEngine] [!] DATA DISCLOSURE DETECTED — Tao Incident: {incident_id}")
            print(f"   [!] Risk Level: {response_analysis['risk_level']} (Score: {response_analysis['disclosure_score']}/100)")

            incident = {
                "incident_id": incident_id,
                "incident_type": "DATA_DISCLOSURE",
                "ai_event": event,
                "sysmon_event": {},
                "response_analysis": response_analysis,
                "severity": "CRITICAL" if response_analysis["disclosure_score"] >= 60 else "HIGH",
            }
            self.incident_queue.put(incident)
            event["_correlated"] = True

    def _correlate(self):
        """Finds links between AI events and Sysmon events."""
        for ai_evt in self.ai_window:
            if ai_evt.get("_correlated"):
                continue
                
            ai_time = self._parse_utc_time(ai_evt.get("timestamp", ""))
            ai_tool = ai_evt.get("tool", "").lower()
            
            for sys_evt in self.sysmon_window:
                if sys_evt.get("_correlated"):
                    continue
                    
                if sys_evt.get("EventID") != 1:
                    continue
                    
                sys_time = self._parse_utc_time(sys_evt.get("TimestampUTC", ""))
                sys_image = sys_evt.get("Image", "").lower()
                
                # Dùng |Δt| ≤ 2s (giá trị tuyệt đối) vì Sysmon log có thể đến
                # sớm hơn AI Agent log do cơ chế cache của IPC library.
                # Cả hai timestamp đã được chuẩn hoá về UTC-aware nên phép trừ luôn hợp lệ.
                if sys_time == datetime.datetime.min.replace(tzinfo=timezone.utc) or \
                   ai_time == datetime.datetime.min.replace(tzinfo=timezone.utc):
                    continue  # Bỏ qua nếu parse thất bại

                time_diff = abs((sys_time - ai_time).total_seconds())

                if time_diff <= 2.0 and ai_tool in sys_image:
                    incident_id = f"INC-{self.incident_counter:04d}"
                    self.incident_counter += 1
                    
                    print(f"\n[CorrelationEngine] [+] BẮT QUẢ TANG MỐI LIÊN KẾT (CORRELATED)!")
                    print(f"   [+] Sinh ra Incident: {incident_id}")
                    print(f"   [+] |Δt| = {time_diff*1000:.1f}ms (ngưỡng ≤ 2000ms)")
                    
                    incident = {
                        "incident_id": incident_id,
                        "incident_type": "CORRELATED",
                        "ai_event": ai_evt,
                        "sysmon_event": sys_evt
                    }

                    # Enrich voi analysis data neu co
                    if "prompt_analysis" in ai_evt:
                        incident["prompt_analysis"] = ai_evt["prompt_analysis"]
                    if "tool_analysis" in ai_evt:
                        incident["tool_analysis"] = ai_evt["tool_analysis"]

                    self.incident_queue.put(incident)
                    
                    # Mark as correlated
                    ai_evt["_correlated"] = True
                    sys_evt["_correlated"] = True

        # TU DONG CHAY NGAM (BACKGROUND MODE): Bat luon ca cac lenh PowerShell/CMD dang ngo mo coi
        # CHI bat khi CommandLine chua keyword nguy hiem (giam false positive)
        suspicious_cmd_keywords = ["curl", "wget", "invoke-webrequest", "iex", "payload",
                                    "attacker", "malware", "http://", "nc.exe", "certutil",
                                    "base64", "-enc", "downloadstring", "bypass"]

        for sys_evt in self.sysmon_window:
            if sys_evt.get("_correlated") or sys_evt.get("EventID") != 1:
                continue
                
            sys_image = sys_evt.get("Image", "").lower()
            cmdline = sys_evt.get("CommandLine", "").lower()

            if ("powershell" in sys_image or "cmd.exe" in sys_image):
                # Chi tao incident khi CommandLine chua keyword dang ngo
                has_suspicious_keyword = any(kw in cmdline for kw in suspicious_cmd_keywords)
                if not has_suspicious_keyword:
                    continue

                incident_id = f"INC-{self.incident_counter:04d}"
                self.incident_counter += 1
                
                print(f"\n[CorrelationEngine] [!] PHÁT HIỆN TIẾN TRÌNH CHẠY NGẦM ĐÁNG NGỜ!")
                print(f"   [+] Sinh ra Incident: {incident_id}")
                print(f"   [+] CommandLine: {cmdline[:120]}")
                
                # Tao mock AI event
                mock_ai_evt = {"agent": "Background Script/AI", "action": "terminal", "timestamp": sys_evt.get("TimestampUTC", "")}
                
                incident = {
                    "incident_id": incident_id,
                    "incident_type": "ORPHAN_SUSPICIOUS",
                    "ai_event": mock_ai_evt,
                    "sysmon_event": sys_evt
                }
                self.incident_queue.put(incident)
                sys_evt["_correlated"] = True
                    
    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._process_queues, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

