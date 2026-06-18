import queue
import threading
import datetime
import time

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
        """Parses UTC string like '2026-06-16T18:10:00Z' or Sysmon's '2026-06-16T11:41:48.1234567Z'"""
        if not time_str:
            return datetime.datetime.min
        try:
            time_str = time_str.replace("Z", "")
            if "." in time_str:
                # Sysmon có thể trả về 7 chữ số sau dấu chấm, Python %f chỉ hỗ trợ 6
                parts = time_str.split(".")
                parts[1] = parts[1][:6]
                time_str = f"{parts[0]}.{parts[1]}"
                return datetime.datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%f")
            else:
                return datetime.datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S")
        except Exception as e:
            return datetime.datetime.min

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
                    self.ai_event_queue.task_done()
                except queue.Empty:
                    break
                    
            # Pull Sysmon Events
            while not self.sysmon_queue.empty():
                try:
                    event = self.sysmon_queue.get_nowait()
                    # Also log raw Sysmon events for visibility if not correlated yet
                    if event.get("EventID") in [1, 3, 11]:
                        self.sysmon_window.append(event)
                    self.sysmon_queue.task_done()
                except queue.Empty:
                    break

            now = datetime.datetime.utcnow()
            self.ai_window = self._clean_window(self.ai_window, now)
            self.sysmon_window = self._clean_window(self.sysmon_window, now)
            
            # Correlate
            self._correlate()
            
            time.sleep(0.5)

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
                
                # Rule: time_diff <= 2s AND tool matches image (theo thiet ke: Delta_t <= 2 giay)
                time_diff = abs((sys_time - ai_time).total_seconds())
                
                if time_diff <= 2.0 and ai_tool in sys_image:
                    incident_id = f"INC-{self.incident_counter:04d}"
                    self.incident_counter += 1
                    
                    print(f"\n[CorrelationEngine] [+] BẮT QUẢ TANG MỐI LIÊN KẾT (CORRELATED)!")
                    print(f"   [+] Sinh ra Incident: {incident_id}")
                    print(f"   [+] Độ trễ (Time Diff): {time_diff:.3f} giây")
                    
                    incident = {
                        "incident_id": incident_id,
                        "ai_event": ai_evt,
                        "sysmon_event": sys_evt
                    }
                    self.incident_queue.put(incident)
                    
                    # Mark as correlated
                    ai_evt["_correlated"] = True
                    sys_evt["_correlated"] = True

        # TỰ ĐỘNG CHẠY NGẦM (BACKGROUND MODE): Bắt luôn cả các lệnh PowerShell/CMD đáng ngờ mồ côi
        for sys_evt in self.sysmon_window:
            if sys_evt.get("_correlated") or sys_evt.get("EventID") != 1:
                continue
                
            sys_image = sys_evt.get("Image", "").lower()
            if "powershell" in sys_image or "cmd.exe" in sys_image:
                incident_id = f"INC-{self.incident_counter:04d}"
                self.incident_counter += 1
                
                print(f"\n[CorrelationEngine] [!] PHÁT HIỆN TIẾN TRÌNH CHẠY NGẦM ĐÁNG NGỜ!")
                print(f"   [+] Sinh ra Incident: {incident_id}")
                
                # Tạo mock AI event
                mock_ai_evt = {"agent": "Background Script/AI", "action": "terminal", "timestamp": sys_evt.get("TimestampUTC", "")}
                
                incident = {
                    "incident_id": incident_id,
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
