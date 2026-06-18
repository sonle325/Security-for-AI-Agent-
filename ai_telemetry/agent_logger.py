import time
import queue
import datetime
import threading

class AITelemetrySimulator:
    def __init__(self, ai_event_queue: queue.Queue, auto_interval: int = 30):
        self.ai_event_queue = ai_event_queue
        self.auto_interval = auto_interval  # Số giây giữa mỗi lần tự động phát sinh sự kiện
        self.running = False
        self.thread = None

    def trigger_manual_event(self):
        """Manually trigger an AI Event (Mô phỏng Cursor gọi PowerShell)"""
        now_utc = datetime.datetime.utcnow().isoformat() + "Z"
        ai_event = {
            "ai_event_id": f"AI-EVT-{int(time.time())}",
            "agent": "Cursor",
            "action": "terminal.execute",
            "tool": "powershell",
            "timestamp": now_utc
        }
        print(f"\n[AITelemetry] [*] AI AGENT ACTION: Yêu cầu thực thi '{ai_event['tool']}' lúc {now_utc}")
        self.ai_event_queue.put(ai_event)

    def _auto_loop(self):
        """Background thread: tự động phát sinh AI Telemetry Event theo chu kỳ."""
        while self.running:
            self.trigger_manual_event()
            time.sleep(self.auto_interval)

    def start(self):
        """Bắt đầu phát sinh sự kiện tự động trong background thread."""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._auto_loop, daemon=True)
        self.thread.start()
        print("[AITelemetry] [+] Auto-trigger started (interval: {}s).".format(self.auto_interval))

    def stop(self):
        """Dừng auto-trigger."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
