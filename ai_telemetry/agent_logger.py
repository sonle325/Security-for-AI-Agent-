import time
import queue
import datetime
import threading

class AITelemetrySimulator:
    def __init__(self, ai_event_queue: queue.Queue):
        self.ai_event_queue = ai_event_queue

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
