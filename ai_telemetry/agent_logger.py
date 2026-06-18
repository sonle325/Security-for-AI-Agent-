import time
import queue
import datetime
import threading
from ai_telemetry.event_normalizer import EventNormalizer

class AITelemetrySimulator:
    """
    Mô phỏng kênh nhận AI Telemetry từ AI Agent (Cursor, Copilot...).
    Trong triển khai thực tế, các AI Agent sẽ đẩy sự kiện JSON vào đây thông qua IPC Channel.
    Trong Demo, gọi trigger_manual_event() để mô phỏng hành động của AI Agent.
    """
    def __init__(self, ai_event_queue: queue.Queue):
        self.ai_event_queue = ai_event_queue

    def trigger_manual_event(self):
        """Gọi thủ công khi muốn mô phỏng AI Agent thực hiện 1 hành động terminal."""
        now_utc = datetime.datetime.utcnow().isoformat() + "Z"
        ai_event = {
            "ai_event_id": f"AI-EVT-{int(time.time())}",
            "agent": "Cursor",
            "action": "terminal.execute",
            "tool": "powershell",
            "timestamp": now_utc
        }
        print(f"\n[AITelemetry] [*] AI AGENT ACTION: Yêu cầu thực thi '{ai_event['tool']}' lúc {now_utc}")
        # Chuan hoa su kien ve schema thong nhat truoc khi dua vao Correlation Engine
        normalized = EventNormalizer.normalize(ai_event)
        if normalized:
            self.ai_event_queue.put(normalized)
        else:
            self.ai_event_queue.put(ai_event)  # fallback neu normalize that bai
