import time
import queue
import datetime
import threading
from ai_telemetry.event_normalizer import EventNormalizer


class AITelemetrySimulator:
    """
    Giả lập kênh nhận AI Telemetry từ AI Agent (Cursor, Copilot...).
    Dùng cho demo — trong thực tế AI Agent đẩy JSON qua IPC Channel.
    """
    def __init__(self, ai_event_queue: queue.Queue):
        self.ai_event_queue = ai_event_queue

    def trigger_manual_event(self):
        """Giả lập AI Agent thực thi 1 lệnh terminal."""
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        ai_event = {
            "ai_event_id": f"AI-EVT-{int(time.time())}",
            "event_type": "agent_action",
            "agent": "Cursor",
            "action": "terminal.execute",
            "tool": "powershell",
            "timestamp": now_utc
        }
        print(f"\n[AITelemetry] [*] AI AGENT ACTION: Yeu cau thuc thi '{ai_event['tool']}' luc {now_utc}")
        normalized = EventNormalizer.normalize(ai_event)
        if normalized:
            self.ai_event_queue.put(normalized)
        else:
            self.ai_event_queue.put(ai_event)

    def trigger_prompt_event(self, content: str, agent: str = "Cursor",
                             prompt_type: str = "user"):
        """Giả lập AI Agent nhận prompt từ user."""
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        ai_event = {
            "ai_event_id": f"PROMPT-{int(time.time() * 1000)}",
            "event_type": "prompt",
            "agent": agent,
            "action": "prompt.received",
            "tool": "llm",
            "content": content,
            "prompt_type": prompt_type,
            "timestamp": now_utc
        }
        print(f"\n[AITelemetry] [*] PROMPT EVENT: Agent={agent}, Type={prompt_type}")
        print(f"   [*] Content: {content[:100]}{'...' if len(content) > 100 else ''}")
        normalized = EventNormalizer.normalize(ai_event)
        self.ai_event_queue.put(normalized if normalized else ai_event)

    def trigger_tool_event(self, tool_type: str, target: str = "",
                           agent: str = "Cursor"):
        """Giả lập AI Agent gọi tool (file_read, web_search...)."""
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        ai_event = {
            "ai_event_id": f"TOOL-{int(time.time() * 1000)}",
            "event_type": "tool_invocation",
            "agent": agent,
            "action": f"tool.{tool_type}",
            "tool": tool_type,
            "tool_type": tool_type,
            "target": target,
            "timestamp": now_utc
        }
        print(f"\n[AITelemetry] [*] TOOL INVOCATION: {tool_type} -> {target}")
        normalized = EventNormalizer.normalize(ai_event)
        self.ai_event_queue.put(normalized if normalized else ai_event)

    def trigger_response_event(self, content: str, agent: str = "Cursor",
                               model: str = "gpt-4"):
        """Giả lập AI Agent trả về response."""
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        ai_event = {
            "ai_event_id": f"RESP-{int(time.time() * 1000)}",
            "event_type": "response",
            "agent": agent,
            "action": "response.generated",
            "tool": "llm",
            "content": content,
            "model": model,
            "timestamp": now_utc
        }
        print(f"\n[AITelemetry] [*] RESPONSE EVENT: Agent={agent}, Model={model}")
        print(f"   [*] Content: {content[:100]}{'...' if len(content) > 100 else ''}")
        normalized = EventNormalizer.normalize(ai_event)
        self.ai_event_queue.put(normalized if normalized else ai_event)
