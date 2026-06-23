import time
import queue
import datetime
import threading
from ai_telemetry.event_normalizer import EventNormalizer

class AITelemetrySimulator:
    """
    Mo phong kenh nhan AI Telemetry tu AI Agent (Cursor, Copilot...).
    Trong trien khai thuc te, cac AI Agent se day su kien JSON vao day thong qua IPC Channel.
    Trong Demo, goi cac trigger methods de mo phong hanh dong cua AI Agent.

    Ho tro 4 loai event:
        - trigger_manual_event(): Mo phong AI Agent thuc thi terminal (agent_action)
        - trigger_prompt_event(): Mo phong prompt injection
        - trigger_tool_event(): Mo phong AI goi tool (file_read, web_search...)
        - trigger_response_event(): Mo phong AI tra ve response co du lieu nhay cam
    """
    def __init__(self, ai_event_queue: queue.Queue):
        self.ai_event_queue = ai_event_queue

    def trigger_manual_event(self):
        """Goi thu cong khi muon mo phong AI Agent thuc hien 1 hanh dong terminal."""
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
        # Chuan hoa su kien ve schema thong nhat truoc khi dua vao Correlation Engine
        normalized = EventNormalizer.normalize(ai_event)
        if normalized:
            self.ai_event_queue.put(normalized)
        else:
            self.ai_event_queue.put(ai_event)  # fallback neu normalize that bai

    def trigger_prompt_event(self, content: str, agent: str = "Cursor",
                             prompt_type: str = "user"):
        """
        Mo phong AI Agent nhan prompt tu user.

        Args:
            content: Noi dung prompt.
            agent: Ten AI Agent.
            prompt_type: "user", "system", hoac "assistant".
        """
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
        """
        Mo phong AI Agent goi tool.

        Args:
            tool_type: Loai tool (file_read, file_write, terminal_execute, web_search...).
            target: Muc tieu (duong dan file, URL, lenh...).
            agent: Ten AI Agent.
        """
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
        """
        Mo phong AI Agent tra ve response.

        Args:
            content: Noi dung response cua AI.
            agent: Ten AI Agent.
            model: Ten model AI.
        """
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

