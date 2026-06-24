import datetime
from typing import Optional, Dict, Any


class EventNormalizer:
    """Chuẩn hoá AI event từ nhiều nguồn (Cursor, Copilot, Claude...) về schema thống nhất."""

    REQUIRED_FIELDS = ["ai_event_id", "agent", "action", "tool", "timestamp"]

    VALID_EVENT_TYPES = [
        "prompt", "response", "tool_invocation", "agent_action", "unknown"
    ]

    KNOWN_AGENTS = [
        "Cursor", "GitHub Copilot", "Claude Code",
        "OpenAI Agent", "Viettel AI", "Unknown Agent"
    ]

    @staticmethod
    def normalize(raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not raw_event or not isinstance(raw_event, dict):
            return None

        event_type = (
            raw_event.get("event_type")
            or raw_event.get("type")
            or "unknown"
        ).lower()

        if event_type not in EventNormalizer.VALID_EVENT_TYPES:
            event_type = "agent_action"

        normalized = {
            "ai_event_id": raw_event.get("ai_event_id")
                           or raw_event.get("event_id")
                           or raw_event.get("id")
                           or f"AI-EVT-NORM-{int(datetime.datetime.now(datetime.timezone.utc).timestamp())}",

            "event_type": event_type,

            "agent": EventNormalizer._normalize_agent(
                raw_event.get("agent")
                or raw_event.get("source")
                or raw_event.get("sender")
            ),

            "action": raw_event.get("action")
                      or raw_event.get("type")
                      or raw_event.get("event_type")
                      or "unknown.action",

            "tool": EventNormalizer._normalize_tool(
                raw_event.get("tool")
                or raw_event.get("command")
                or raw_event.get("executable")
                or raw_event.get("tool_type")
            ),

            "timestamp": raw_event.get("timestamp")
                         or raw_event.get("time")
                         or datetime.datetime.now(datetime.timezone.utc).isoformat(),

            "raw_command": raw_event.get("raw_command") or raw_event.get("cmdline", ""),
            "session_id":  raw_event.get("session_id", ""),
            "user":        raw_event.get("user", ""),
        }

        # Thêm trường đặc trưng theo event_type
        if event_type == "prompt":
            normalized["content"] = raw_event.get("content", "")
            normalized["prompt_type"] = raw_event.get("prompt_type", "user")
            if "prompt_analysis" in raw_event:
                normalized["prompt_analysis"] = raw_event["prompt_analysis"]

        elif event_type == "response":
            normalized["content"] = raw_event.get("content", "")
            normalized["model"] = raw_event.get("model", "")
            if "response_analysis" in raw_event:
                normalized["response_analysis"] = raw_event["response_analysis"]

        elif event_type == "tool_invocation":
            normalized["tool_type"] = raw_event.get("tool_type", "unknown")
            normalized["target"] = raw_event.get("target", "")
            normalized["parameters"] = raw_event.get("parameters", {})
            if "tool_analysis" in raw_event:
                normalized["tool_analysis"] = raw_event["tool_analysis"]

        elif event_type == "agent_action":
            normalized["tool_type"] = raw_event.get("tool_type", "")
            normalized["target"] = raw_event.get("target", "")

        if not EventNormalizer._is_valid(normalized):
            return None

        return normalized

    @staticmethod
    def _normalize_agent(agent_str: Optional[str]) -> str:
        if not agent_str:
            return "Unknown Agent"
        agent_lower = agent_str.lower()
        for known in EventNormalizer.KNOWN_AGENTS:
            if known.lower() in agent_lower:
                return known
        return agent_str

    @staticmethod
    def _normalize_tool(tool_str: Optional[str]) -> str:
        if not tool_str:
            return "unknown"
        tool_lower = tool_str.lower().strip()
        if "\\" in tool_lower:
            tool_lower = tool_lower.split("\\")[-1]
        if "/" in tool_lower:
            tool_lower = tool_lower.split("/")[-1]
        return tool_lower

    @staticmethod
    def _is_valid(event: Dict[str, Any]) -> bool:
        return all(event.get(field) for field in ["ai_event_id", "action"])
