"""
AI Telemetry Event Normalizer
==============================
Chuan hoa cac su kien AI Telemetry tu nhieu nguon khac nhau
(Cursor, GitHub Copilot, Claude Code, AI Agent noi bo...)
ve mot dinh dang thong nhat truoc khi dua vao Correlation Engine.

Trong thiet ke thuc te, cac AI Agent gui su kien JSON qua IPC Channel
(Named Pipe hoac Local Queue). Module nay dam nhan viec chuan hoa
cac dinh dang khac nhau do.

Ho tro 4 loai event:
    - prompt: Noi dung prompt cua user/system
    - response: Noi dung response cua AI
    - tool_invocation: AI goi tool (file_read, terminal_execute...)
    - agent_action: AI thuc thi hanh dong tren he thong
"""

import datetime
from typing import Optional, Dict, Any


class EventNormalizer:
    """
    Chuan hoa AI Telemetry Event tu nhieu dinh dang khac nhau
    ve mot schema thong nhat.
    """

    # Schema chuan: dinh dang dau ra bat buoc phai co
    REQUIRED_FIELDS = ["ai_event_id", "agent", "action", "tool", "timestamp"]

    # Cac loai event duoc ho tro
    VALID_EVENT_TYPES = [
        "prompt",           # User/System prompt
        "response",         # AI response
        "tool_invocation",  # AI goi tool
        "agent_action",     # AI thuc thi hanh dong
        "unknown"           # Mac dinh
    ]

    # Danh sach AI Agent duoc nhan dien
    KNOWN_AGENTS = [
        "Cursor",
        "GitHub Copilot",
        "Claude Code",
        "OpenAI Agent",
        "Viettel AI",
        "Unknown Agent"
    ]

    @staticmethod
    def normalize(raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Chuan hoa mot su kien tho tu AI Agent.

        Args:
            raw_event: Dict chua du lieu tho tu AI Agent gui len qua IPC.

        Returns:
            Dict da chuan hoa theo schema thong nhat, hoac None neu su kien khong hop le.
        """
        if not raw_event or not isinstance(raw_event, dict):
            return None

        # Xac dinh event_type
        event_type = (
            raw_event.get("event_type")
            or raw_event.get("type")
            or "unknown"
        ).lower()

        if event_type not in EventNormalizer.VALID_EVENT_TYPES:
            event_type = "agent_action"  # Fallback cho event cu

        # Trich xuat va chuan hoa cac truong chinh
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

            # Cac truong tuy chon (chung)
            "raw_command": raw_event.get("raw_command") or raw_event.get("cmdline", ""),
            "session_id":  raw_event.get("session_id", ""),
            "user":        raw_event.get("user", ""),
        }

        # Them cac truong dac trung cho tung event_type
        if event_type == "prompt":
            normalized["content"] = raw_event.get("content", "")
            normalized["prompt_type"] = raw_event.get("prompt_type", "user")
            # Giu lai prompt_analysis neu da duoc PromptMonitor xu ly
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

        # Kiem tra tinh hop le
        if not EventNormalizer._is_valid(normalized):
            return None

        return normalized

    @staticmethod
    def _normalize_agent(agent_str: Optional[str]) -> str:
        """Chuan hoa ten AI Agent."""
        if not agent_str:
            return "Unknown Agent"
        # So khop khong phan biet hoa thuong
        agent_lower = agent_str.lower()
        for known in EventNormalizer.KNOWN_AGENTS:
            if known.lower() in agent_lower:
                return known
        return agent_str  # Giu nguyen neu la agent chua biet

    @staticmethod
    def _normalize_tool(tool_str: Optional[str]) -> str:
        """Chuan hoa ten cong cu/tien trinh."""
        if not tool_str:
            return "unknown"
        # Lay ten file thuc thi cuoi cung, bo duong dan
        tool_lower = tool_str.lower().strip()
        if "\\" in tool_lower:
            tool_lower = tool_lower.split("\\")[-1]
        if "/" in tool_lower:
            tool_lower = tool_lower.split("/")[-1]
        return tool_lower

    @staticmethod
    def _is_valid(event: Dict[str, Any]) -> bool:
        """Kiem tra su kien co du cac truong bat buoc khong."""
        return all(event.get(field) for field in ["ai_event_id", "action"])

