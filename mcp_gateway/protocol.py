"""MCP Protocol — JSON-RPC 2.0 message parser/serializer cho MCP transport."""

import json
import logging
from typing import Dict, Any, Optional, Tuple, List

logger = logging.getLogger("EDR.MCP.Protocol")


# --- MCP Method Constants ---
METHOD_TOOLS_CALL = "tools/call"
METHOD_TOOLS_LIST = "tools/list"
METHOD_RESOURCES_READ = "resources/read"
METHOD_RESOURCES_LIST = "resources/list"
METHOD_PROMPTS_GET = "prompts/get"
METHOD_PROMPTS_LIST = "prompts/list"
METHOD_INITIALIZE = "initialize"
METHOD_PING = "ping"


INTERCEPTABLE_METHODS = {
    METHOD_TOOLS_CALL,
    METHOD_RESOURCES_READ,
    METHOD_PROMPTS_GET,
}


LOG_ONLY_METHODS = {
    METHOD_TOOLS_LIST,
    METHOD_RESOURCES_LIST,
    METHOD_PROMPTS_LIST,
    METHOD_INITIALIZE,
    METHOD_PING,
}


class MCPMessage:
    """Parsed MCP JSON-RPC 2.0 message."""

    __slots__ = ("raw", "jsonrpc", "id", "method", "params", "result", "error",
                 "is_request", "is_response", "is_notification")

    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.jsonrpc = raw.get("jsonrpc", "2.0")
        self.id = raw.get("id")
        self.method = raw.get("method")
        self.params = raw.get("params", {})
        self.result = raw.get("result")
        self.error = raw.get("error")


        self.is_request = self.method is not None and self.id is not None
        self.is_notification = self.method is not None and self.id is None
        self.is_response = self.method is None and self.id is not None

    def is_tool_call(self) -> bool:
        return self.is_request and self.method == METHOD_TOOLS_CALL

    def is_resource_read(self) -> bool:
        return self.is_request and self.method == METHOD_RESOURCES_READ

    def is_interceptable(self) -> bool:
        return self.is_request and self.method in INTERCEPTABLE_METHODS

    def get_tool_name(self) -> str:
        if not self.is_tool_call():
            return ""
        return self.params.get("name", "")

    def get_tool_arguments(self) -> Dict[str, Any]:
        if not self.is_tool_call():
            return {}
        return self.params.get("arguments", {})

    def get_resource_uri(self) -> str:
        if not self.is_resource_read():
            return ""
        return self.params.get("uri", "")

    def __repr__(self):
        if self.is_request:
            return f"MCPMessage(request, method={self.method}, id={self.id})"
        elif self.is_response:
            return f"MCPMessage(response, id={self.id}, error={self.error is not None})"
        else:
            return f"MCPMessage(notification, method={self.method})"


class MCPProtocol:
    """Parse và serialize MCP JSON-RPC 2.0 messages với Content-Length framing."""

    CONTENT_LENGTH_HEADER = b"Content-Length: "
    HEADER_SEPARATOR = b"\r\n\r\n"

    @staticmethod
    def parse_message(raw_json: str) -> Optional[MCPMessage]:
        try:
            data = json.loads(raw_json)
            if not isinstance(data, dict):
                return None
            return MCPMessage(data)
        except (json.JSONDecodeError, TypeError) as e:
            logger.debug("Failed to parse MCP message: %s", e)
            return None

    @staticmethod
    def parse_batch(raw_json: str) -> List[MCPMessage]:
        try:
            data = json.loads(raw_json)
            if isinstance(data, list):
                return [MCPMessage(item) for item in data if isinstance(item, dict)]
            elif isinstance(data, dict):
                return [MCPMessage(data)]
            return []
        except (json.JSONDecodeError, TypeError):
            return []

    @staticmethod
    def serialize(msg: Dict[str, Any]) -> str:
        return json.dumps(msg, ensure_ascii=False)

    @staticmethod
    def frame_message(json_str: str) -> bytes:
        content = json_str.encode("utf-8")
        header = f"Content-Length: {len(content)}\r\n\r\n".encode("utf-8")
        return header + content

    @staticmethod
    def make_error_response(request_id: Any, code: int, message: str,
                            data: Optional[Dict] = None) -> Dict[str, Any]:
        error = {"code": code, "message": message}
        if data:
            error["data"] = data
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": error,
        }

    @staticmethod
    def make_success_response(request_id: Any, result: Any) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result,
        }

    @staticmethod
    def make_blocked_response(request_id: Any, reason: str,
                              risk_score: int = 0) -> Dict[str, Any]:
        return MCPProtocol.make_error_response(
            request_id,
            code=-32000,
            message=f"[EDR Security] Tool call blocked: {reason}",
            data={
                "blocked_by": "AI_Runtime_Security_EDR",
                "risk_score": risk_score,
                "reason": reason,
            }
        )


class StdioFrameReader:
    """Reader cho Content-Length framed messages."""

    def __init__(self):
        self._buffer = b""

    def feed(self, data: bytes) -> List[str]:
        self._buffer += data
        messages = []

        while True:
            # Tìm header separator
            sep_pos = self._buffer.find(MCPProtocol.HEADER_SEPARATOR)
            if sep_pos == -1:
                break


            header_part = self._buffer[:sep_pos]
            content_length = self._parse_content_length(header_part)
            if content_length is None:
                self._buffer = self._buffer[sep_pos + len(MCPProtocol.HEADER_SEPARATOR):]
                continue


            content_start = sep_pos + len(MCPProtocol.HEADER_SEPARATOR)
            content_end = content_start + content_length

            if len(self._buffer) < content_end:
                break


            content = self._buffer[content_start:content_end].decode("utf-8", errors="replace")
            messages.append(content)


            self._buffer = self._buffer[content_end:]

        return messages

    @staticmethod
    def _parse_content_length(header: bytes) -> Optional[int]:
        for line in header.split(b"\r\n"):
            line_stripped = line.strip()
            if line_stripped.lower().startswith(b"content-length:"):
                try:
                    value = line_stripped.split(b":", 1)[1].strip()
                    return int(value)
                except (ValueError, IndexError):
                    return None
        return None
