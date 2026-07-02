import json
import queue
import logging
import threading
import time
from typing import Optional, Dict, Any

from ai_telemetry.event_normalizer import EventNormalizer
from ai_telemetry.prompt_monitor import PromptMonitor
from ai_telemetry.tool_monitor import ToolMonitor
from ai_telemetry.response_monitor import ResponseMonitor
import config_loader

logger = logging.getLogger("EDR.IPC")


class IPCTelemetryServer:
    """Nhận AI Telemetry qua Named Pipe hoặc TCP Socket fallback."""

    def __init__(self, ai_event_queue: queue.Queue):
        self.ai_event_queue = ai_event_queue
        self.running = False
        self.thread = None
        self.pipe_handle = None

        ipc_cfg = config_loader.get("ipc", default={})
        self.PIPE_NAME = ipc_cfg.get("pipe_name", r"\\.\pipe\ai_edr_telemetry")
        self.BUFFER_SIZE = ipc_cfg.get("buffer_size", 65536)
        self.AUTH_TOKEN = ipc_cfg.get("auth_token", "EDR_SECRET_2026")

        self.prompt_monitor = PromptMonitor()
        self.tool_monitor = ToolMonitor()
        self.response_monitor = ResponseMonitor()

    def _process_event(self, raw_json: str) -> Optional[Dict[str, Any]]:
        try:
            event = json.loads(raw_json.strip())
        except json.JSONDecodeError:
            return None
        if not isinstance(event, dict):
            return None
            
        # Xác thực Token chống Local Fake Event Injection
        if event.get("auth_token") != self.AUTH_TOKEN:
            logger.warning("Cảnh báo: Bắt được IPC event thiếu Auth Token hợp lệ!")
            return None

        event_type = (event.get("event_type") or event.get("type") or "").lower()

        if event_type == "prompt":
            event = self.prompt_monitor.analyze(event)
        elif event_type == "response":
            event = self.response_monitor.analyze(event)
        elif event_type in ("tool_invocation", "tool_call", "tool"):
            event = self.tool_monitor.analyze(event)
        elif event_type == "agent_action" and (event.get("tool_type") or event.get("tool_name")):
            event = self.tool_monitor.analyze(event)

        normalized = EventNormalizer.normalize(event)
        return normalized if normalized else event

    def _listen_loop(self):
        try:
            import win32pipe  # type: ignore
            import win32file  # type: ignore
            import pywintypes  # type: ignore
        except ImportError:
            logger.info("pywin32 not available, using Socket fallback...")
            self._listen_socket_fallback()
            return

        while self.running:
            try:
                self.pipe_handle = win32pipe.CreateNamedPipe(
                    self.PIPE_NAME,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    self.BUFFER_SIZE, self.BUFFER_SIZE, 0, None
                )

                print(f"[IPC Server] Đợi AI Agent kết nối trên {self.PIPE_NAME}...")
                win32pipe.ConnectNamedPipe(self.pipe_handle, None)
                logger.info("AI Agent connected!")

                buffer = ""
                while self.running:
                    try:
                        result, data = win32file.ReadFile(self.pipe_handle, self.BUFFER_SIZE)
                        if result == 0:
                            buffer += data.decode("utf-8", errors="replace")
                            while "\n" in buffer:
                                line, buffer = buffer.split("\n", 1)
                                line = line.strip()
                                if line:
                                    processed = self._process_event(line)
                                    if processed:
                                        self.ai_event_queue.put(processed)
                    except pywintypes.error as e:
                        if e.args[0] == 109:  # ERROR_BROKEN_PIPE
                            logger.info("Client disconnected.")
                            break
                        else:
                            break

            except pywintypes.error:
                if self.running:
                    time.sleep(2)
            except Exception:
                if self.running:
                    time.sleep(2)
            finally:
                if self.pipe_handle:
                    try:
                        win32file.CloseHandle(self.pipe_handle)
                    except Exception:
                        pass
                    self.pipe_handle = None

    def _listen_socket_fallback(self):
        import socket
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(2.0)
        try:
            srv.bind(("127.0.0.1", 9999))
            srv.listen(5)
            logger.info("Socket fallback: 127.0.0.1:9999")
            while self.running:
                try:
                    client, addr = srv.accept()
                    threading.Thread(target=self._handle_socket, args=(client,), daemon=True).start()
                except socket.timeout:
                    continue
        finally:
            srv.close()

    def _handle_socket(self, sock):
        import socket
        buffer = ""
        sock.settimeout(1.0)
        try:
            while self.running:
                try:
                    data = sock.recv(self.BUFFER_SIZE)
                    if not data:
                        break
                    buffer += data.decode("utf-8", errors="replace")
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        if line.strip():
                            processed = self._process_event(line.strip())
                            if processed:
                                self.ai_event_queue.put(processed)
                except socket.timeout:
                    continue
        except Exception:
            pass
        finally:
            sock.close()

    def inject_event(self, event: Dict[str, Any]):
        """Cho module khác đẩy event trực tiếp vào pipeline (dùng cho demo)."""
        processed = self._process_event(json.dumps(event))
        if processed:
            self.ai_event_queue.put(processed)

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.thread.start()
        logger.info("AI Telemetry IPC Server started.")

    def stop(self):
        self.running = False
        if self.pipe_handle:
            try:
                import win32file  # type: ignore
                win32file.CloseHandle(self.pipe_handle)
            except Exception:
                pass
            self.pipe_handle = None
        if self.thread:
            self.thread.join(timeout=3)
