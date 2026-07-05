"""LSP Protocol Interceptor — Transparent Proxy for LSP (JSON-RPC 2.0).

Intercepts JSON-RPC messages between IDE and Language Server
to detect AI Agent actions executed via IDE.
"""

import asyncio
import json
import queue
import logging
import threading
import datetime
import time
import re
from typing import Dict, Any, Optional, List

from mcp_gateway.protocol import MCPProtocol, StdioFrameReader
import config_loader

logger = logging.getLogger("EDR.LSP.Interceptor")


# --- LSP Method Constants ---
LSP_EXECUTE_COMMAND = "workspace/executeCommand"
LSP_APPLY_EDIT = "workspace/applyEdit"
LSP_DID_SAVE = "textDocument/didSave"
LSP_COMPLETION = "textDocument/completion"
LSP_SHOW_MESSAGE = "window/showMessage"
LSP_DID_OPEN = "textDocument/didOpen"
LSP_DID_CHANGE = "textDocument/didChange"
LSP_CODE_ACTION = "textDocument/codeAction"

# Security analysis methods (can be blocked)
INTERCEPTABLE_LSP_METHODS = {
    LSP_EXECUTE_COMMAND,
    LSP_APPLY_EDIT,
}

# Log-only methods (no blocking)
LOG_ONLY_LSP_METHODS = {
    LSP_DID_SAVE,
    LSP_COMPLETION,
    LSP_SHOW_MESSAGE,
    LSP_DID_OPEN,
    LSP_DID_CHANGE,
    LSP_CODE_ACTION,
}


class LSPVerdict:
    """Security analysis result for an LSP message."""

    __slots__ = ("action", "risk_score", "risk_level", "reasons", "matched_rules")

    def __init__(self, action: str = "ALLOW", risk_score: int = 0,
                 risk_level: str = "NONE", reasons: List[str] = None,
                 matched_rules: List[str] = None):
        self.action = action
        self.risk_score = risk_score
        self.risk_level = risk_level
        self.reasons = reasons or []
        self.matched_rules = matched_rules or []


class LSPMessageAnalyzer:
    """Security analyzer for LSP JSON-RPC messages."""

    # Dangerous commands in workspace/executeCommand
    DANGEROUS_COMMANDS = [
        "terminal.execute", "terminal.sendText", "workbench.action.terminal.sendSequence",
        "workbench.action.terminal.new", "workbench.action.terminal.runSelectedText",
        "python.execInTerminal", "python.execSelectionInTerminal",
        "shellCommand.execute", "command.execute",
    ]

    # Dangerous patterns in executeCommand arguments
    DANGEROUS_ARG_PATTERNS = [
        re.compile(r"(?i)powershell.*(-enc|invoke-webrequest|iex|invoke-expression|downloadstring)", re.DOTALL),
        re.compile(r"(?i)curl.*(-o|--output|http)", re.DOTALL),
        re.compile(r"(?i)wget\s+http", re.DOTALL),
        re.compile(r"(?i)(mimikatz|nc\.exe|ncat|netcat|meterpreter|cobalt)", re.DOTALL),
        re.compile(r"(?i)certutil.*-decode", re.DOTALL),
        re.compile(r"(?i)(rm\s+-rf|del\s+/[sfq]|format\s+[a-z]:)", re.DOTALL),
        re.compile(r"(?i)reg\s+add.*\\\\run", re.DOTALL),
        re.compile(r"(?i)schtasks\s+/create", re.DOTALL),
        re.compile(r"(?i)(\.env|id_rsa|credentials|aws_secret|private.?key)", re.DOTALL),
    ]

    # Sensitive file patterns for applyEdit
    SENSITIVE_FILE_PATTERNS = [
        re.compile(r"(?i)\.(env|pem|key|p12|pfx|jks)$"),
        re.compile(r"(?i)(id_rsa|credentials|secrets|passwd|shadow|kubeconfig)"),
        re.compile(r"(?i)(\.ssh|\.aws|\.gnupg)"),
    ]

    def analyze_execute_command(self, method: str, params: Dict[str, Any]) -> LSPVerdict:
        """Analyze workspace/executeCommand."""
        command = params.get("command", "")
        arguments = params.get("arguments", [])
        args_str = json.dumps(arguments, ensure_ascii=False) if arguments else ""

        reasons = []
        matched_rules = []
        risk_score = 0

        # Check 1: Command name is in dangerous list
        for dangerous_cmd in self.DANGEROUS_COMMANDS:
            if dangerous_cmd.lower() in command.lower():
                risk_score += 50
                reasons.append(f"Dangerous LSP command: {command}")
                matched_rules.append(f"DANGEROUS_LSP_CMD:{command}")
                break

        # Check 2: Arguments contain dangerous patterns
        for pattern in self.DANGEROUS_ARG_PATTERNS:
            if pattern.search(args_str):
                risk_score += 40
                reasons.append(f"Dangerous argument pattern: {pattern.pattern[:60]}")
                matched_rules.append(f"DANGEROUS_ARG:{pattern.pattern[:40]}")

        # Check 3: Arguments contain suspicious keywords (fallback)
        suspicious_keywords = config_loader.get(
            "lsp_interceptor.dangerous_keywords",
            default=["payload", "attacker", "malware", "c2.", "exfiltrate"]
        )
        args_lower = args_str.lower()
        for keyword in suspicious_keywords:
            if keyword.lower() in args_lower:
                risk_score += 20
                reasons.append(f"Suspicious keyword in args: {keyword}")
                matched_rules.append(f"KEYWORD:{keyword}")

        risk_score = min(100, risk_score)

        # Classify
        if risk_score >= 60:
            return LSPVerdict("BLOCK", risk_score, "CRITICAL", reasons, matched_rules)
        elif risk_score >= 35:
            return LSPVerdict("ALERT", risk_score, "HIGH", reasons, matched_rules)
        elif risk_score >= 15:
            return LSPVerdict("ALERT", risk_score, "MEDIUM", reasons, matched_rules)
        elif risk_score > 0:
            return LSPVerdict("ALLOW", risk_score, "LOW", reasons, matched_rules)
        else:
            return LSPVerdict("ALLOW", 0, "NONE", [], [])

    def analyze_apply_edit(self, method: str, params: Dict[str, Any]) -> LSPVerdict:
        """Analyze workspace/applyEdit."""
        reasons = []
        matched_rules = []
        risk_score = 0

        # Extract edited files
        edit = params.get("edit", {})
        changes = edit.get("changes", {})
        doc_changes = edit.get("documentChanges", [])

        target_files = list(changes.keys())
        for doc_change in doc_changes:
            if isinstance(doc_change, dict):
                text_doc = doc_change.get("textDocument", {})
                uri = text_doc.get("uri", "")
                if uri:
                    target_files.append(uri)

        # Check: sensitive file edits
        for file_path in target_files:
            for pattern in self.SENSITIVE_FILE_PATTERNS:
                if pattern.search(file_path):
                    risk_score += 60
                    reasons.append(f"Editing sensitive file: {file_path}")
                    matched_rules.append(f"SENSITIVE_FILE_EDIT:{file_path}")

        risk_score = min(100, risk_score)

        if risk_score >= 60:
            return LSPVerdict("BLOCK", risk_score, "CRITICAL", reasons, matched_rules)
        elif risk_score >= 35:
            return LSPVerdict("ALERT", risk_score, "HIGH", reasons, matched_rules)
        elif risk_score > 0:
            return LSPVerdict("ALLOW", risk_score, "LOW", reasons, matched_rules)
        else:
            return LSPVerdict("ALLOW", 0, "NONE", [], [])

    def analyze(self, method: str, params: Dict[str, Any]) -> Optional[LSPVerdict]:
        """Dispatch analysis based on method type."""
        if method == LSP_EXECUTE_COMMAND:
            return self.analyze_execute_command(method, params)
        elif method == LSP_APPLY_EDIT:
            return self.analyze_apply_edit(method, params)
        return None


class LSPProtocolInterceptor:
    """Transparent Proxy TCP for LSP protocol between IDE and Language Server.

    - Parses JSON-RPC 2.0 messages with Content-Length framing
    - Analyzes workspace/executeCommand, workspace/applyEdit
    - Emits events to ai_event_queue for Correlation Engine
    - Supports MONITOR (log only) and INTERCEPT (block threats)
    """

    def __init__(self, ai_event_queue: queue.Queue):
        self.ai_event_queue = ai_event_queue
        self.running = False
        self._thread = None
        self._loop = None

        # Config
        lsp_cfg = config_loader.get("lsp_interceptor", default={})
        self.enabled = lsp_cfg.get("enabled", True)
        self.mode = lsp_cfg.get("mode", "MONITOR").upper()
        self.listen_port = lsp_cfg.get("listen_port", 9001)
        self.upstream_host = lsp_cfg.get("upstream_host", "127.0.0.1")
        self.upstream_port = lsp_cfg.get("upstream_port", 9002)
        self.block_threshold = lsp_cfg.get("block_threshold", 60)

        # Analyzer
        self.analyzer = LSPMessageAnalyzer()

        # Stats
        self._stats = {
            "total_messages": 0,
            "total_interceptable": 0,
            "total_blocked": 0,
            "total_alerts": 0,
        }
        self._stats_lock = threading.Lock()

    # ── Lifecycle ──────────────────────────────────────────────

    def start(self):
        if not self.enabled:
            logger.info("LSP Protocol Interceptor is DISABLED in config.")
            return
        if self.running:
            return

        self.running = True
        self._thread = threading.Thread(target=self._run_event_loop, daemon=True)
        self._thread.start()
        logger.info(
            "LSP Protocol Interceptor started (mode=%s, listen=%d, upstream=%s:%d)",
            self.mode, self.listen_port, self.upstream_host, self.upstream_port,
        )

    def stop(self):
        self.running = False
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("LSP Protocol Interceptor stopped. Stats: %s", self._stats)

    def get_stats(self) -> Dict[str, int]:
        with self._stats_lock:
            return dict(self._stats)

    # ── Asyncio Event Loop ─────────────────────────────────────

    def _run_event_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._start_tcp_proxy())
        except Exception as e:
            if self.running:
                logger.error("LSP Interceptor event loop error: %s", e)
        finally:
            self._loop.close()

    async def _start_tcp_proxy(self):
        server = await asyncio.start_server(
            self._handle_client,
            "127.0.0.1",
            self.listen_port,
        )
        logger.info("LSP TCP Proxy listening on 127.0.0.1:%d", self.listen_port)

        async with server:
            while self.running:
                await asyncio.sleep(0.5)

    # ── Connection Handler ─────────────────────────────────────

    async def _handle_client(self, client_reader: asyncio.StreamReader,
                             client_writer: asyncio.StreamWriter):
        client_addr = client_writer.get_extra_info("peername")
        logger.info("LSP client connected: %s", client_addr)

        upstream_reader = None
        upstream_writer = None

        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.upstream_host, self.upstream_port,
            )
            logger.info("Connected to upstream Language Server %s:%d",
                        self.upstream_host, self.upstream_port)

            await asyncio.gather(
                self._relay_client_to_server(client_reader, upstream_writer, client_writer),
                self._relay_server_to_client(upstream_reader, client_writer),
            )

        except ConnectionRefusedError:
            logger.warning(
                "Cannot connect to upstream Language Server at %s:%d. "
                "Running in standalone/monitor mode.",
                self.upstream_host, self.upstream_port,
            )
            await self._handle_standalone(client_reader, client_writer)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("LSP client handler error: %s", e)
        finally:
            client_writer.close()
            if upstream_writer:
                upstream_writer.close()

    # ── Relay: IDE → Language Server ───────────────────────────

    async def _relay_client_to_server(self, client_reader: asyncio.StreamReader,
                                      upstream_writer: asyncio.StreamWriter,
                                      client_writer: asyncio.StreamWriter):
        """Relay traffic from IDE to Language Server, analyzing requests."""
        frame_reader = StdioFrameReader()

        try:
            while self.running:
                data = await asyncio.wait_for(client_reader.read(65536), timeout=1.0)
                if not data:
                    break

                messages = frame_reader.feed(data)

                for raw_json in messages:
                    msg = self._parse_lsp_message(raw_json)
                    if not msg:
                        # Unable to parse -> forward raw
                        upstream_writer.write(MCPProtocol.frame_message(raw_json))
                        await upstream_writer.drain()
                        continue

                    with self._stats_lock:
                        self._stats["total_messages"] += 1

                    method = msg.get("method")
                    params = msg.get("params", {})
                    msg_id = msg.get("id")

                    # Security analysis
                    verdict = None
                    if method in INTERCEPTABLE_LSP_METHODS:
                        with self._stats_lock:
                            self._stats["total_interceptable"] += 1
                        verdict = self.analyzer.analyze(method, params)

                    # Block decision
                    should_block = self._should_block(verdict)

                    if should_block and msg_id is not None:
                        # Block: send error response to IDE
                        self._emit_blocked_log(method, verdict)
                        blocked_resp = MCPProtocol.make_error_response(
                            msg_id,
                            code=-32000,
                            message=f"[EDR Security] LSP command blocked: {'; '.join(verdict.reasons)}",
                            data={
                                "blocked_by": "AI_Runtime_Security_EDR",
                                "risk_score": verdict.risk_score,
                            },
                        )
                        resp_bytes = MCPProtocol.frame_message(
                            MCPProtocol.serialize(blocked_resp)
                        )
                        client_writer.write(resp_bytes)
                        await client_writer.drain()

                        # Emit event to Correlation Engine
                        self._emit_lsp_event(method, params, msg_id, verdict)
                        continue  # DO NOT forward upstream

                    # Allow: forward upstream
                    upstream_writer.write(MCPProtocol.frame_message(raw_json))
                    await upstream_writer.drain()

                    # Emit event if notable
                    if method in INTERCEPTABLE_LSP_METHODS or method in LOG_ONLY_LSP_METHODS:
                        self._emit_lsp_event(method, params, msg_id, verdict)

        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug("LSP client relay ended: %s", e)

    # ── Relay: Language Server → IDE ───────────────────────────

    async def _relay_server_to_client(self, upstream_reader: asyncio.StreamReader,
                                      client_writer: asyncio.StreamWriter):
        """Relay responses from Language Server to IDE (pass-through)."""
        try:
            while self.running:
                data = await asyncio.wait_for(upstream_reader.read(65536), timeout=1.0)
                if not data:
                    break
                client_writer.write(data)
                await client_writer.drain()

        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug("LSP upstream relay ended: %s", e)

    # ── Standalone Mode (không có upstream) ────────────────────

    async def _handle_standalone(self, client_reader: asyncio.StreamReader,
                                 client_writer: asyncio.StreamWriter):
        """Analyze and log messages when upstream connection is unavailable."""
        frame_reader = StdioFrameReader()

        try:
            while self.running:
                try:
                    data = await asyncio.wait_for(client_reader.read(65536), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                if not data:
                    break

                messages = frame_reader.feed(data)
                for raw_json in messages:
                    msg = self._parse_lsp_message(raw_json)
                    if not msg:
                        continue

                    method = msg.get("method")
                    params = msg.get("params", {})
                    msg_id = msg.get("id")

                    verdict = None
                    if method in INTERCEPTABLE_LSP_METHODS:
                        verdict = self.analyzer.analyze(method, params)

                    self._emit_lsp_event(method, params, msg_id, verdict)

                    # Send mock response if it's a request
                    if msg_id is not None:
                        should_block = self._should_block(verdict)
                        if should_block:
                            resp = MCPProtocol.make_error_response(
                                msg_id, -32000,
                                f"[EDR] Blocked: {'; '.join(verdict.reasons)}",
                            )
                        else:
                            resp = MCPProtocol.make_success_response(
                                msg_id,
                                {"status": "ok", "note": "[LSP Interceptor Standalone]"},
                            )
                        resp_bytes = (json.dumps(resp) + "\n").encode("utf-8")
                        client_writer.write(resp_bytes)
                        await client_writer.drain()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug("LSP standalone handler ended: %s", e)

    # ── Decision & Analysis Helpers ────────────────────────────

    def _should_block(self, verdict: Optional[LSPVerdict]) -> bool:
        """Determine whether to block message based on mode and verdict."""
        if not verdict:
            return False

        if self.mode == "MONITOR":
            return False
        elif self.mode == "INTERCEPT":
            return verdict.risk_score >= self.block_threshold

        return False

    @staticmethod
    def _parse_lsp_message(raw_json: str) -> Optional[Dict[str, Any]]:
        """Parse JSON-RPC message to dict."""
        try:
            data = json.loads(raw_json)
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, TypeError):
            pass
        return None

    # ── Event Emitters ─────────────────────────────────────────

    def _emit_lsp_event(self, method: str, params: Dict[str, Any],
                        msg_id: Any, verdict: Optional[LSPVerdict]):
        """Emit event to ai_event_queue for Correlation Engine."""
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Extract details from params
        command_name = ""
        command_args = ""
        if method == LSP_EXECUTE_COMMAND:
            command_name = params.get("command", "")
            arguments = params.get("arguments", [])
            command_args = json.dumps(arguments, ensure_ascii=False)[:300] if arguments else ""
        elif method == LSP_APPLY_EDIT:
            edit = params.get("edit", {})
            files = list(edit.get("changes", {}).keys())
            command_name = "applyEdit"
            command_args = json.dumps(files, ensure_ascii=False)[:300] if files else ""

        event = {
            "ai_event_id": f"LSP-{msg_id or int(time.time() * 1000)}",
            "event_type": "lsp_command",
            "agent": "IDE_Agent",
            "action": method or "unknown",
            "tool": command_name or method or "unknown",
            "tool_type": command_name,
            "target": command_args,
            "timestamp": now_utc,
            "session_id": "",
            "source": "lsp_interceptor",

            # LSP-specific metadata
            "lsp_method": method,
            "lsp_command": command_name,
            "lsp_arguments": command_args,
            "lsp_request_id": msg_id,
        }

        if verdict and verdict.risk_score > 0:
            event["lsp_verdict"] = {
                "action": verdict.action,
                "risk_score": verdict.risk_score,
                "risk_level": verdict.risk_level,
                "reasons": verdict.reasons,
                "matched_rules": verdict.matched_rules,
            }
            event["tool_analysis"] = {
                "has_anomaly": verdict.action in ("BLOCK", "ALERT"),
                "risk_score": verdict.risk_score,
                "risk_level": verdict.risk_level,
                "anomalies": [{"type": r, "detail": ""} for r in verdict.matched_rules],
                "analyzed_at": now_utc,
            }

        try:
            self.ai_event_queue.put_nowait(event)
        except queue.Full:
            logger.warning("ai_event_queue is full, dropping LSP event")

    def _emit_blocked_log(self, method: str, verdict: LSPVerdict):
        """Log warning when blocking an LSP message."""
        with self._stats_lock:
            self._stats["total_blocked"] += 1
        logger.warning(
            "[BLOCKED] LSP %s: score=%d, reasons=%s",
            method, verdict.risk_score, "; ".join(verdict.reasons),
        )
