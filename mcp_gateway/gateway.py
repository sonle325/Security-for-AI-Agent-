"""MCP Security Gateway — Transparent proxy between AI Agent and MCP Server."""

import asyncio
import json
import queue
import logging
import threading
import datetime
import time
from typing import Dict, Any, Optional, Callable

from mcp_gateway.protocol import MCPProtocol, MCPMessage, StdioFrameReader
from mcp_gateway.interceptor import (
    ToolCallInterceptor,
    ResourceInterceptor,
    ResponseInterceptor,
    InterceptVerdict,
)
import config_loader

logger = logging.getLogger("EDR.MCP.Gateway")


class MCPSecurityGateway:


    def __init__(self, ai_event_queue: queue.Queue):
        self.ai_event_queue = ai_event_queue
        self.running = False
        self._thread = None
        self._loop = None

        # Config
        gateway_cfg = config_loader.get("mcp_gateway", default={})
        self.enabled = gateway_cfg.get("enabled", True)
        self.mode = gateway_cfg.get("mode", "AUDIT").upper()
        self.block_threshold = gateway_cfg.get("block_threshold", 60)
        self.hard_block_threshold = gateway_cfg.get("hard_block_threshold", 90)
        self.block_action = gateway_cfg.get("block_action", "deny").lower()
        self.tool_overrides = gateway_cfg.get("tool_overrides", {})
        
        self.listen_port = gateway_cfg.get("listen_port", 8765)
        self.upstream_host = gateway_cfg.get("upstream_host", "127.0.0.1")
        self.upstream_port = gateway_cfg.get("upstream_port", 8766)


        self._substituted_requests = set()


        self.tool_interceptor = ToolCallInterceptor()
        self.resource_interceptor = ResourceInterceptor()
        self.response_interceptor = ResponseInterceptor()


        self._stats = {
            "total_requests": 0,
            "total_blocked": 0,
            "total_allowed": 0,
            "total_alerts": 0,
        }
        self._stats_lock = threading.Lock()



    def start(self):
        if not self.enabled:
            logger.info("MCP Security Gateway is DISABLED in config.")
            return
        if self.running:
            return

        self.running = True
        self._thread = threading.Thread(target=self._run_event_loop, daemon=True)
        self._thread.start()
        logger.info("MCP Security Gateway started (mode=%s, listen=%d, upstream=%s:%d)",
                     self.mode, self.listen_port, self.upstream_host, self.upstream_port)

    def stop(self):
        self.running = False
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("MCP Security Gateway stopped. Stats: %s", self._stats)

    def get_stats(self) -> Dict[str, int]:
        with self._stats_lock:
            return dict(self._stats)



    def _run_event_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._start_tcp_proxy())
        except Exception as e:
            if self.running:
                logger.error("Gateway event loop error: %s", e)
        finally:
            self._loop.close()

    async def _start_tcp_proxy(self):
        server = await asyncio.start_server(
            self._handle_client,
            "127.0.0.1",
            self.listen_port
        )
        logger.info("TCP Proxy listening on 127.0.0.1:%d", self.listen_port)

        async with server:
            while self.running:
                await asyncio.sleep(0.5)



    async def _handle_client(self, client_reader: asyncio.StreamReader,
                             client_writer: asyncio.StreamWriter):
        client_addr = client_writer.get_extra_info("peername")
        logger.info("New client connected: %s", client_addr)

        upstream_reader = None
        upstream_writer = None

        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.upstream_host, self.upstream_port
            )
            logger.info("Connected to upstream MCP Server %s:%d",
                        self.upstream_host, self.upstream_port)

            await asyncio.gather(
                self._relay_client_to_upstream(client_reader, upstream_writer),
                self._relay_upstream_to_client(upstream_reader, client_writer),
            )

        except ConnectionRefusedError:
            logger.warning("Cannot connect to upstream MCP Server at %s:%d",
                           self.upstream_host, self.upstream_port)
            await self._handle_standalone(client_reader, client_writer)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Client handler error: %s", e)
        finally:
            client_writer.close()
            if upstream_writer:
                upstream_writer.close()

    async def _relay_client_to_upstream(self, client_reader: asyncio.StreamReader,
                                       upstream_writer: asyncio.StreamWriter,
                                       client_writer: asyncio.StreamWriter):
        """Intercept and analyze requests from Agent to Server."""
        frame_reader = StdioFrameReader()

        try:
            while self.running:
                data = await asyncio.wait_for(client_reader.read(65536), timeout=1.0)
                if not data:
                    break

                messages = frame_reader.feed(data)

                for raw_json in messages:
                    msg = MCPProtocol.parse_message(raw_json)
                    if not msg:
                        upstream_writer.write(MCPProtocol.frame_message(raw_json))
                        await upstream_writer.drain()
                        continue

                    verdict = self._analyze_request(msg)

                    should_block, action = self._should_block(msg, verdict)

                    if should_block:
                        self._emit_blocked_event(msg, verdict, action)
                        
                        if action == "deny":
                            # Block logic
                            blocked_resp = MCPProtocol.make_blocked_response(
                                msg.id,
                                reason="; ".join(verdict.reasons),
                                risk_score=verdict.risk_score,
                            )
                            resp_json = MCPProtocol.serialize(blocked_resp)
                            client_writer.write((resp_json + "\n").encode("utf-8"))
                            await client_writer.drain()
                            self._emit_mcp_event(msg, verdict)
                            continue
                            
                        elif action == "delay":
                            # Bidirectional relay
                            logger.info("Delaying tool call %s for 30s...", msg.get_tool_name())
                            await asyncio.sleep(30)
                            
                        elif action == "substitute":
                            logger.info("Substituting tool call %s response...", msg.get_tool_name())
                            # Send error response to Agent
                            if should_block and msg.id is not None:
                                self._substituted_requests.add(msg.id)

                    else:
                        if verdict and verdict.action in ("ALERT", "BLOCK"):
                            self._emit_alert_event(msg, verdict)

                    upstream_writer.write(MCPProtocol.frame_message(raw_json))
                    await upstream_writer.drain()

                    self._emit_mcp_event(msg, verdict)

        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug("Client relay ended: %s", e)

    async def _relay_upstream_to_client(self, upstream_reader: asyncio.StreamReader,
                                       client_writer: asyncio.StreamWriter):
        """Intercept and analyze responses from Server to Agent."""
        frame_reader = StdioFrameReader()

        try:
            while self.running:
                data = await asyncio.wait_for(upstream_reader.read(65536), timeout=1.0)
                if not data:
                    break

                messages = frame_reader.feed(data)
                for raw_json in messages:
                    msg = MCPProtocol.parse_message(raw_json)

                    if msg and msg.is_response:
                        if msg.id in self._substituted_requests:
                            self._substituted_requests.remove(msg.id)
                            msg.raw["result"] = {
                                "content": [{"type": "text", "text": "[REDACTED by EDR security policy]"}]
                            }
                            if "error" in msg.raw:
                                del msg.raw["error"]
                            raw_json = MCPProtocol.serialize(msg.raw)

                        elif msg.result:
                            resp_verdict = self.response_interceptor.analyze_response(msg.raw)
                            if resp_verdict.risk_score > 0:
                                self._emit_response_leak_event(msg, resp_verdict)

                    client_writer.write(MCPProtocol.frame_message(raw_json))
                    await client_writer.drain()

        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug("Upstream relay ended: %s", e)

    async def _handle_standalone(self, client_reader: asyncio.StreamReader,
                                 client_writer: asyncio.StreamWriter):
        frame_reader = StdioFrameReader()
        buffer = b""

        try:
            while self.running:
                try:
                    data = await asyncio.wait_for(client_reader.read(65536), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                if not data:
                    break

                buffer += data
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    line_str = line.decode("utf-8", errors="replace").strip()
                    if not line_str:
                        # DO NOT forward to upstream
                        continue

                    # Allow: forward upstream
                    msg = MCPProtocol.parse_message(line_str)
                    if not msg:
                        # Unable to parse -> forward raw
                        continue

                    verdict = self._analyze_request(msg)
                    self._emit_mcp_event(msg, verdict)

                    if msg.is_request:
                        should_block, action = self._should_block(msg, verdict)
                        if should_block:
                            if action == "deny":
                                resp = MCPProtocol.make_blocked_response(
                                    msg.id,
                                    reason="; ".join(verdict.reasons),
                                    risk_score=verdict.risk_score,
                                )
                            elif action == "substitute":
                                resp = MCPProtocol.make_success_response(
                                    msg.id,
                                    {"content": [{"type": "text", "text": "[REDACTED by EDR security policy]"}]}
                                )
                            else: # delay
                                await asyncio.sleep(30)
                                resp = MCPProtocol.make_success_response(msg.id, {"content": [{"type": "text", "text": "[Standalone Allowed]"}]})
                            self._emit_blocked_event(msg, verdict, action)
                        else:
                            resp = MCPProtocol.make_success_response(
                                msg.id,
                                {"content": [{"type": "text",
                                              "text": f"[Gateway Standalone] Tool '{msg.get_tool_name()}' allowed."}]}
                            )
                        resp_bytes = (json.dumps(resp) + "\n").encode("utf-8")
                        client_writer.write(resp_bytes)
                        await client_writer.drain()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug("Standalone handler ended: %s", e)



    def _analyze_request(self, msg: MCPMessage) -> Optional[InterceptVerdict]:
        if not msg.is_interceptable():
            return None

        with self._stats_lock:
            self._stats["total_requests"] += 1

        if msg.is_tool_call():
            verdict = self.tool_interceptor.analyze(msg)
        elif msg.is_resource_read():
            verdict = self.resource_interceptor.analyze(msg)
        else:
            return None

        with self._stats_lock:

            if verdict.action == "ALERT":
                self._stats["total_alerts"] += 1
            elif verdict.action == "ALLOW":
                self._stats["total_allowed"] += 1

        return verdict

    def _should_block(self, msg: MCPMessage, verdict: Optional[InterceptVerdict]) -> tuple[bool, str]:
        if not verdict:
            return False, ""
            
        tool_name = msg.get_tool_name() or "unknown"
        

        effective_mode = self.mode
        effective_block_thresh = self.block_threshold
        effective_hard_thresh = self.hard_block_threshold
        effective_action = self.block_action
        
        if tool_name in self.tool_overrides:
            override = self.tool_overrides[tool_name]
            effective_mode = override.get("mode", effective_mode).upper()
            effective_block_thresh = override.get("block_threshold", effective_block_thresh)
            effective_hard_thresh = override.get("hard_block_threshold", effective_hard_thresh)
            effective_action = override.get("block_action", effective_action).lower()
            
        score = verdict.risk_score
        should_block = False
        
        if effective_mode == "MONITOR":
            should_block = False
        elif effective_mode == "AUDIT":
            should_block = score >= effective_hard_thresh
        elif effective_mode == "INTERCEPT":
            should_block = score >= effective_block_thresh
            

        if score == 100 and effective_mode != "MONITOR":
            should_block = True
            
        if should_block:
            with self._stats_lock:
                self._stats["total_blocked"] += 1
                
        return should_block, effective_action



    def _emit_mcp_event(self, msg: MCPMessage, verdict: Optional[InterceptVerdict]):
        if not msg.is_request:
            return

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        event = {
            "ai_event_id": f"MCP-{msg.id or int(time.time() * 1000)}",
            "event_type": "mcp_tool_call" if msg.is_tool_call() else "mcp_resource_read",
            "agent": "MCP_Agent",
            "action": msg.method or "unknown",
            "tool": msg.get_tool_name() or msg.method or "unknown",
            "tool_type": msg.get_tool_name(),
            "target": json.dumps(msg.get_tool_arguments() or msg.get_resource_uri(), ensure_ascii=False),
            "timestamp": now_utc,
            "session_id": "",
            "source": "mcp_gateway",


            "mcp_method": msg.method,
            "mcp_params": msg.params,
            "mcp_request_id": msg.id,
        }

        if verdict:
            event["mcp_verdict"] = {
                "action": verdict.action,
                "risk_score": verdict.risk_score,
                "risk_level": verdict.risk_level,
                "reasons": verdict.reasons,
                "matched_rules": verdict.matched_rules,
            }


            if verdict.risk_score > 0:
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
            logger.warning("ai_event_queue is full, dropping MCP event")

    def _emit_blocked_event(self, msg: MCPMessage, verdict: InterceptVerdict, action: str = "deny"):
        logger.warning(
            "[BLOCKED] MCP %s: tool=%s, score=%d, action=%s, reasons=%s",
            msg.method, msg.get_tool_name(), verdict.risk_score, action,
            "; ".join(verdict.reasons)
        )

    def _emit_alert_event(self, msg: MCPMessage, verdict: InterceptVerdict):
        logger.warning(
            "[ALERT] MCP %s: tool=%s, score=%d, reasons=%s",
            msg.method, msg.get_tool_name(), verdict.risk_score,
            "; ".join(verdict.reasons)
        )

    def _emit_response_leak_event(self, msg: MCPMessage, verdict: InterceptVerdict):
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        event = {
            "ai_event_id": f"MCP-RESP-{msg.id or int(time.time() * 1000)}",
            "event_type": "response",
            "agent": "MCP_Agent",
            "action": "mcp_response",
            "tool": "mcp_response",
            "timestamp": now_utc,
            "source": "mcp_gateway",
            "response_analysis": {
                "has_sensitive_data": True,
                "disclosure_score": verdict.risk_score,
                "risk_level": verdict.risk_level,
                "detected_secrets": [{"type": r, "description": r, "severity": verdict.risk_level}
                                     for r in verdict.matched_rules],
                "analyzed_at": now_utc,
            },
        }
        try:
            self.ai_event_queue.put_nowait(event)
        except queue.Full:
            pass
