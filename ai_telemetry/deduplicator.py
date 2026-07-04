"""Telemetry Deduplicator — Ngăn chặn double-count tín hiệu."""

import time
import hashlib
import logging
from typing import Dict, Any, Optional

import config_loader

logger = logging.getLogger("EDR.Telemetry.Dedup")


class TelemetryDeduplicator:
    def __init__(self):
        cfg = config_loader.get("telemetry", default={}).get("deduplication", {})
        self.enabled = cfg.get("enabled", True)
        self.window_ms = cfg.get("window_ms", 500)
        
        priority_list = cfg.get("priority", ["mcp_gateway", "lsp_sniffer", "ipc_sdk"])
        
        self.priorities = {src: len(priority_list) - i for i, src in enumerate(priority_list)}
        
        self.seen_events: Dict[str, Dict[str, Any]] = {}

    def process(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return event
            
        now = time.time() * 1000
        
        self._cleanup(now)
        

        event_type = event.get("event_type", "")
        if event_type not in ("tool_invocation", "agent_action", "mcp_tool_call"):
            return event
            
        fingerprint = self._fingerprint(event)
        source = event.get("source", "ipc_sdk")
        
        if fingerprint in self.seen_events:
            existing = self.seen_events[fingerprint]
            age = now - existing["timestamp"]
            
            if age < self.window_ms:
                # Trùng fingerprint trong window -> so sánh độ ưu tiên
                current_prio = self.priorities.get(source, 0)
                existing_prio = self.priorities.get(existing["source"], 0)
                
                if current_prio > existing_prio:
                    logger.debug("[Dedup] Replaced lower priority event. %s -> %s (Tool: %s)", existing['source'], source, event.get('tool'))
                    self.seen_events[fingerprint] = {
                        "timestamp": now,
                        "source": source,
                        "event": event
                    }
                    return event
                else:
                    logger.debug("[Dedup] Dropped duplicate lower/equal priority event from %s (Tool: %s)", source, event.get('tool'))
                    return None
                    

        self.seen_events[fingerprint] = {
            "timestamp": now,
            "source": source,
            "event": event
        }
        return event

    def _fingerprint(self, event: Dict[str, Any]) -> str:
        tool = event.get("tool", "")
        session_id = event.get("session_id", "")
        target = event.get("target", "")
        raw_cmd = event.get("raw_command", "")
        args = str(event.get("mcp_params", event.get("parameters", "")))
        
        norm_tool = tool.lower().split(".")[-1]
        
        raw_str = f"{norm_tool}:{session_id}:{target}:{raw_cmd}:{args}"
        return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

    def _cleanup(self, now: float):
        expired = [fp for fp, data in self.seen_events.items() if now - data["timestamp"] > self.window_ms]
        for fp in expired:
            del self.seen_events[fp]
