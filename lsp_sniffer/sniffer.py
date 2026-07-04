"""LSP Sniffer — Passive monitor cho IDE ↔ AI Extension communication."""

import os
import time
import queue
import logging
import threading
import datetime
import json
import re
from typing import Dict, Any, List, Set, Optional

import psutil
import config_loader

logger = logging.getLogger("EDR.LSP.Sniffer")


class LSPSniffer:
    """Monitor AI-related processes và IDE extension communications."""


    DEFAULT_AI_PROCESSES = [
        "code.exe",           # VS Code
        "cursor.exe",         # Cursor
        "cursor-helper.exe",  # Cursor helper
        "copilot",            # GitHub Copilot
        "aider",              # Aider CLI
        "claude",             # Claude Code
        "windsurf.exe",       # Windsurf
        "continue",           # Continue extension
    ]


    AI_CMDLINE_PATTERNS = [
        r"(?i)copilot",
        r"(?i)language.server",
        r"(?i)extension.?host",
        r"(?i)claude",
        r"(?i)cursor",
        r"(?i)ai.?agent",
        r"(?i)mcp",
        r"(?i)anthropic",
        r"(?i)openai",
    ]


    AI_PIPE_PATTERNS = [
        r"(?i)copilot",
        r"(?i)cursor",
        r"(?i)claude",
        r"(?i)ai[_-]",
        r"(?i)mcp",
        r"(?i)lsp",
    ]


    CRITICAL_PATTERNS = ["mimikatz", "nc.exe", "ncat", "netcat", "meterpreter", "cobalt"]
    DANGEROUS_CMD_ARGS = [
        "invoke-webrequest", "iex", "invoke-expression",
        "-enc ", "-encodedcommand", "downloadstring",
        "attacker", "payload", "malware", "c2.",
        "certutil", "bitsadmin",
    ]
    NETWORK_TOOLS = ["curl.exe", "wget.exe", "ssh.exe", "scp.exe", "ftp.exe", "telnet.exe"]
    DEV_TOOLS = ["node.exe", "python.exe", "npm.cmd", "git.exe", "pip.exe", "cargo.exe", "go.exe"]

    def __init__(self, ai_event_queue: queue.Queue):
        self.ai_event_queue = ai_event_queue
        self.running = False
        self._thread = None

        # Config
        lsp_cfg = config_loader.get("lsp_sniffer", default={})
        self.enabled = lsp_cfg.get("enabled", True)
        self.scan_interval = lsp_cfg.get("scan_interval_seconds", 5)

        target_procs = lsp_cfg.get("target_processes", [])
        self.target_processes = set(
            p.lower() for p in (target_procs or self.DEFAULT_AI_PROCESSES)
        )

        # Track known AI processes (avoid duplicate reporting)
        self._known_ai_pids: Set[int] = set()
        self._known_child_pids: Set[int] = set()
        self._ai_process_info: Dict[int, Dict[str, Any]] = {}

        # Compile patterns
        self._cmdline_patterns = [re.compile(p) for p in self.AI_CMDLINE_PATTERNS]
        self._pipe_patterns = [re.compile(p) for p in self.AI_PIPE_PATTERNS]



    def start(self):
        if not self.enabled:
            logger.info("LSP Sniffer is DISABLED in config.")
            return
        if self.running:
            return

        self.running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("LSP Sniffer started (scan_interval=%ds, targets=%s)",
                     self.scan_interval, list(self.target_processes))

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("LSP Sniffer stopped. Tracked %d AI processes.",
                     len(self._known_ai_pids))



    def _monitor_loop(self):
        while self.running:
            try:
                self._scan_ai_processes()
                self._monitor_ai_children()
                self._cleanup_dead_processes()
            except Exception as e:
                logger.debug("Monitor loop error: %s", e)

            time.sleep(self.scan_interval)



    def _scan_ai_processes(self):
        for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
            try:
                pid = proc.info["pid"]
                if pid in self._known_ai_pids:
                    continue

                name = (proc.info["name"] or "").lower()
                cmdline_list = proc.info.get("cmdline") or []
                cmdline = " ".join(cmdline_list) if cmdline_list else ""

                is_ai = False
                ai_type = "unknown"


                if name in self.target_processes:
                    is_ai = True
                    ai_type = name

                if not is_ai and cmdline:
                    for pattern in self._cmdline_patterns:
                        if pattern.search(cmdline):
                            is_ai = True
                            ai_type = f"cmdline:{pattern.pattern}"
                            break

                if is_ai:
                    self._known_ai_pids.add(pid)
                    self._ai_process_info[pid] = {
                        "pid": pid,
                        "name": name,
                        "ai_type": ai_type,
                        "cmdline": cmdline[:200],
                        "create_time": proc.info.get("create_time", 0),
                        "discovered_at": time.time(),
                    }

                    logger.info("Discovered AI process: PID=%d, name=%s, type=%s",
                                pid, name, ai_type)


                    self._emit_ai_process_event(pid, "AI_PROCESS_DISCOVERED", {
                        "process_name": name,
                        "ai_type": ai_type,
                        "cmdline": cmdline[:200],
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def _monitor_ai_children(self):
        for ai_pid, ai_info in list(self._ai_process_info.items()):
            try:
                parent = psutil.Process(ai_pid)
                children = parent.children(recursive=True)

                for child in children:
                    try:
                        child_pid = child.pid
                        if child_pid in self._known_child_pids:
                            continue

                        self._known_child_pids.add(child_pid)

                        child_name = child.name().lower()
                        child_cmdline_list = child.cmdline()
                        child_cmdline = " ".join(child_cmdline_list) if child_cmdline_list else ""


                        event_detail = {
                            "parent_ai_pid": ai_pid,
                            "parent_ai_name": ai_info.get("name", ""),
                            "parent_ai_type": ai_info.get("ai_type", ""),
                            "child_pid": child_pid,
                            "child_name": child_name,
                            "child_cmdline": child_cmdline[:300],
                        }


                        suspicion = self._classify_child_process(child_name, child_cmdline)
                        event_detail["suspicion_level"] = suspicion

                        if suspicion in ("HIGH", "CRITICAL"):
                            logger.warning(
                                "AI Agent (PID=%d, %s) spawned suspicious child: "
                                "PID=%d, name=%s, cmd=%s",
                                ai_pid, ai_info.get("name"), child_pid,
                                child_name, child_cmdline[:100]
                            )

                        self._emit_ai_process_event(
                            child_pid,
                            "AI_CHILD_PROCESS_SPAWNED",
                            event_detail,
                        )

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

            except (psutil.NoSuchProcess, psutil.AccessDenied):

                continue

    def _classify_child_process(self, name: str, cmdline: str) -> str:
        name_lower = name.lower()
        cmdline_lower = cmdline.lower()

        if any(p in name_lower or p in cmdline_lower for p in self.CRITICAL_PATTERNS):
            return "CRITICAL"

        if name_lower in ("powershell.exe", "pwsh.exe", "cmd.exe", "bash", "sh"):
            if any(d in cmdline_lower for d in self.DANGEROUS_CMD_ARGS):
                return "HIGH"
            return "MEDIUM"

        if name_lower in self.NETWORK_TOOLS:
            return "MEDIUM"

        if name_lower in self.DEV_TOOLS:
            return "LOW"

        return "NONE"



    def _scan_named_pipes(self) -> List[str]:
        ai_pipes = []
        try:
            pipe_dir = r"\\.\pipe"
            if not os.path.exists(pipe_dir):
                return ai_pipes

            for pipe_name in os.listdir(pipe_dir):
                for pattern in self._pipe_patterns:
                    if pattern.search(pipe_name):
                        ai_pipes.append(pipe_name)
                        break

        except (PermissionError, OSError):
            pass

        return ai_pipes



    def _cleanup_dead_processes(self):
        dead_pids = set()
        for pid in self._known_ai_pids:
            if not psutil.pid_exists(pid):
                dead_pids.add(pid)

        for pid in dead_pids:
            self._known_ai_pids.discard(pid)
            self._ai_process_info.pop(pid, None)

        dead_children = set()
        for pid in self._known_child_pids:
            if not psutil.pid_exists(pid):
                dead_children.add(pid)

        self._known_child_pids -= dead_children



    def _emit_ai_process_event(self, pid: int, event_type: str,
                               detail: Dict[str, Any]):
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        event = {
            "ai_event_id": f"LSP-{pid}-{int(time.time() * 1000)}",
            "event_type": "lsp_message",
            "agent": detail.get("parent_ai_name", detail.get("process_name", "AI_Agent")),
            "action": event_type,
            "tool": detail.get("child_name", detail.get("process_name", "")),
            "timestamp": now_utc,
            "session_id": "",
            "source": "lsp_sniffer",

    
            "lsp_event_type": event_type,
            "lsp_detail": detail,
            "lsp_pid": pid,
        }


        suspicion = detail.get("suspicion_level", "NONE")
        if suspicion in ("HIGH", "CRITICAL"):
            risk_score = 60 if suspicion == "CRITICAL" else 40
            event["tool_analysis"] = {
                "has_anomaly": True,
                "risk_score": risk_score,
                "risk_level": suspicion,
                "anomalies": [{
                    "type": f"AI_SPAWNED_{suspicion}_PROCESS",
                    "detail": f"AI Agent spawned: {detail.get('child_name', '')} "
                              f"cmd={detail.get('child_cmdline', '')[:100]}",
                }],
                "analyzed_at": now_utc,
            }

        try:
            self.ai_event_queue.put_nowait(event)
        except queue.Full:
            logger.warning("ai_event_queue is full, dropping LSP event")
