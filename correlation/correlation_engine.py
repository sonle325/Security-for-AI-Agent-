import queue
import threading
import datetime
import time
import logging
import shlex
import os
from datetime import timezone, timedelta
import config_loader
from ai_telemetry.deduplicator import TelemetryDeduplicator

logger = logging.getLogger("EDR.Correlation")


class CorrelationEngine:
    def __init__(self, sysmon_queue: queue.Queue, ai_event_queue: queue.Queue, incident_queue: queue.Queue):
        self.sysmon_queue = sysmon_queue
        self.ai_event_queue = ai_event_queue
        self.incident_queue = incident_queue
        self.running = False
        self.thread = None

        self.sysmon_window = []
        self.ai_window = []
        self.incident_counter = 1

        self.session_events = {}
        self.buffer_lock = threading.Lock()
        self.deduplicator = TelemetryDeduplicator()

        corr_cfg = config_loader.get("correlation", default={})
        self.time_window = corr_cfg.get("time_window_seconds", 30)
        self.max_window = corr_cfg.get("max_window_size", 100)
        self.delta_t = corr_cfg.get("delta_t_threshold", 2.0)
        self.suspicious_cmd_keywords = corr_cfg.get("suspicious_cmd_keywords", [
            "curl", "wget", "invoke-webrequest", "iex", "payload",
            "attacker", "malware", "http://", "nc.exe", "certutil",
            "base64", "-enc", "downloadstring", "bypass"
        ])

        self.whitelist_parent_images = config_loader.get("whitelist_parent_images", default=[
            "antigravity.exe", "language_server_windows_x64.exe", "code.exe", "cursor.exe",
            "idea64.exe", "pycharm64.exe", "devenv.exe", "copilot.exe"
        ])

        self.critical_cmd_keywords = ["mimikatz", "nc.exe", "certutil", "-enc", "downloadstring"]

    def _is_parent_whitelisted(self, parent_image: str) -> bool:
        if not parent_image:
            return False
        import ntpath
        return ntpath.basename(parent_image).lower() in self.whitelist_parent_images

    def _is_keyword_in_string_literal(self, cmdline: str, keyword: str) -> bool:
        keyword_lower = keyword.lower()
        if keyword_lower not in cmdline.lower():
            return False

        try:
            tokens = shlex.split(cmdline, posix=False)
            cleaned_cmdline = cmdline
            for token in tokens:
                if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
                    cleaned_cmdline = cleaned_cmdline.replace(token, "")
            
            return keyword_lower not in cleaned_cmdline.lower()
        except ValueError:
            return False

    def _parse_utc_time(self, time_str: str) -> datetime.datetime:
        if not time_str or not isinstance(time_str, str):
            return datetime.datetime.min.replace(tzinfo=timezone.utc)
        try:
            normalized = time_str.strip().replace("Z", "+00:00")

            if "." in normalized:
                dot_pos = normalized.index(".")
                plus_pos = normalized.find("+", dot_pos)
                if plus_pos == -1:
                    plus_pos = len(normalized)
                frac = normalized[dot_pos+1:plus_pos]
                frac = frac[:6].ljust(6, "0")
                normalized = normalized[:dot_pos+1] + frac + normalized[plus_pos:]

            dt = datetime.datetime.fromisoformat(normalized)

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)

            return dt
        except Exception:
            return datetime.datetime.min.replace(tzinfo=timezone.utc)

    def _clean_window(self, window: list, current_time: datetime.datetime):
        cutoff_time = current_time - datetime.timedelta(seconds=self.time_window)
        cleaned = [e for e in window if self._parse_utc_time(e.get("TimestampUTC", e.get("timestamp", ""))) >= cutoff_time]
        return cleaned[-self.max_window:]

    def _process_queues(self):
        while self.running:

            new_ai_events = []
            while not self.ai_event_queue.empty():
                try:
                    event = self.ai_event_queue.get_nowait()
                    self.ai_event_queue.task_done()
                    
                    deduped_event = self.deduplicator.process(event)
                    if not deduped_event:
                        continue
                        
                    new_ai_events.append(deduped_event)
                    self._check_ai_event_anomalies(deduped_event)
                except queue.Empty:
                    break

            new_sysmon_events = []
            while not self.sysmon_queue.empty():
                try:
                    event = self.sysmon_queue.get_nowait()
                    if event.get("EventID") in [1, 3, 11, 13, 22]:
                        new_sysmon_events.append(event)
                    self.sysmon_queue.task_done()
                except queue.Empty:
                    break

            now = datetime.datetime.now(timezone.utc)
            
            with self.buffer_lock:
                for event in new_ai_events:
                    self.ai_window.append(event)
                    sid = event.get("session_id", "")
                    if sid:
                        self.session_events.setdefault(sid, []).append(event)
                
                for event in new_sysmon_events:
                    self.sysmon_window.append(event)

                self.ai_window = self._clean_window(self.ai_window, now)
                self.sysmon_window = self._clean_window(self.sysmon_window, now)
                
                self._correlate()
                
            time.sleep(0.5)

    def _check_ai_event_anomalies(self, event: dict):


        prompt_analysis = event.get("prompt_analysis", {})
        if prompt_analysis.get("is_injection") and prompt_analysis.get("risk_level") in ("CRITICAL", "HIGH"):
            incident_id = f"INC-{self.incident_counter:04d}"
            self.incident_counter += 1

            logger.warning("PROMPT INJECTION DETECTED — Tao Incident: %s", incident_id)
            logger.warning("   Risk Level: %s (Score: %s/100)", prompt_analysis['risk_level'], prompt_analysis['injection_score'])
            logger.warning("   Patterns: %s", ', '.join(prompt_analysis.get('matched_patterns', [])))

            incident = {
                "incident_id": incident_id,
                "incident_type": "PROMPT_INJECTION",
                "ai_event": event,
                "sysmon_event": {},
                "prompt_analysis": prompt_analysis,
                "severity": "CRITICAL" if prompt_analysis["injection_score"] >= 60 else "HIGH",
            }
            self.incident_queue.put(incident)
            event["_correlated"] = True


        tool_analysis = event.get("tool_analysis", {})
        if tool_analysis.get("has_anomaly") and tool_analysis.get("risk_level") in ("CRITICAL", "HIGH"):
            incident_id = f"INC-{self.incident_counter:04d}"
            self.incident_counter += 1

            logger.warning("AI TOOL ANOMALY DETECTED — Tao Incident: %s", incident_id)
            logger.warning("   Risk Level: %s (Score: %s/100)", tool_analysis['risk_level'], tool_analysis['risk_score'])

            incident = {
                "incident_id": incident_id,
                "incident_type": "TOOL_ANOMALY",
                "ai_event": event,
                "sysmon_event": {},
                "tool_analysis": tool_analysis,
                "severity": "CRITICAL" if tool_analysis["risk_score"] >= 60 else "HIGH",
            }
            self.incident_queue.put(incident)
            event["_correlated"] = True


        response_analysis = event.get("response_analysis", {})
        if response_analysis.get("has_sensitive_data") and response_analysis.get("risk_level") in ("CRITICAL", "HIGH"):
            incident_id = f"INC-{self.incident_counter:04d}"
            self.incident_counter += 1

            logger.warning("DATA DISCLOSURE DETECTED — Tao Incident: %s", incident_id)
            logger.warning("   Risk Level: %s (Score: %s/100)", response_analysis['risk_level'], response_analysis['disclosure_score'])

            incident = {
                "incident_id": incident_id,
                "incident_type": "DATA_DISCLOSURE",
                "ai_event": event,
                "sysmon_event": {},
                "response_analysis": response_analysis,
                "severity": "CRITICAL" if response_analysis["disclosure_score"] >= 60 else "HIGH",
            }
            self.incident_queue.put(incident)
            event["_correlated"] = True

    def _correlate(self):
        for ai_evt in self.ai_window:
            if ai_evt.get("_correlated"):
                continue

            ai_time = self._parse_utc_time(ai_evt.get("timestamp", ""))
            ai_tool = ai_evt.get("tool", "").lower()
            ai_session = ai_evt.get("session_id", "")
            
            mcp_args = ""
            if ai_evt.get("event_type") == "mcp_tool_call":
                params = ai_evt.get("mcp_params", {})
                args_dict = params.get("arguments", {})
                mcp_args = " ".join(str(v) for v in args_dict.values()).lower()
            elif ai_evt.get("event_type") == "mcp_resource_read":
                mcp_args = ai_evt.get("target", "").lower()

            for sys_evt in self.sysmon_window:
                if sys_evt.get("_correlated") or sys_evt.get("EventID") != 1:
                    continue

                sys_time = self._parse_utc_time(sys_evt.get("TimestampUTC", ""))
                sys_image = sys_evt.get("Image", "").lower()


                if sys_time == datetime.datetime.min.replace(tzinfo=timezone.utc) or \
                   ai_time == datetime.datetime.min.replace(tzinfo=timezone.utc):
                    continue

                time_diff = abs((sys_time - ai_time).total_seconds())

                is_match = False
                if time_diff <= self.delta_t:
                    sys_cmdline = sys_evt.get("CommandLine", "").lower()
                    if mcp_args and sys_cmdline:
                        mcp_words = {w for w in mcp_args.split() if len(w) > 3}
                        sys_words = set(sys_cmdline.split())
                        
                        if mcp_words.intersection(sys_words) or mcp_args in sys_cmdline:
                            is_match = True
                            
                    if not is_match and ai_tool in sys_image:
                        is_match = True

                if is_match:
                    incident_id = f"INC-{self.incident_counter:04d}"
                    self.incident_counter += 1

                    logger.info("Correlation found! Created Incident: %s", incident_id)
                    logger.info("   Time diff: %.1fms (threshold <= %.0fms)", time_diff*1000, self.delta_t*1000)

                    incident = {
                        "incident_id": incident_id,
                        "incident_type": "CORRELATED",
                        "ai_event": ai_evt,
                        "sysmon_event": sys_evt,
                        "session_id": ai_session,
                    }

                    if "prompt_analysis" in ai_evt:
                        incident["prompt_analysis"] = ai_evt["prompt_analysis"]
                    if "tool_analysis" in ai_evt:
                        incident["tool_analysis"] = ai_evt["tool_analysis"]

                    self.incident_queue.put(incident)
                    ai_evt["_correlated"] = True
                    sys_evt["_correlated"] = True


        for sys_evt in self.sysmon_window:
            if sys_evt.get("_correlated") or sys_evt.get("EventID") != 1:
                continue

            sys_image = sys_evt.get("Image", "").lower()
            cmdline = sys_evt.get("CommandLine", "").lower()
            parent_image = sys_evt.get("ParentImage", "")

            if ("powershell" in sys_image or "cmd.exe" in sys_image):
                if self._is_parent_whitelisted(parent_image):
                    continue

                has_suspicious_keyword = False
                for kw in self.suspicious_cmd_keywords:
                    if kw in cmdline:

                        if self._is_keyword_in_string_literal(sys_evt.get("CommandLine", ""), kw):
                            continue
                        has_suspicious_keyword = True
                        break

                if not has_suspicious_keyword:
                    continue

                incident_id = f"INC-{self.incident_counter:04d}"
                self.incident_counter += 1

                logger.warning("PHÁT HIỆN TIẾN TRÌNH CHẠY NGẦM ĐÁNG NGỜ!")
                logger.warning("   Sinh ra Incident: %s", incident_id)
                logger.warning("   CommandLine: %s", cmdline[:120])

                mock_ai_evt = {"agent": "Background Script/AI", "action": "terminal", "timestamp": sys_evt.get("TimestampUTC", "")}

                incident = {
                    "incident_id": incident_id,
                    "incident_type": "ORPHAN_SUSPICIOUS",
                    "ai_event": mock_ai_evt,
                    "sysmon_event": sys_evt
                }
                self.incident_queue.put(incident)
                sys_evt["_correlated"] = True

    def get_session_chain(self, session_id: str) -> list:
        with self.buffer_lock:
            return list(self.session_events.get(session_id, []))

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._process_queues, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
