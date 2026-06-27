import json
import os
import datetime
import logging
from datetime import timezone
from typing import Dict, Any
import config_loader

logger = logging.getLogger("EDR.Summary")


class IncidentSummarizer:
    """Tổng hợp kết quả phân tích thành báo cáo sự cố."""

    def __init__(self, reports_dir: str = None):
        rpt_cfg = config_loader.get("reports", default={})
        self.reports_dir = reports_dir or rpt_cfg.get("directory", "reports")
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        incident_id  = incident.get("incident_id", "UNKNOWN")
        severity     = incident.get("severity", "LOW")
        matched_rules = incident.get("matched_rules", [])
        ai_event     = incident.get("ai_event", {})
        sysmon_event = incident.get("sysmon_event", {})
        threat_label = incident.get("ai_threat_label", "Unclassified")

        summary = {
            "report_id":    f"RPT-{incident_id}",
            "generated_at": datetime.datetime.now(timezone.utc).isoformat(),
            "incident_id":  incident_id,
            "severity":     severity,

            "intent_space": {
                "ai_agent":  ai_event.get("agent", "Unknown"),
                "action":    ai_event.get("action", ""),
                "tool":      ai_event.get("tool", ""),
                "timestamp": ai_event.get("timestamp", ""),
                "session_id": ai_event.get("session_id", ""),
            },

            "action_space": {
                "process":      sysmon_event.get("Image", ""),
                "pid":          sysmon_event.get("ProcessId", ""),
                "parent":       sysmon_event.get("ParentImage", ""),
                "parent_pid":   sysmon_event.get("ParentProcessId", ""),
                "cmdline":      sysmon_event.get("CommandLine", ""),
                "event_time":   sysmon_event.get("TimestampUTC", ""),
                "event_id":     sysmon_event.get("EventID", ""),
            },

            "analysis": {
                "matched_rules": matched_rules,
                "nlp_threat_label": threat_label,
                "attack_type": self._classify_attack(matched_rules, threat_label),
                "ai_classifications": incident.get("ai_classifications", []),
            },

            "monitor_analysis": {
                "prompt_injection": incident.get("prompt_analysis", {}),
                "tool_anomaly": incident.get("tool_analysis", {}),
                "data_disclosure": incident.get("response_analysis", {}),
            },

            "response": self._build_response(incident),
        }

        self._save(summary)
        return summary

    @staticmethod
    def _build_response(incident: Dict[str, Any]) -> Dict[str, str]:
        """Xây dựng phần response dựa trên kết quả containment thực tế,
        không suy luận từ severity.
        """
        result = incident.get("containment_result", "")
        severity = incident.get("severity", "LOW")

        # Mapping kết quả thực tế → action_taken & status trung thực
        result_map = {
            "TERMINATED":       ("KILL_PROCESS",  "CONTAINED"),
            "ALREADY_EXITED":   ("KILL_PROCESS",  "CONTAINED"),
            "ACCESS_DENIED":    ("KILL_ATTEMPTED", "FAILED_ACCESS_DENIED"),
            "WHITELISTED":      ("BLOCKED_BY_WHITELIST", "NOT_CONTAINED"),
            "ALERT_ONLY":       ("ALERT",         "OBSERVED"),
            "NO_PID_AVAILABLE": ("NO_ACTION",     "DETECTION_ONLY"),
            "INVALID_PID":      ("NO_ACTION",     "DETECTION_ONLY"),
            "NOT_CRITICAL":     ("MONITOR",       "OBSERVED"),
            "ERROR":            ("KILL_ATTEMPTED", "FAILED_ERROR"),
        }

        if result in result_map:
            action, status = result_map[result]
        elif severity == "CRITICAL":
            # Fallback: nếu chưa qua ContainmentEngine (race condition / queue chưa xử lý)
            action, status = "PENDING", "PENDING_CONTAINMENT"
        else:
            action, status = "MONITOR", "OBSERVED"

        return {
            "action_taken": action,
            "status": status,
            "containment_detail": result or "N/A",
        }

    def _save(self, summary: Dict[str, Any]):
        filename = f"{summary['report_id']}.json"
        filepath = os.path.join(self.reports_dir, filename)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.error("Lỗi ghi report %s: %s", filepath, e)

    @staticmethod
    def _classify_attack(rules: list, nlp_label: str) -> str:
        rules_str = " ".join(rules).lower()
        label_lower = nlp_label.lower()

        if "prompt injection" in label_lower or "promptmonitor" in rules_str:
            return "Prompt Injection"
        if "invoke-webrequest" in rules_str or "curl" in rules_str or "wget" in rules_str:
            return "Executable Download / C2 Callback"
        if "exfil" in rules_str or "data exfiltration" in label_lower:
            return "Data Exfiltration"
        if "credential" in label_lower or "credential" in rules_str:
            return "Credential Access"
        if "remote code execution" in label_lower:
            return "Remote Code Execution (RCE)"
        if "privilege" in label_lower:
            return "Privilege Escalation"
        if "lateral" in label_lower:
            return "Lateral Movement"
        if "payload" in rules_str:
            return "Payload Delivery"
        if "iex" in rules_str:
            return "In-Memory Execution (IEX)"
        return "Suspicious Activity"
