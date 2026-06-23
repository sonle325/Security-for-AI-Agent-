"""
Incident Summary Generator
============================
Tong hop ket qua phan tich tu cac module xuoi dong
(NLP Classifier + Risk Scoring + Correlation) thanh mot ban bao cao
su co ngan gon, co cau truc, phuc vu viec dieu tra SOC.

Dau ra cua module nay duoc luu vao reports/ va dung lam
tai lieu chung minh cho cac Incident da xu ly.
"""

import json
import os
import datetime
from typing import Dict, Any


class IncidentSummarizer:
    """
    Tao bao cao tom tat su co (Incident Summary Report).
    Ket hop thong tin tu:
        - Correlation Engine (Intent-Action chain)
        - Detection Engine (Risk Score + matched rules)
        - AI Security Analyzer (NLP threat label + confidence)
        - Response Engine (containment action taken)
    """

    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tao ban tom tat su co tu du lieu da xu ly.

        Args:
            incident: Dict chua day du thong tin tu cac engine xuoi dong.

        Returns:
            Dict cau truc tom tat su co.
        """
        incident_id  = incident.get("incident_id", "UNKNOWN")
        severity     = incident.get("severity", "LOW")
        matched_rules = incident.get("matched_rules", [])
        ai_event     = incident.get("ai_event", {})
        sysmon_event = incident.get("sysmon_event", {})
        threat_label = incident.get("ai_threat_label", "Unclassified")

        summary = {
            "report_id":    f"RPT-{incident_id}",
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "incident_id":  incident_id,
            "severity":     severity,

            # Phan 1: Nguon goc tan cong (Intent Space)
            "intent_space": {
                "ai_agent":  ai_event.get("agent", "Unknown"),
                "action":    ai_event.get("action", ""),
                "tool":      ai_event.get("tool", ""),
                "timestamp": ai_event.get("timestamp", ""),
            },

            # Phan 2: Hanh dong thuc te tren OS (Action Space)
            "action_space": {
                "process":      sysmon_event.get("Image", ""),
                "pid":          sysmon_event.get("ProcessId", ""),
                "parent":       sysmon_event.get("ParentImage", ""),
                "cmdline":      sysmon_event.get("CommandLine", ""),
                "event_time":   sysmon_event.get("TimestampUTC", ""),
                "event_id":     sysmon_event.get("EventID", ""),
            },

            # Phan 3: Ket qua phan tich (Analysis)
            "analysis": {
                "matched_rules": matched_rules,
                "nlp_threat_label": threat_label,
                "attack_type": IncidentSummarizer._classify_attack(matched_rules, threat_label),
            },

            # Phan 4: Bien phap xu ly (Response taken)
            "response": {
                "action_taken": "KILL_PROCESS" if severity == "CRITICAL" else "MONITOR",
                "status": "CONTAINED" if severity == "CRITICAL" else "OBSERVED",
            },
        }

        # Luu ra file JSON trong reports/
        self._save(summary)
        return summary

    def _save(self, summary: Dict[str, Any]):
        """Luu ban tom tat ra file JSON trong thu muc reports/."""
        filename = f"{summary['report_id']}.json"
        filepath = os.path.join(self.reports_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=4, ensure_ascii=False)

    @staticmethod
    def _classify_attack(rules: list, nlp_label: str) -> str:
        """
        Phan loai loai tan cong dua tren matched_rules va nhan NLP.
        """
        rules_str = " ".join(rules).lower()
        label_lower = nlp_label.lower()

        if "invoke-webrequest" in rules_str or "curl" in rules_str or "wget" in rules_str:
            return "Executable Download / C2 Callback"
        if "exfil" in rules_str or "data exfiltration" in label_lower:
            return "Data Exfiltration"
        if "remote code execution" in label_lower:
            return "Remote Code Execution (RCE)"
        if "payload" in rules_str:
            return "Payload Delivery"
        if "iex" in rules_str:
            return "In-Memory Execution (IEX)"
        return "Suspicious Activity"
