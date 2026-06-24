import logging
from typing import Dict, Any, Tuple, List
import config_loader

logger = logging.getLogger("EDR.RiskScoring")


class RiskScoringEngine:
    """Đánh giá rủi ro incident dựa trên: Rule + Process + Network + Correlation + Monitor Bonus."""

    def __init__(self):
        weights = config_loader.get("risk_weights", default={})
        det_cfg = config_loader.get("detection", default={})

        self.critical_threshold = det_cfg.get("critical_threshold", 60)
        self.rule_severity_max = weights.get("rule_severity_max", 20)
        self.process_weight_ps = weights.get("process_weight_powershell", 20)
        self.process_weight_cmd = weights.get("process_weight_cmd", 10)
        self.network_activity_score = weights.get("network_activity", 20)
        self.correlation_confidence_score = weights.get("correlation_confidence", 30)
        self.prompt_injection_bonus = weights.get("prompt_injection_bonus", 15)
        self.tool_anomaly_bonus = weights.get("tool_anomaly_bonus", 10)
        self.response_disclosure_bonus = weights.get("response_disclosure_bonus", 10)

    def evaluate(self, incident: Dict[str, Any], cmdline: str, image: str,
                 ai_event: Dict[str, Any], dangerous_keywords: List[str]) -> Tuple[int, str, List[str], Dict[str, int]]:
        """Trả về (total_score, severity, matched_rules, score_details)."""
        rule_severity = 0
        process_weight = 0
        network_activity = 0
        correlation_confidence = 0
        monitor_bonus = 0
        matched_rules = []

        # Keyword matching
        matched_keywords = [kw for kw in dangerous_keywords if kw in cmdline]
        if matched_keywords:
            rule_severity = self.rule_severity_max
            for kw in matched_keywords:
                matched_rules.append(f"Suspicious Keyword: {kw}")

        # Process type
        if "powershell" in image:
            process_weight = self.process_weight_ps
            matched_rules.append("Process: PowerShell")
        elif "cmd.exe" in image:
            process_weight = self.process_weight_cmd
            matched_rules.append("Process: CMD")

        # Network
        if any(nw in cmdline for nw in ["http", "ftp", "curl", "wget", "invoke-webrequest"]):
            network_activity = self.network_activity_score
            matched_rules.append("Network: Outbound Comm")

        # AI Agent correlation
        agent = ai_event.get("agent", "")
        if agent and agent != "Background Script/AI" and agent != "Unknown Agent":
            correlation_confidence = self.correlation_confidence_score
            matched_rules.append("Correlation: Confirmed AI Match")

        # PromptMonitor bonus
        prompt_analysis = incident.get("prompt_analysis", {})
        if prompt_analysis.get("is_injection"):
            injection_score = prompt_analysis.get("injection_score", 0)
            if injection_score >= 40:
                monitor_bonus += self.prompt_injection_bonus
                matched_rules.append(f"PromptMonitor: Injection (score={injection_score})")

        # ToolMonitor bonus
        tool_analysis = incident.get("tool_analysis", {})
        if tool_analysis.get("has_anomaly"):
            tool_risk = tool_analysis.get("risk_score", 0)
            if tool_risk >= 30:
                monitor_bonus += self.tool_anomaly_bonus
                matched_rules.append(f"ToolMonitor: Anomaly (score={tool_risk})")

        # ResponseMonitor bonus
        response_analysis = incident.get("response_analysis", {})
        if response_analysis.get("has_sensitive_data"):
            disclosure_score = response_analysis.get("disclosure_score", 0)
            if disclosure_score >= 30:
                monitor_bonus += self.response_disclosure_bonus
                matched_rules.append(f"ResponseMonitor: Disclosure (score={disclosure_score})")

        total_risk_score = rule_severity + process_weight + network_activity + correlation_confidence + monitor_bonus

        if total_risk_score >= self.critical_threshold:
            severity = "CRITICAL"
        elif total_risk_score >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        score_details = {
            "rule": rule_severity,
            "process": process_weight,
            "network": network_activity,
            "correlation": correlation_confidence,
            "monitor_bonus": monitor_bonus,
        }

        logger.debug("Risk Score: %d (%s) — %s", total_risk_score, severity, score_details)

        return total_risk_score, severity, matched_rules, score_details
