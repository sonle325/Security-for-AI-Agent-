import logging
from typing import Dict, Any, Tuple, List
import config_loader

logger = logging.getLogger("EDR.RiskScoring")


class RiskScoringEngine:


    def __init__(self):
        det_cfg = config_loader.get("detection", default={})
        self.critical_threshold = det_cfg.get("critical_threshold", 60)

        risk_cfg = config_loader.get("risk_scoring", default={})
        
        base = risk_cfg.get("base_severity", {})
        self.base_ps = base.get("powershell", 70)
        self.base_cmd = base.get("cmd", 60)
        self.base_kw = base.get("suspicious_keyword", 80)
        self.base_unknown = base.get("default_unknown", 20)
        
        ctx = risk_cfg.get("context_multiplier", {})
        self.ctx_net = ctx.get("external_network", 1.5)
        self.ctx_inj = ctx.get("prompt_injection", 1.4)
        self.ctx_tool = ctx.get("tool_anomaly", 1.3)
        self.ctx_data = ctx.get("data_disclosure", 1.5)
        self.ctx_dev = ctx.get("human_dev_override", 0.3)
        
        conf = risk_cfg.get("confidence_weights", {})
        self.conf_time = conf.get("time_match", 0.4)
        self.conf_sem = conf.get("semantic_match", 0.3)
        self.conf_sess = conf.get("session_match", 0.3)

    def evaluate(self, incident: Dict[str, Any], cmdline: str, image: str,
                 ai_event: Dict[str, Any], dangerous_keywords: List[str]) -> Tuple[int, str, List[str], Dict[str, int]]:
        
        base_severity = 0
        context_multiplier = 1.0
        matched_rules = []


        if "powershell" in image:
            base_severity = max(base_severity, self.base_ps)
            matched_rules.append("Process: PowerShell")
        elif "cmd.exe" in image:
            base_severity = max(base_severity, self.base_cmd)
            matched_rules.append("Process: CMD")

        matched_keywords = [kw for kw in dangerous_keywords if kw in cmdline]
        if matched_keywords:
            base_severity = max(base_severity, self.base_kw)
            for kw in matched_keywords:
                matched_rules.append(f"Suspicious Keyword: {kw}")

        if base_severity == 0:
            base_severity = self.base_unknown


        if any(nw in cmdline for nw in ["http", "ftp", "curl", "wget", "invoke-webrequest"]):
            context_multiplier = max(context_multiplier, self.ctx_net)
            matched_rules.append(f"Context: External Network (x{self.ctx_net})")

        prompt_analysis = incident.get("prompt_analysis", {})
        if prompt_analysis.get("is_injection"):
            context_multiplier = max(context_multiplier, self.ctx_inj)
            matched_rules.append(f"Context: Prompt Injection (x{self.ctx_inj})")

        tool_analysis = incident.get("tool_analysis", {})
        if tool_analysis.get("has_anomaly"):
            context_multiplier = max(context_multiplier, self.ctx_tool)
            matched_rules.append(f"Context: Tool Anomaly (x{self.ctx_tool})")

        response_analysis = incident.get("response_analysis", {})
        if response_analysis.get("has_sensitive_data"):
            context_multiplier = max(context_multiplier, self.ctx_data)
            matched_rules.append(f"Context: Data Disclosure (x{self.ctx_data})")


        if "cursor" in image.lower() and not ai_event:
            context_multiplier = min(context_multiplier, self.ctx_dev)
            matched_rules.append(f"Context: Human Dev Override (x{self.ctx_dev})")


        confidence = 0.0
        agent = ai_event.get("agent", "")
        if agent and agent not in ["Background Script/AI", "Unknown Agent"]:

            time_match = 1.0
            semantic_match = 0.8
            session_match = 1.0
            
            confidence = (self.conf_time * time_match) + (self.conf_sem * semantic_match) + (self.conf_sess * session_match)
            matched_rules.append(f"Causal Confidence: High ({confidence:.2f})")
        else:
            confidence = 0.5
            matched_rules.append("Causal Confidence: Low/Uncorrelated (0.5)")


        final_risk = base_severity * confidence * context_multiplier
        final_risk = min(100, int(final_risk))

        if final_risk >= self.critical_threshold:
            severity = "CRITICAL"
        elif final_risk >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        score_details = {
            "base_severity": base_severity,
            "confidence": confidence,
            "context_multiplier": context_multiplier,
            "rule": 0, "process": 0, "network": 0, "correlation": 0
        }

        logger.debug("Probabilistic Risk: %d (%s) — %s", final_risk, severity, score_details)

        return final_risk, severity, matched_rules, score_details
