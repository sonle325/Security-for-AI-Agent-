"""
Risk Scoring Engine
===================
Dam nhan viec cham diem muc do rui ro cua mot su co (Incident)
dua tren 4 bien so: Rule Severity, Process Weight, Network Activity,
va Correlation Confidence.

Output cua module nay quyet dinh Incident co bi phan loai la CRITICAL hay khong.
"""

from typing import Dict, Any, Tuple, List

class RiskScoringEngine:
    def __init__(self):
        # Nguong diem quyet dinh
        self.critical_threshold = 60

    def evaluate(self, incident: Dict[str, Any], cmdline: str, image: str, ai_event: Dict[str, Any], dangerous_keywords: List[str]) -> Tuple[int, str, List[str], Dict[str, int]]:
        """
        Danh gia rui ro cua incident.
        Tra ve: (total_risk_score, severity, matched_rules, score_details)
        """
        rule_severity = 0
        process_weight = 0
        network_activity = 0
        correlation_confidence = 0
        matched_rules = []
        
        # 1. Rule Severity (cap toi da 20 diem)
        matched_keywords = [kw for kw in dangerous_keywords if kw in cmdline]
        if matched_keywords:
            rule_severity = 20
            for kw in matched_keywords:
                matched_rules.append(f"Suspicious Keyword: {kw}")
                
        # 2. Process Weight
        if "powershell" in image:
            process_weight = 20
            matched_rules.append("Process: PowerShell")
        elif "cmd.exe" in image:
            process_weight = 10
            matched_rules.append("Process: CMD")
            
        # 3. Network Activity
        if any(nw in cmdline for nw in ["http", "ftp", "curl", "wget", "invoke-webrequest"]):
            network_activity = 20
            matched_rules.append("Network: Outbound Comm")
            
        # 4. Correlation Confidence
        if ai_event.get("agent") and ai_event.get("agent") != "Background Script/AI" and ai_event.get("agent") != "Unknown Agent":
            correlation_confidence = 30
            matched_rules.append("Correlation: Confirmed AI Match")
        else:
            correlation_confidence = 0
            
        # 5. TOTAL RISK SCORE
        total_risk_score = rule_severity + process_weight + network_activity + correlation_confidence
        
        # Determine Severity
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
            "correlation": correlation_confidence
        }
            
        return total_risk_score, severity, matched_rules, score_details
