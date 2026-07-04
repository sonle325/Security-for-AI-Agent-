import queue
import threading
import json
import os
import logging
from detector.risk_scoring import RiskScoringEngine
import config_loader

logger = logging.getLogger("EDR.Detection")


class DetectionEngine:
    def __init__(self, incident_queue: queue.Queue, action_queue: queue.Queue):
        self.incident_queue = incident_queue
        self.action_queue = action_queue
        self.running = False
        self.thread = None

        det_cfg = config_loader.get("detection", default={})
        alert_cfg = config_loader.get("alert_queue", default={})

        self.alert_dir = alert_cfg.get("directory", "alert_queue")
        os.makedirs(self.alert_dir, exist_ok=True)

        self.dangerous_keywords = det_cfg.get("dangerous_keywords", [
            "curl", "wget", "iex", "invoke-webrequest", "payload", "nc.exe"
        ])

        self.allowed_domains = det_cfg.get("allowed_domains", [
            "github.com", "viettel.com.vn", "localhost", "127.0.0.1", "pypi.org", "npm"
        ])

        self.risk_scorer = RiskScoringEngine()

    def _evaluate_risk(self, incident):
        sysmon_event = incident.get("sysmon_event", {})

        if not sysmon_event:
            score = (incident.get("prompt_analysis", {}).get("injection_score")
                     or incident.get("tool_analysis", {}).get("risk_score")
                     or incident.get("response_analysis", {}).get("disclosure_score")
                     or 0)
            severity = "CRITICAL" if score >= self.risk_scorer.critical_threshold \
                        else "MEDIUM" if score >= 30 else "LOW"
            incident["severity"] = severity
            if severity == "CRITICAL":
                logger.warning("CẢNH BÁO MỨC ĐỘ CRITICAL: %s (Monitor Score: %d/100)", incident['incident_id'], score)
                filepath = os.path.join(self.alert_dir, f"{incident['incident_id']}.json")
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(incident, f, indent=4, ensure_ascii=False)
            self.action_queue.put(incident)
            return

        cmdline = sysmon_event.get("CommandLine", "").lower()

        import re
        for domain in self.allowed_domains:
            pattern = r'(?i)\b' + re.escape(domain) + r'\b'
            if re.search(pattern, cmdline):
                incident["severity"] = "LOW"
                logger.info("Skipped due to allowlist match: %s", domain)
                return

        ai_event = incident.get("ai_event", {})
        image = sysmon_event.get("Image", "").lower()

        score, severity, matched_rules, details = self.risk_scorer.evaluate(
            incident, cmdline, image, ai_event, self.dangerous_keywords
        )

        if severity == "CRITICAL":
            incident["severity"] = "CRITICAL"
            incident["matched_rules"] = matched_rules
            logger.warning("CẢNH BÁO MỨC ĐỘ CRITICAL: %s", incident['incident_id'])
            logger.warning("   Công thức: Base(%d) x Conf(%.2f) x Context(%.2f) = %d điểm",
                         details['base_severity'], details['confidence'], details['context_multiplier'], score)
            logger.warning("   Dấu hiệu: %s", ', '.join(matched_rules))
            logger.warning("   CommandLine: %s", cmdline)

            filepath = os.path.join(self.alert_dir, f"{incident['incident_id']}.json")
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(incident, f, indent=4, ensure_ascii=False)
        else:
            incident["severity"] = severity
            logger.info("Incident %s (Severity: %s, Score: %d/100).", incident['incident_id'], severity, score)
        
        self.action_queue.put(incident)

    def _process_queue(self):
        while self.running:
            try:
                incident = self.incident_queue.get(timeout=1.0)
                self._evaluate_risk(incident)
                self.incident_queue.task_done()
            except queue.Empty:
                pass

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._process_queue, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
