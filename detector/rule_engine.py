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

        # Allowlist domain — lệnh truy cập domain này sẽ không bị flag
        self.allowed_domains = det_cfg.get("allowed_domains", [
            "github.com", "viettel.com.vn", "localhost", "127.0.0.1", "pypi.org", "npm"
        ])

        self.risk_scorer = RiskScoringEngine()

    def _evaluate_risk(self, incident):
        sysmon_event = incident.get("sysmon_event", {})
        cmdline = sysmon_event.get("CommandLine", "").lower()

        for domain in self.allowed_domains:
            if domain in cmdline:
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
            logger.warning("   Công thức: Rule(%d) + Process(%d) + Net(%d) + Corr(%d) + Monitor(%d) = %d điểm",
                         details['rule'], details['process'], details['network'],
                         details['correlation'], details.get('monitor_bonus', 0), score)
            logger.warning("   Dấu hiệu: %s", ', '.join(matched_rules))
            logger.warning("   CommandLine: %s", cmdline)

            filepath = os.path.join(self.alert_dir, f"{incident['incident_id']}.json")
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(incident, f, indent=4, ensure_ascii=False)
        else:
            incident["severity"] = severity
            logger.info("Incident %s (Severity: %s, Score: %d/100).", incident['incident_id'], severity, score)
        
        # LUÔN ĐẨY VÀO QUEUE ĐỂ HIỂN THỊ LÊN DASHBOARD VÀ CHẠY NLP REPORT
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
