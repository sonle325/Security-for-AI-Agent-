import queue
import threading
import time
import logging
import os
from analyzer.incident_summary import IncidentSummarizer
import config_loader

logging.getLogger("transformers").setLevel(logging.ERROR)

logger = logging.getLogger("EDR.NLP")


class AISecurityAnalyzer:
    def __init__(self, action_queue: queue.Queue):
        self.action_queue = action_queue
        self.running = False
        self.thread = None
        self.classifier = None
        self.summarizer = IncidentSummarizer()

        nlp_cfg = config_loader.get("nlp", default={})
        self.model_name = nlp_cfg.get("model_name", "cross-encoder/nli-deberta-v3-small")
        self.hf_mirror = nlp_cfg.get("hf_mirror", "https://hf-mirror.com")
        self.candidate_labels = nlp_cfg.get("candidate_labels", [
            "remote code execution", "data exfiltration",
            "prompt injection", "credential access",
            "privilege escalation", "system discovery",
            "lateral movement", "benign task"
        ])

    def _init_model(self):
        os.environ["HF_ENDPOINT"] = self.hf_mirror
        logger.info("Loading Zero-Shot Model: %s", self.model_name)
        try:
            from transformers import pipeline  # type: ignore
            self.classifier = pipeline("zero-shot-classification", model=self.model_name)
            logger.info("NLP Pipeline loaded successfully.")
        except Exception as e:
            logger.error("Lỗi tải model: %s", e)

    def _classify_text(self, text: str, incident_id: str) -> dict:
        if not text or not self.classifier:
            return {}
        try:
            result = self.classifier(text, self.candidate_labels)
            return {
                "text_preview": text[:100],
                "top_label": result["labels"][0],
                "top_score": result["scores"][0],
                "all_labels": dict(zip(result["labels"], result["scores"])),
            }
        except Exception as e:
            logger.error("Lỗi classify cho %s: %s", incident_id, e)
            return {}

    def _process_queue(self):
        while self.running:
            try:
                incident = self.action_queue.get(timeout=1.0)
                incident_id = incident.get("incident_id", "?")

                if not self.classifier:
                    self.action_queue.task_done()
                    continue

                logger.info("Analyzing incident %s with ML model...", incident_id)
                start_t = time.time()

                classifications = []

                # CommandLine (Sysmon)
                cmdline = incident.get("sysmon_event", {}).get("CommandLine", "")
                if cmdline:
                    cls = self._classify_text(cmdline, incident_id)
                    if cls:
                        cls["source"] = "sysmon_cmdline"
                        classifications.append(cls)

                # Prompt content (AI Telemetry)
                prompt_content = incident.get("ai_event", {}).get("content", "")
                if prompt_content:
                    cls = self._classify_text(prompt_content, incident_id)
                    if cls:
                        cls["source"] = "ai_prompt"
                        classifications.append(cls)

                # AI action description (fallback nếu không có cmdline)
                ai_action = incident.get("ai_event", {}).get("action", "")
                ai_tool = incident.get("ai_event", {}).get("tool", "")
                if ai_action and not cmdline:
                    action_text = f"{ai_action} using {ai_tool}" if ai_tool else ai_action
                    cls = self._classify_text(action_text, incident_id)
                    if cls:
                        cls["source"] = "ai_action"
                        classifications.append(cls)

                elapsed = time.time() - start_t

                if classifications:
                    best = max(classifications, key=lambda c: c.get("top_score", 0))
                    top_label = best["top_label"]
                    top_score = best["top_score"]

                    logger.info("   Analysis completed in %.2fs", elapsed)
                    logger.info("   Threat Label: %s (Confidence: %.1f%%) [source: %s]",
                                top_label.upper(), top_score * 100, best.get("source", "?"))

                    incident["ai_threat_label"] = top_label
                    incident["ai_classifications"] = classifications
                else:
                    logger.info("   No text available to analyze for incident %s", incident_id)

                self.summarizer.generate(incident)
                self.action_queue.task_done()
            except queue.Empty:
                pass
            except Exception as e:
                logger.error("Lỗi trong NLP pipeline: %s", e)

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._process_queue, daemon=True)
        self.thread.start()
        threading.Thread(target=self._init_model, daemon=True).start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
