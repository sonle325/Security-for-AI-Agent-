import queue
import threading
import time
import logging
import os
from analyzer.incident_summary import IncidentSummarizer

# Tắt log nhiễu của transformers
logging.getLogger("transformers").setLevel(logging.ERROR)

# Ép tải qua server Mirror siêu tốc để chống đứt cáp / nhà mạng chặn HuggingFace
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

class AISecurityAnalyzer:
    def __init__(self, action_queue: queue.Queue):
        self.action_queue = action_queue
        self.running = False
        self.thread = None
        self.classifier = None
        self.summarizer = IncidentSummarizer()  # Tao bao cao Incident sau khi NLP phan tich xong
        
    def _init_model(self):
        print("[AI Analyzer] [*] Đang tải Zero-Shot Model (DeBERTa) vào bộ nhớ...")
        try:
            from transformers import pipeline # type: ignore
            self.classifier = pipeline("zero-shot-classification", model="cross-encoder/nli-deberta-v3-small")
            print("[AI Analyzer] [+] NLP Pipeline tải thành công! Sẵn sàng chinh chiến đồ thật 100%!")
        except Exception as e:
            print(f"[AI Analyzer] [!] Lỗi tải model: {e}")

    def _process_queue(self):
        while self.running:
            try:
                incident = self.action_queue.get(timeout=1.0)
                cmdline = incident.get("sysmon_event", {}).get("CommandLine", "")
                
                if cmdline and self.classifier:
                    print(f"\n[AI Analyzer] [*] Đang dùng Machine Learning đánh giá {incident.get('incident_id')}...")
                    start_t = time.time()
                    
                    candidate_labels = ["remote code execution", "data exfiltration", "system discovery", "benign task"]
                    result = self.classifier(cmdline, candidate_labels)
                    
                    top_label = result['labels'][0]
                    score = result['scores'][0]
                    
                    print(f"   [+] Phân tích xong trong {time.time() - start_t:.2f}s")
                    print(f"   [+] Threat Label: {top_label.upper()} (Confidence: {score*100:.1f}%)")
                    
                    incident["ai_threat_label"] = top_label
                    # Sinh bao cao Incident Summary vao reports/
                    self.summarizer.generate(incident)
                    
                self.action_queue.task_done()
            except queue.Empty:
                pass
            except Exception as e:
                pass

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
