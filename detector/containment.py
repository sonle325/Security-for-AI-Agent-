import queue
import threading
import logging
import psutil
import config_loader

logger = logging.getLogger("EDR.Containment")


class ContainmentEngine:
    def __init__(self, action_queue: queue.Queue, mode: str = None):
        self.action_queue = action_queue
        self.running = False
        self.thread = None

        cont_cfg = config_loader.get("containment", default={})
        self.mode = (mode or cont_cfg.get("mode", "CONTAIN")).upper()

        self.action_lock = threading.Lock()

        # Whitelist — tiến trình KHÔNG BAO GIỜ bị kill dù ML detect nhầm
        self.whitelist_images = cont_cfg.get("whitelist_processes", [
            "code.exe", "cursor.exe", "explorer.exe", "svchost.exe",
            "system", "smss.exe", "csrss.exe", "wininit.exe",
            "services.exe", "lsass.exe", "winlogon.exe",
            "conhost.exe"
        ])

        # Merge thêm từ whitelist_parent_images (bảo vệ IDE)
        parent_wl = config_loader.get("whitelist_parent_images", default=[])
        for item in parent_wl:
            if item not in self.whitelist_images:
                self.whitelist_images.append(item)

    def _is_whitelisted(self, image_name: str) -> bool:
        import ntpath
        basename = ntpath.basename(image_name).lower()
        return basename in [w.lower() for w in self.whitelist_images]

    def _kill_process(self, pid: int, image_name: str) -> str:
        """Thực hiện kill process và trả về kết quả thực tế.
        
        Returns:
            str: TERMINATED | ALREADY_EXITED | ACCESS_DENIED | WHITELISTED | ALERT_ONLY | ERROR
        """
        if self.mode == "ALERT":
            logger.info("[MODE: ALERT] Skipped terminating PID %d (%s) - Monitor-only mode.", pid, image_name)
            return "ALERT_ONLY"

        if self._is_whitelisted(image_name):
            logger.warning("FAIL-SAFE: Từ chối kill tiến trình an toàn: %s (PID: %d).", image_name, pid)
            return "WHITELISTED"

        # Lock để tránh race condition + deadlock nếu psutil crash
        self.action_lock.acquire()
        try:
            p = psutil.Process(pid)
            p.terminate()
            logger.info("Terminated PID: %d (%s)", pid, image_name)
            return "TERMINATED"
        except psutil.NoSuchProcess:
            logger.info("Process PID %d already exited.", pid)
            return "ALREADY_EXITED"
        except psutil.AccessDenied:
            logger.error("Access Denied khi kill PID %d (cần quyền Admin).", pid)
            return "ACCESS_DENIED"
        except Exception as e:
            logger.error("Lỗi kill process %d: %s", pid, e)
            return "ERROR"
        finally:
            self.action_lock.release()

    def _process_queue(self):
        while self.running:
            try:
                incident = self.action_queue.get(timeout=1.0)
                sysmon_event = incident.get("sysmon_event", {})
                pid_str = sysmon_event.get("ProcessId")
                image = sysmon_event.get("Image", "Unknown")

                if incident.get("severity") == "CRITICAL":
                    if pid_str:
                        logger.info("Evaluating containment for incident %s...", incident['incident_id'])
                        try:
                            result = self._kill_process(int(pid_str), image)
                            incident["containment_result"] = result
                        except ValueError:
                            incident["containment_result"] = "INVALID_PID"
                    else:
                        # AI-only incident (Prompt Injection / Tool Anomaly / Data Disclosure)
                        # Không có PID từ Sysmon → không thể kill → ghi trung thực
                        incident["containment_result"] = "NO_PID_AVAILABLE"
                        logger.info("Incident %s is AI-only (no sysmon PID) — containment not applicable.",
                                    incident['incident_id'])
                else:
                    incident["containment_result"] = "NOT_CRITICAL"

                self.action_queue.task_done()
            except queue.Empty:
                pass
            except Exception as e:
                logger.error("Lỗi trong _process_queue: %s", e)

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
