import queue
import threading
import psutil

class ContainmentEngine:
    def __init__(self, action_queue: queue.Queue, mode: str = "CONTAIN"):
        self.action_queue = action_queue
        self.mode = mode.upper() # "ALERT" hoặc "CONTAIN"
        self.running = False
        self.thread = None

    def _kill_process(self, pid: int, image_name: str):
        if self.mode == "ALERT":
            print(f"\n[ResponseEngine] ⚠️ [MODE: ALERT] Bỏ qua diệt PID {pid} ({image_name}) do đang ở chế độ Monitor-only.")
            return

        try:
            p = psutil.Process(pid)
            p.terminate()
            print(f"\n[ResponseEngine] ⚔️ ĐÃ TIÊU DIỆT THÀNH CÔNG TIẾN TRÌNH ĐỘC HẠI!")
            print(f"   [+] PID: {pid} ({image_name})")
            print(f"   [+] AI IDE/Agent vẫn an toàn, chỉ luồng thực thi phụ bị chặn đứng.")
        except psutil.NoSuchProcess:
            print(f"\n[ResponseEngine] ℹ️ Tiến trình PID {pid} đã tự kết thúc trước khi bị chém.")
        except psutil.AccessDenied:
            print(f"\n[ResponseEngine] ❌ Lỗi: Access Denied. Không đủ quyền chém PID {pid} (Cần quyền Admin / SYSTEM).")
        except Exception as e:
            print(f"\n[ResponseEngine] ❌ Lỗi không xác định khi tiêu diệt tiến trình {pid}: {e}")

    def _process_queue(self):
        while self.running:
            try:
                incident = self.action_queue.get(timeout=1.0)
                sysmon_event = incident.get("sysmon_event", {})
                pid_str = sysmon_event.get("ProcessId")
                image = sysmon_event.get("Image", "Unknown")
                
                if pid_str:
                    print(f"\n[ResponseEngine] ⚡ RA QUYẾT ĐỊNH CONTAINMENT CHO {incident['incident_id']}...")
                    try:
                        pid = int(pid_str)
                        self._kill_process(pid, image)
                    except ValueError:
                        pass
                        
                self.action_queue.task_done()
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
