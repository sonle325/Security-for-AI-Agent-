import queue
import threading
import psutil

class ContainmentEngine:
    def __init__(self, action_queue: queue.Queue, mode: str = "CONTAIN"):
        self.action_queue = action_queue
        self.mode = mode.upper() # "ALERT" hoặc "CONTAIN"
        self.running = False
        self.thread = None
        
        # Khóa an toàn (Fail-Safe Lock) cho các thao tác tác động hệ thống
        self.action_lock = threading.Lock()
        
        # Whitelist (Safe-list) các tiến trình KHÔNG BAO GIỜ bị EDR chém
        # Dù cho ML/Rules có nhận diện nhầm, hệ thống vẫn an toàn.
        self.whitelist_images = [
            "code.exe", 
            "cursor.exe", 
            "explorer.exe", 
            "svchost.exe",
            "system",
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "services.exe",
            "lsass.exe",
            "winlogon.exe"
        ]

    def _is_whitelisted(self, image_name: str) -> bool:
        img_lower = image_name.lower()
        for safe_img in self.whitelist_images:
            if safe_img in img_lower:
                return True
        return False

    def _kill_process(self, pid: int, image_name: str):
        if self.mode == "ALERT":
            print(f"\n[ResponseEngine] [!] [MODE: ALERT] Bỏ qua diệt PID {pid} ({image_name}) do đang ở chế độ Monitor-only.")
            return

        # Kiểm tra Fallback an toàn trước khi hành động
        if self._is_whitelisted(image_name):
            print(f"\n[ResponseEngine] [!] FAIL-SAFE KÍCH HOẠT: Từ chối tiêu diệt tiến trình an toàn: {image_name} (PID: {pid}).")
            return

        # Sử dụng try...finally với threading.Lock() để đảm bảo
        # không bao giờ bị treo (deadlock) nếu psutil bị crash giữa chừng
        self.action_lock.acquire()
        try:
            p = psutil.Process(pid)
            p.terminate()
            print(f"\n[ResponseEngine] [+] ĐÃ TIÊU DIỆT THÀNH CÔNG TIẾN TRÌNH ĐỘC HẠI!")
            print(f"   [+] PID: {pid} ({image_name})")
            print(f"   [+] AI IDE/Agent vẫn an toàn, chỉ luồng thực thi phụ bị chặn đứng.")
        except psutil.NoSuchProcess:
            print(f"\n[ResponseEngine] [*] Tiến trình PID {pid} đã tự kết thúc trước khi bị chém.")
        except psutil.AccessDenied:
            print(f"\n[ResponseEngine] [-] Lỗi: Access Denied. Không đủ quyền chém PID {pid} (Cần quyền Admin / SYSTEM).")
        except Exception as e:
            print(f"\n[ResponseEngine] [-] Lỗi không xác định khi tiêu diệt tiến trình {pid}: {e}")
        finally:
            self.action_lock.release()

    def _process_queue(self):
        while self.running:
            try:
                incident = self.action_queue.get(timeout=1.0)
                sysmon_event = incident.get("sysmon_event", {})
                pid_str = sysmon_event.get("ProcessId")
                image = sysmon_event.get("Image", "Unknown")
                
                if pid_str:
                    print(f"\n[ResponseEngine] [*] RA QUYẾT ĐỊNH CONTAINMENT CHO {incident['incident_id']}...")
                    try:
                        pid = int(pid_str)
                        self._kill_process(pid, image)
                    except ValueError:
                        pass
                        
                self.action_queue.task_done()
            except queue.Empty:
                pass
            except Exception as e:
                # Catch-all để đảm bảo thread không bị chết
                print(f"[ResponseEngine] Lỗi trong _process_queue: {e}")

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
