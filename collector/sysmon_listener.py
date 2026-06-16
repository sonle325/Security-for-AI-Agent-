import time
import win32evtlog
import winerror
import queue
import threading
from .event_parser import EventParser

class SysmonListener:
    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue
        self.running = False
        self.subscription = None
        self.thread = None
        
        # Filter noise early to save CPU
        self.whitelist_images = [
            "code.exe",
            "cursor.exe",
            "chrome.exe",
            "explorer.exe",
            "svchost.exe"
        ]

    def _is_whitelisted(self, image_path: str) -> bool:
        if not image_path:
            return False
        image_lower = image_path.lower()
        for whitelist_img in self.whitelist_images:
            if image_lower.endswith(whitelist_img):
                return True
        return False

    def _on_event(self, action, context, event_handle):
        """Callback for win32evtlog subscription."""
        if action == win32evtlog.EvtSubscribeActionDeliver:
            try:
                # Render event as XML
                xml_content = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
                
                # Parse and normalize
                normalized_event = EventParser.parse_sysmon_xml(xml_content)
                
                if normalized_event:
                    # Apply early whitelist on Process Image
                    image = normalized_event.get("Image", "")
                    if not self._is_whitelisted(image):
                        self.event_queue.put(normalized_event)
                        
            except Exception as e:
                # Log error or pass
                pass

    def _listen_loop(self):
        """Background loop to maintain subscription and handle auto-reconnect."""
        channel_path = "Microsoft-Windows-Sysmon/Operational"
        query = "*" # Listen to all events, we filter in parser
        
        while self.running:
            try:
                if self.subscription is None:
                    print(f"[SysmonListener] Subscribing to {channel_path}...")
                    self.subscription = win32evtlog.EvtSubscribe(
                        channel_path,
                        win32evtlog.EvtSubscribeToFutureEvents,
                        None,
                        self._on_event,
                        None,
                        query
                    )
                    print("[SysmonListener] Subscription active.")
                
                # Keep thread alive, polling for stop signal
                time.sleep(2)
                
            except Exception as e:
                print(f"[SysmonListener] Error: {e}. Reconnecting in 5s...")
                if self.subscription:
                    try:
                        self.subscription.close()
                    except:
                        pass
                    self.subscription = None
                time.sleep(5)

    def start(self):
        """Starts the listener in a background thread."""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.thread.start()

    def stop(self):
        """Stops the listener."""
        self.running = False
        if self.subscription:
            try:
                self.subscription.close()
            except:
                pass
            self.subscription = None
        if self.thread:
            self.thread.join(timeout=3)
