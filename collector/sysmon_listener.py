import time
import win32evtlog
import winerror
import queue
import logging
import threading
from .event_parser import EventParser
import config_loader

logger = logging.getLogger("EDR.Sysmon")


class SysmonListener:
    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue
        self.running = False
        self.subscription = None
        self.thread = None

        sysmon_cfg = config_loader.get("sysmon", default={})
        self.whitelist_images = sysmon_cfg.get("whitelist_images", [
            "code.exe", "cursor.exe", "chrome.exe",
            "explorer.exe", "svchost.exe"
        ])

    def _is_whitelisted(self, image_path: str) -> bool:
        if not image_path:
            return False
        image_lower = image_path.lower()
        return any(image_lower.endswith(w) for w in self.whitelist_images)

    def _on_event(self, action, context, event_handle):
        if action == win32evtlog.EvtSubscribeActionDeliver:
            try:
                xml_content = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
                normalized_event = EventParser.parse_sysmon_xml(xml_content)

                if normalized_event:
                    image = normalized_event.get("Image", "")
                    if not self._is_whitelisted(image):
                        self.event_queue.put(normalized_event)
            except Exception:
                pass

    def _listen_loop(self):
        channel_path = "Microsoft-Windows-Sysmon/Operational"
        query = "*"

        while self.running:
            try:
                if self.subscription is None:
                    logger.info("Subscribing to %s...", channel_path)
                    self.subscription = win32evtlog.EvtSubscribe(
                        channel_path,
                        win32evtlog.EvtSubscribeToFutureEvents,
                        None, self._on_event, None, query
                    )
                    logger.info("Subscription active.")

                time.sleep(2)

            except Exception as e:
                logger.error("Error: %s. Reconnecting in 5s...", e)
                if self.subscription:
                    try:
                        self.subscription.close()
                    except Exception:
                        pass
                    self.subscription = None
                time.sleep(5)

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.subscription:
            try:
                self.subscription.close()
            except Exception:
                pass
            self.subscription = None
        if self.thread:
            self.thread.join(timeout=3)
