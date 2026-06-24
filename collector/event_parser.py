import xmltodict
from typing import Dict, Any, Optional


class EventParser:
    """Parse và normalize Sysmon Event XML."""

    @staticmethod
    def parse_sysmon_xml(xml_string: str) -> Optional[Dict[str, Any]]:
        """Chuyển Windows Event XML thành dict. Chỉ xử lý Event ID 1, 3, 11, 13, 22."""
        try:
            event_dict = xmltodict.parse(xml_string)

            event = event_dict.get("Event", {})
            system = event.get("System", {})
            event_data_raw = event.get("EventData", {}).get("Data", [])

            event_id = system.get("EventID")
            # EventID có thể là dict dạng {'@Qualifiers': '1', '#text': '1'}
            if isinstance(event_id, dict):
                event_id = event_id.get("#text")

            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                return None

            if event_id not in [1, 3, 11, 13, 22]:
                return None

            timestamp_utc = system.get("TimeCreated", {}).get("@SystemTime")

            # Normalize EventData list → dict
            event_data = {}
            if isinstance(event_data_raw, list):
                for item in event_data_raw:
                    name = item.get("@Name")
                    value = item.get("#text")
                    if name:
                        event_data[name] = value
            elif isinstance(event_data_raw, dict):
                name = event_data_raw.get("@Name")
                value = event_data_raw.get("#text")
                if name:
                    event_data[name] = value

            normalized = {
                "EventID": event_id,
                "TimestampUTC": timestamp_utc,
                "ProcessId": event_data.get("ProcessId"),
                "Image": event_data.get("Image", ""),
                "CommandLine": event_data.get("CommandLine", ""),
                "ParentProcessId": event_data.get("ParentProcessId"),
                "ParentImage": event_data.get("ParentImage", "")
            }

            if event_id == 3:  # Network
                normalized["DestinationIp"] = event_data.get("DestinationIp", "")
                normalized["DestinationPort"] = event_data.get("DestinationPort", "")
                normalized["Protocol"] = event_data.get("Protocol", "")
            elif event_id == 11:  # File Create
                normalized["TargetFilename"] = event_data.get("TargetFilename", "")
            elif event_id == 13:  # Registry
                normalized["EventType"] = event_data.get("EventType", "")
                normalized["TargetObject"] = event_data.get("TargetObject", "")
                normalized["Details"] = event_data.get("Details", "")
            elif event_id == 22:  # DNS
                normalized["QueryName"] = event_data.get("QueryName", "")
                normalized["QueryResults"] = event_data.get("QueryResults", "")
                normalized["QueryStatus"] = event_data.get("QueryStatus", "")

            return normalized

        except Exception:
            return None
