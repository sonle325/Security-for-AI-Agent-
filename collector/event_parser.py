import xmltodict
from typing import Dict, Any, Optional

class EventParser:
    """
    Parses and normalizes Sysmon Event XML strings.
    """
    
    @staticmethod
    def parse_sysmon_xml(xml_string: str) -> Optional[Dict[str, Any]]:
        """
        Convert Windows Event XML string into a normalized dictionary.
        Focuses on Event IDs 1, 3, and 11.
        """
        try:
            # Parse XML to dictionary
            event_dict = xmltodict.parse(xml_string)
            
            # Navigate to the core Event node
            event = event_dict.get("Event", {})
            system = event.get("System", {})
            event_data_raw = event.get("EventData", {}).get("Data", [])
            
            # Extract basic System info
            event_id = system.get("EventID")
            # Handle cases where EventID is a dict e.g., {'@Qualifiers': '1', '#text': '1'}
            if isinstance(event_id, dict):
                event_id = event_id.get("#text")
                
            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                return None
                
            # We care about Event ID 1, 3, 11, 13 (Registry), 22 (DNS)
            if event_id not in [1, 3, 11, 13, 22]:
                return None
                
            timestamp_utc = system.get("TimeCreated", {}).get("@SystemTime")
            
            # Normalize EventData (which is usually a list of dicts: [{'@Name': 'RuleName', '#text': '...'}, ...])
            event_data = {}
            if isinstance(event_data_raw, list):
                for item in event_data_raw:
                    name = item.get("@Name")
                    value = item.get("#text")
                    if name:
                        event_data[name] = value
            elif isinstance(event_data_raw, dict): # Single item edge case
                name = event_data_raw.get("@Name")
                value = event_data_raw.get("#text")
                if name:
                    event_data[name] = value
                    
            # Build normalized output
            normalized = {
                "EventID": event_id,
                "TimestampUTC": timestamp_utc,
                "ProcessId": event_data.get("ProcessId"),
                "Image": event_data.get("Image", ""),
                "CommandLine": event_data.get("CommandLine", ""),
                "ParentProcessId": event_data.get("ParentProcessId"),
                "ParentImage": event_data.get("ParentImage", "")
            }
            
            # Add specific fields based on Event ID
            if event_id == 3: # Network Connection
                normalized["DestinationIp"] = event_data.get("DestinationIp", "")
                normalized["DestinationPort"] = event_data.get("DestinationPort", "")
                normalized["Protocol"] = event_data.get("Protocol", "")
            elif event_id == 11: # File Creation
                normalized["TargetFilename"] = event_data.get("TargetFilename", "")
            elif event_id == 13: # Registry Modification (SetValue)
                normalized["EventType"] = event_data.get("EventType", "")
                normalized["TargetObject"] = event_data.get("TargetObject", "")
                normalized["Details"] = event_data.get("Details", "")
            elif event_id == 22: # DNS Query
                normalized["QueryName"] = event_data.get("QueryName", "")
                normalized["QueryResults"] = event_data.get("QueryResults", "")
                normalized["QueryStatus"] = event_data.get("QueryStatus", "")
                
            return normalized
            
        except Exception as e:
            # Silently drop malformed XML in production, or log it
            return None
