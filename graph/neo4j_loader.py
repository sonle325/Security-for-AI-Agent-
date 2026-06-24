import os
from typing import Dict, Any, Optional


class Neo4jLoader:
    """Build và thực thi Cypher Query để đẩy Incident lên Neo4j."""

    CYPHER_OUTPUT_FILE = "incident_graph_queries.cypher"

    @staticmethod
    def build_merge_query(incident: Dict[str, Any]) -> tuple:
        """Xây dựng Cypher MERGE query từ incident data. Returns (query, params)."""
        ai_event  = incident.get("ai_event", {})
        sys_event = incident.get("sysmon_event", {})
        inc_type  = incident.get("incident_type", "CORRELATED")

        query = """
        MERGE (e:Endpoint {hostname: $hostname})

        MERGE (a:AIAgent {name: $agent})
          SET a.last_seen = $ai_time

        MERGE (i:Incident {id: $inc_id})
          SET i.type      = $inc_type,
              i.severity  = $severity,
              i.timestamp = $ai_time

        MERGE (a)-[:TRIGGERED {action: $action, time: $ai_time}]->(i)
        MERGE (i)-[:OCCURRED_ON]->(e)
        """

        if sys_event.get("Image"):
            query += """
        MERGE (p:Process {pid: $pid, image: $image})
          SET p.cmdline   = $cmdline,
              p.eventTime = $sys_time,
              p.eventId   = $event_id
        MERGE (i)-[:EXECUTED {time: $sys_time}]->(p)
        MERGE (p)-[:RAN_ON]->(e)
            """

        if incident.get("prompt_analysis"):
            query += """
        MERGE (pr:PromptEvent {incident_id: $inc_id})
          SET pr.injection_score = $inj_score,
              pr.risk_level      = $inj_risk,
              pr.patterns        = $inj_patterns
        MERGE (i)-[:CONTAINS_PROMPT]->(pr)
            """

        if sys_event.get("EventID") == 3:
            query += """
        MERGE (n:NetworkConn {dest_ip: $dest_ip, dest_port: $dest_port})
        MERGE (i)-[:NETWORK_ACTIVITY]->(n)
            """

        if sys_event.get("EventID") == 13:
            query += """
        MERGE (r:RegistryKey {path: $reg_path})
          SET r.details = $reg_details
        MERGE (i)-[:MODIFIED_REGISTRY]->(r)
            """

        session_id = ai_event.get("session_id")
        if session_id:
            query += """
        MERGE (s:Session {id: $session_id})
        MERGE (i)-[:BELONGS_TO]->(s)
            """

        prompt_analysis = incident.get("prompt_analysis", {})
        params = {
            "hostname": os.environ.get("COMPUTERNAME", "localhost"),
            "agent":    ai_event.get("agent", "Unknown"),
            "inc_id":   incident.get("incident_id", "UNKNOWN"),
            "inc_type": inc_type,
            "severity": incident.get("severity", incident.get("ai_event", {}).get("risk_level", "LOW")),
            "ai_time":  ai_event.get("timestamp", ""),
            "action":   ai_event.get("action", ""),
            "pid":      str(sys_event.get("ProcessId", "0")),
            "image":    sys_event.get("Image", ""),
            "cmdline":  sys_event.get("CommandLine", ""),
            "sys_time": sys_event.get("TimestampUTC", ""),
            "event_id": str(sys_event.get("EventID", "")),
            "inj_score":    prompt_analysis.get("injection_score", 0),
            "inj_risk":     prompt_analysis.get("risk_level", "NONE"),
            "inj_patterns": ", ".join(prompt_analysis.get("matched_patterns", [])),
            "dest_ip":   sys_event.get("DestinationIp", ""),
            "dest_port": str(sys_event.get("DestinationPort", "")),
            "reg_path":    sys_event.get("TargetObject", ""),
            "reg_details": sys_event.get("Details", ""),
            "session_id":  ai_event.get("session_id", ""),
        }

        return query.strip(), params

    @staticmethod
    def execute(driver, incident: Dict[str, Any]) -> bool:
        if driver is None:
            return False
        query, params = Neo4jLoader.build_merge_query(incident)
        try:
            with driver.session() as session:
                session.run(query, **params)
            return True
        except Exception as e:
            print(f"[Neo4jLoader] Lỗi đẩy Neo4j: {e}")
            return False

    @staticmethod
    def export_cypher(incident: Dict[str, Any], output_path: Optional[str] = None):
        """Xuất Cypher ra file khi Neo4j offline."""
        if output_path is None:
            output_path = Neo4jLoader.CYPHER_OUTPUT_FILE

        ai_event  = incident.get("ai_event", {})
        sys_event = incident.get("sysmon_event", {})
        inc_id    = incident.get("incident_id", "UNKNOWN")
        inc_type  = incident.get("incident_type", "CORRELATED")
        severity  = incident.get("severity", "LOW")

        def esc(s):
            return str(s or "").replace("'", "\\'").replace("\\", "\\\\")

        hostname = os.environ.get("COMPUTERNAME", "localhost")
        prompt_analysis = incident.get("prompt_analysis", {})

        lines = [
            f"// Incident: {inc_id} | Type: {inc_type} | Severity: {severity}",
            f"MERGE (e:Endpoint {{hostname: '{esc(hostname)}'}});",
            f"MERGE (a:AIAgent {{name: '{esc(ai_event.get('agent', 'Unknown'))}'}}) SET a.last_seen = '{esc(ai_event.get('timestamp', ''))}'  ;",
            f"MERGE (i:Incident {{id: '{inc_id}'}}) SET i.type = '{inc_type}', i.severity = '{severity}', i.timestamp = '{esc(ai_event.get('timestamp', ''))}';",
            f"MATCH (a:AIAgent {{name: '{esc(ai_event.get('agent', ''))}'}}), (i:Incident {{id: '{inc_id}'}}) MERGE (a)-[:TRIGGERED {{action: '{esc(ai_event.get('action', ''))}'}}]->(i);",
            f"MATCH (i:Incident {{id: '{inc_id}'}}), (e:Endpoint {{hostname: '{esc(hostname)}'}}) MERGE (i)-[:OCCURRED_ON]->(e);",
        ]

        if sys_event.get("Image"):
            pid = str(sys_event.get("ProcessId", "0"))
            img = esc(sys_event.get("Image", ""))
            cmd = esc(sys_event.get("CommandLine", ""))
            sys_t = esc(sys_event.get("TimestampUTC", ""))
            lines += [
                f"MERGE (p:Process {{pid: '{pid}', image: '{img}'}}) SET p.cmdline = '{cmd}', p.eventTime = '{sys_t}';",
                f"MATCH (i:Incident {{id: '{inc_id}'}}), (p:Process {{pid: '{pid}', image: '{img}'}}) MERGE (i)-[:EXECUTED]->(p);",
            ]

        if prompt_analysis:
            inj_score = prompt_analysis.get("injection_score", 0)
            inj_risk  = prompt_analysis.get("risk_level", "NONE")
            inj_pats  = esc(", ".join(prompt_analysis.get("matched_patterns", [])))
            lines += [
                f"MERGE (pr:PromptEvent {{incident_id: '{inc_id}'}}) SET pr.injection_score = {inj_score}, pr.risk_level = '{inj_risk}', pr.patterns = '{inj_pats}';",
                f"MATCH (i:Incident {{id: '{inc_id}'}}), (pr:PromptEvent {{incident_id: '{inc_id}'}}) MERGE (i)-[:CONTAINS_PROMPT]->(pr);",
            ]

        if sys_event.get("EventID") == 3:
            dest_ip = esc(sys_event.get("DestinationIp", ""))
            dest_port = str(sys_event.get("DestinationPort", ""))
            lines += [
                f"MERGE (n:NetworkConn {{dest_ip: '{dest_ip}', dest_port: '{dest_port}'}});",
                f"MATCH (i:Incident {{id: '{inc_id}'}}), (n:NetworkConn {{dest_ip: '{dest_ip}'}}) MERGE (i)-[:NETWORK_ACTIVITY]->(n);",
            ]

        if sys_event.get("EventID") == 13:
            reg_path = esc(sys_event.get("TargetObject", ""))
            reg_det  = esc(sys_event.get("Details", ""))
            lines += [
                f"MERGE (r:RegistryKey {{path: '{reg_path}'}}) SET r.details = '{reg_det}';",
                f"MATCH (i:Incident {{id: '{inc_id}'}}), (r:RegistryKey {{path: '{reg_path}'}}) MERGE (i)-[:MODIFIED_REGISTRY]->(r);",
            ]

        session_id = ai_event.get("session_id")
        if session_id:
            lines += [
                f"MERGE (s:Session {{id: '{esc(session_id)}'}});",
                f"MATCH (i:Incident {{id: '{inc_id}'}}), (s:Session {{id: '{esc(session_id)}'}}) MERGE (i)-[:BELONGS_TO]->(s);",
            ]

        cypher_block = "\n".join(lines) + "\n\n"
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(cypher_block)
