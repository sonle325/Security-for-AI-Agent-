import queue
import logging
import threading
import json
import os
from neo4j import GraphDatabase  # type: ignore
from graph.neo4j_loader import Neo4jLoader

logger = logging.getLogger("EDR.Neo4j")


class Neo4jIncidentGraph:
    def __init__(self, action_queue: queue.Queue,
                 uri="bolt://localhost:7687", user="neo4j", password="password"):
        self.action_queue = action_queue
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = None
        self.running = False
        self.thread = None
        
        self.log_dir = "logs"
        os.makedirs(self.log_dir, exist_ok=True)
        self.dashboard_feed = os.path.join(self.log_dir, "dashboard_feed.jsonl")

    def connect(self):
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            logger.info("Successfully connected to Neo4j.")
        except Exception:
            if self.driver:
                try:
                    self.driver.close()
                except:
                    pass
            self.driver = None
            logger.info("Neo4j offline - running in MOCK MODE (export .cypher + Dashboard).")

    def _process_queue(self):
        while self.running:
            try:
                incident = self.action_queue.get(timeout=1.0)

                # Format JSON cho Dashboard và ghi ra file log
                dash_data = {
                    "id":           incident.get("incident_id", "?"),
                    "type":         incident.get("incident_type", "CORRELATED"),
                    "severity":     incident.get("severity", "MEDIUM"),
                    "agent":        incident.get("ai_event", {}).get("agent", "Unknown"),
                    "action":       incident.get("ai_event", {}).get("action", ""),
                    "session_id":   incident.get("ai_event", {}).get("session_id", "") or incident.get("session_id", ""),
                    "timestamp":    incident.get("ai_event", {}).get("timestamp", ""),
                    "process":      incident.get("sysmon_event", {}).get("Image", ""),
                    "cmdline":      incident.get("sysmon_event", {}).get("CommandLine", ""),
                    "event_id":     str(incident.get("sysmon_event", {}).get("EventID", "")),
                    "prompt_score": incident.get("prompt_analysis", {}).get("injection_score", 0),
                    "prompt_risk":  incident.get("prompt_analysis", {}).get("risk_level", ""),
                    "tool_risk":    incident.get("tool_analysis", {}).get("risk_level", ""),
                    "data_risk":    incident.get("response_analysis", {}).get("risk_level", ""),
                }
                with open(self.dashboard_feed, "a", encoding="utf-8") as f:
                    f.write(json.dumps(dash_data, ensure_ascii=False) + "\n")

                if self.driver:
                    ok = Neo4jLoader.execute(self.driver, incident)
                    if ok:
                        logger.info("Pushed Incident %s to Neo4j.", incident.get('incident_id'))
                    else:
                        Neo4jLoader.export_cypher(incident)
                else:
                    Neo4jLoader.export_cypher(incident)
                    logger.info("(MOCK) Incident %s -> incident_graph_queries.cypher", incident.get('incident_id'))

                self.action_queue.task_done()
            except queue.Empty:
                pass
            except Exception:
                pass

    def start(self):
        self.connect()
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._process_queue, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        if self.driver:
            self.driver.close()
