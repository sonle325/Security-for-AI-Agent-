import queue
import threading
from neo4j import GraphDatabase  # type: ignore
from graph.neo4j_loader import Neo4jLoader
from graph.dashboard import IncidentDashboard, push_incident


class Neo4jIncidentGraph:
    def __init__(self, action_queue: queue.Queue,
                 uri="bolt://localhost:7687", user="neo4j", password="password",
                 dashboard_port=8888):
        self.action_queue = action_queue
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = None
        self.running = False
        self.thread = None
        self.dashboard = IncidentDashboard(port=dashboard_port)

    def connect(self):
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            print("[Neo4j] Kết nối thành công tới Neo4j.")
        except Exception:
            if self.driver:
                try:
                    self.driver.close()
                except:
                    pass
            self.driver = None
            print("[Neo4j] Neo4j offline — chạy MOCK MODE (xuất .cypher + Dashboard).")

    def _process_queue(self):
        while self.running:
            try:
                incident = self.action_queue.get(timeout=1.0)

                # Push vào Dashboard (luôn chạy, dù online hay offline)
                push_incident(incident)

                if self.driver:
                    success = Neo4jLoader.execute(self.driver, incident)
                    if success:
                        print(f"[Neo4j] Đã đẩy Incident {incident.get('incident_id')} lên Neo4j.")
                    else:
                        Neo4jLoader.export_cypher(incident)
                else:
                    Neo4jLoader.export_cypher(incident)
                    print(f"[Neo4j] (MOCK) Incident {incident.get('incident_id')} → incident_graph_queries.cypher")

                self.action_queue.task_done()
            except queue.Empty:
                pass
            except Exception:
                pass

    def start(self):
        self.connect()
        self.dashboard.start()
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
        self.dashboard.stop()
