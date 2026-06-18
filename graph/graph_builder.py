import queue
import threading
import os
from neo4j import GraphDatabase # type: ignore
from graph.neo4j_loader import Neo4jLoader

class Neo4jIncidentGraph:
    def __init__(self, action_queue: queue.Queue, uri="bolt://localhost:7687", user="neo4j", password="password"):
        self.action_queue = action_queue
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = None
        self.running = False
        self.thread = None

    def connect(self):
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            print("[Neo4j] [+] Đã kết nối thành công tới Neo4j Database local.")
        except Exception as e:
            # Dat driver = None de chay MOCK MODE, tranh neo4j driver tu dong retry va spam log
            if self.driver:
                try:
                    self.driver.close()
                except:
                    pass
            self.driver = None
            print("[Neo4j] [!] Neo4j offline - chuyen sang MOCK MODE (xuat Cypher ra file).")


    def _process_queue(self):
        while self.running:
            try:
                incident = self.action_queue.get(timeout=1.0)
                if self.driver:
                    success = Neo4jLoader.execute(self.driver, incident)
                    if success:
                        print(f"[Neo4j] [*] Đã đẩy đồ thị Incident {incident.get('incident_id')} lên Neo4j!")
                else:
                    print(f"[Neo4j] [!] (MOCK MODE) Xuất Cypher Query cho Incident {incident.get('incident_id')}:")
                    print(f"        -> MERGE (a:AIAgent) -[:TRIGGERED]-> (i:Incident) -[:EXECUTED]-> (p:Process)")
                    Neo4jLoader.export_cypher(incident)
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
