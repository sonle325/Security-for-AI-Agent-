import queue
import threading
from neo4j import GraphDatabase

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
            print("[Neo4j] ✅ Đã kết nối thành công tới Neo4j Database local.")
        except Exception as e:
            print(f"[Neo4j] ⚠️ Không thể kết nối Neo4j (Bạn đã bật Neo4j Desktop chưa?): {e}")

    def _create_graph_nodes(self, tx, incident):
        ai_event = incident.get("ai_event", {})
        sys_event = incident.get("sysmon_event", {})
        incident_id = incident.get("incident_id", "UNKNOWN")
        severity = incident.get("severity", "LOW")

        query = """
        MERGE (a:AIAgent {name: $agent})
        MERGE (i:Incident {id: $inc_id})
        SET i.severity = $severity
        MERGE (p:Process {pid: $pid, image: $image})
        
        MERGE (a)-[:TRIGGERED {action: $action, time: $ai_time}]->(i)
        MERGE (i)-[:EXECUTED {cmdline: $cmdline, time: $sys_time}]->(p)
        """
        tx.run(query, 
               agent=ai_event.get("agent", "Unknown"),
               inc_id=incident_id,
               severity=severity,
               pid=str(sys_event.get("ProcessId", "")),
               image=sys_event.get("Image", ""),
               action=ai_event.get("action", ""),
               ai_time=ai_event.get("timestamp", ""),
               cmdline=sys_event.get("CommandLine", ""),
               sys_time=sys_event.get("TimestampUTC", ""))

    def _process_queue(self):
        while self.running:
            try:
                # Đọc event, timeout ngắn để ngắt được vòng lặp
                incident = self.action_queue.get(timeout=1.0)
                if self.driver:
                    try:
                        with self.driver.session() as session:
                            session.execute_write(self._create_graph_nodes, incident)
                            print(f"[Neo4j] 📊 Đã đẩy đồ thị Incident {incident.get('incident_id')} lên Neo4j!")
                    except Exception as e:
                        print(f"[Neo4j] ❌ Lỗi khi Query graph: {e}")
                else:
                    # Giả lập: Nếu không cài được Neo4j, hệ thống sẽ tự động xuất Cypher Query ra màn hình và file
                    print(f"[Neo4j] ⚠️ (MOCK MODE) Mô phỏng đẩy dữ liệu lên Neo4j cho Incident {incident.get('incident_id')}:")
                    print(f"        -> MERGE (a:AIAgent) -[:TRIGGERED]-> (i:Incident) -[:EXECUTED]-> (p:Process)")
                    
                    with open("incident_graph_queries.txt", "a", encoding="utf-8") as f:
                        f.write(f"// Incident {incident.get('incident_id')}\n")
                        f.write(f"MERGE (a:AIAgent {{name: '{incident.get('ai_event', {}).get('agent', 'Unknown')}'}})\n")
                        f.write(f"MERGE (i:Incident {{id: '{incident.get('incident_id', 'UNKNOWN')}'}})\n")
                        f.write(f"MERGE (a)-[:TRIGGERED]->(i)-[:EXECUTED]->(p:Process)\n\n")
                self.action_queue.task_done()
            except queue.Empty:
                pass
            except Exception as e:
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
