import time
import queue
import threading
from collector.sysmon_listener import SysmonListener
from ai_telemetry.agent_logger import AITelemetrySimulator
from correlation.correlation_engine import CorrelationEngine
from detection.risk_engine import DetectionEngine
from response.containment import ContainmentEngine
from investigation.neo4j_builder import Neo4jIncidentGraph
from ai_analyzer.nlp_pipeline import AISecurityAnalyzer

def main():
    print("=== AI Runtime Threat Detection & Response Platform ===")
    print("[*] Starting All 8 Phases: Sysmon + Telemetry + Correlation + Detection + Containment + Neo4j + NLP")
    
    # Setup queues
    sysmon_queue = queue.Queue()
    ai_event_queue = queue.Queue()
    incident_queue = queue.Queue()
    action_queue = queue.Queue()
    
    # Multiplex queue cho các module phía sau
    # Do queue chuẩn trong Python bị tiêu thụ 1 lần, ta tạo 1 queue trung gian rồi clone ra 3 queue
    neo4j_queue = queue.Queue()
    nlp_queue = queue.Queue()
    containment_queue = queue.Queue()
    
    def action_dispatcher():
        while True:
            try:
                incident = action_queue.get()
                containment_queue.put(incident)
                neo4j_queue.put(incident)
                nlp_queue.put(incident)
                action_queue.task_done()
            except Exception:
                pass

    threading.Thread(target=action_dispatcher, daemon=True).start()
    
    # Initialize components
    sysmon_listener = SysmonListener(sysmon_queue)
    ai_simulator = AITelemetrySimulator(ai_event_queue)
    correlation_engine = CorrelationEngine(sysmon_queue, ai_event_queue, incident_queue)
    detection_engine = DetectionEngine(incident_queue, action_queue)
    containment_engine = ContainmentEngine(containment_queue)
    neo4j_graph = Neo4jIncidentGraph(neo4j_queue)
    nlp_analyzer = AISecurityAnalyzer(nlp_queue)
    
    # Start engines
    nlp_analyzer.start()
    neo4j_graph.start()
    containment_engine.start()
    detection_engine.start()
    correlation_engine.start()
    sysmon_listener.start()
    
    print("[*] EDR Engine is FULLY OPERATIONAL (8/8 Phases).")
    print("[*] Phím tắt: Bấm [Enter] để giả lập AI Agent gọi PowerShell.")
    print("[*] Bấm [Ctrl+C] để thoát.")
    
    def input_listener():
        while True:
            try:
                input() # Wait for Enter key
                ai_simulator.trigger_manual_event()
            except:
                break
                
    threading.Thread(target=input_listener, daemon=True).start()
    
    try:
        while True:
            time.sleep(1)
                
    except KeyboardInterrupt:
        print("\n[*] Shutting down EDR Engine...")
        sysmon_listener.stop()
        correlation_engine.stop()
        detection_engine.stop()
        containment_engine.stop()
        neo4j_graph.stop()
        nlp_analyzer.stop()
        print("[*] Shutdown complete.")

if __name__ == "__main__":
    main()
