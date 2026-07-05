"""AI Runtime Security — EDR Engine entry point."""

import time
import queue
import threading
import logging
import sys
from collector.sysmon_listener import SysmonListener
from ai_telemetry.agent_logger import AITelemetrySimulator
from ai_telemetry.ipc_server import IPCTelemetryServer
from correlation.correlation_engine import CorrelationEngine
from detector.rule_engine import DetectionEngine
from detector.containment import ContainmentEngine
from graph.graph_builder import Neo4jIncidentGraph
from analyzer.nlp_classifier import AISecurityAnalyzer

from mcp_gateway.gateway import MCPSecurityGateway
from lsp_sniffer.lsp_interceptor import LSPProtocolInterceptor


def setup_logging():
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    fmt = logging.Formatter(
        "[%(name)s] %(message)s",
        datefmt="%H:%M:%S"
    )
    console.setFormatter(fmt)
    root_logger.addHandler(console)

    try:
        file_handler = logging.FileHandler("edr_engine.log", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(
            "%(asctime)s [%(name)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_fmt)
        root_logger.addHandler(file_handler)
    except Exception:
        pass


def main():
    setup_logging()
    logger = logging.getLogger("EDR.Main")

    logger.info("Initializing AI Runtime Security EDR...")

    sysmon_queue = queue.Queue(maxsize=1000)
    ai_event_queue = queue.Queue(maxsize=1000)
    incident_queue = queue.Queue(maxsize=1000)
    action_queue = queue.Queue(maxsize=1000)

    neo4j_queue = queue.Queue(maxsize=1000)
    nlp_queue = queue.Queue(maxsize=1000)
    containment_queue = queue.Queue(maxsize=1000)

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

    sysmon_listener = SysmonListener(sysmon_queue)
    ai_simulator = AITelemetrySimulator(ai_event_queue)
    ipc_server = IPCTelemetryServer(ai_event_queue)
    correlation_engine = CorrelationEngine(sysmon_queue, ai_event_queue, incident_queue)
    detection_engine = DetectionEngine(incident_queue, action_queue)
    containment_engine = ContainmentEngine(containment_queue)
    neo4j_graph = Neo4jIncidentGraph(neo4j_queue)
    nlp_analyzer = AISecurityAnalyzer(nlp_queue)

    mcp_gateway = MCPSecurityGateway(ai_event_queue)
    lsp_interceptor = LSPProtocolInterceptor(ai_event_queue)

    nlp_analyzer.start()
    neo4j_graph.start()
    containment_engine.start()
    detection_engine.start()
    correlation_engine.start()
    sysmon_listener.start()
    
    ipc_server.start()
    mcp_gateway.start()
    lsp_interceptor.start()

    logger.info("EDR Engine is now running.")
    logger.info("IPC Telemetry listening on \\\\.\\pipe\\ai_edr_telemetry and 127.0.0.1:9999")
    if mcp_gateway.enabled:
        logger.info("MCP Security Gateway proxy listening on 127.0.0.1:%d", mcp_gateway.listen_port)
    if lsp_interceptor.enabled:
        logger.info("LSP Protocol Interceptor listening on 127.0.0.1:%d", lsp_interceptor.listen_port)
    logger.info("Logs are being written to edr_engine.log")
    logger.info("Press [Ctrl+C] to exit.")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logger.info("Shutting down EDR Engine...")
        lsp_interceptor.stop()
        mcp_gateway.stop()
        ipc_server.stop()
        sysmon_listener.stop()
        correlation_engine.stop()
        detection_engine.stop()
        containment_engine.stop()
        neo4j_graph.stop()
        nlp_analyzer.stop()
        logger.info("Shutdown complete.")

if __name__ == "__main__":
    main()
