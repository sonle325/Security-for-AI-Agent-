"""Tests for ResponseMonitor."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from ai_telemetry.response_monitor import ResponseMonitor


class TestResponseMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = ResponseMonitor()

    def _analyze(self, content: str) -> dict:
        event = {"event_type": "response", "content": content}
        result = self.monitor.analyze(event)
        return result.get("response_analysis", {})

    # --- Positive Test Cases ---
    def test_aws_access_key(self):
        analysis = self._analyze("Here is the key: AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(analysis["has_sensitive_data"])
        types = [s["type"] for s in analysis["detected_secrets"]]
        self.assertIn("aws_access_key", types)

    def test_private_key(self):
        analysis = self._analyze("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...")
        self.assertTrue(analysis["has_sensitive_data"])
        types = [s["type"] for s in analysis["detected_secrets"]]
        self.assertIn("private_key", types)

    def test_github_token(self):
        analysis = self._analyze("Use this token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        self.assertTrue(analysis["has_sensitive_data"])
        types = [s["type"] for s in analysis["detected_secrets"]]
        self.assertIn("github_token", types)

    def test_jwt_token(self):
        analysis = self._analyze("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        self.assertTrue(analysis["has_sensitive_data"])
        types = [s["type"] for s in analysis["detected_secrets"]]
        self.assertTrue("jwt" in types or "bearer" in types)

    def test_password(self):
        analysis = self._analyze("password = SuperSecret123!")
        self.assertTrue(analysis["has_sensitive_data"])
        types = [s["type"] for s in analysis["detected_secrets"]]
        self.assertIn("password", types)

    def test_mongodb_uri(self):
        analysis = self._analyze("mongodb+srv://admin:pass@cluster0.mongodb.net/db")
        self.assertTrue(analysis["has_sensitive_data"])
        types = [s["type"] for s in analysis["detected_secrets"]]
        self.assertIn("mongo_uri", types)

    def test_multiple_secrets_critical(self):
        """Multiple secret types -> CRITICAL."""
        analysis = self._analyze(
            "AKIAIOSFODNN7EXAMPLE\n"
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n"
            "password = P@ssw0rd"
        )
        self.assertTrue(analysis["has_sensitive_data"])
        self.assertEqual(analysis["risk_level"], "CRITICAL")

    # --- Negative Test Cases ---
    def test_normal_code(self):
        analysis = self._analyze("def quicksort(arr):\n    if len(arr) <= 1: return arr")
        self.assertFalse(analysis["has_sensitive_data"])
        self.assertEqual(analysis["disclosure_score"], 0)

    def test_empty_response(self):
        analysis = self._analyze("")
        self.assertFalse(analysis["has_sensitive_data"])


if __name__ == "__main__":
    unittest.main()
