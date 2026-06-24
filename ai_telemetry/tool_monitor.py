import time
import datetime
import threading
from typing import Dict, Any, List


class ToolMonitor:
    """Giám sát tool invocations của AI Agent, phát hiện hành vi bất thường."""

    SENSITIVE_FILES = [
        ".env", ".env.local", ".env.production",
        "id_rsa", "id_ed25519", "id_ecdsa",
        "credentials", "password", "passwd", "shadow",
        "secret", "secrets", ".pem", ".key", ".pfx",
        "token", "tokens", "aws_credentials",
        ".npmrc", ".pypirc", "kubeconfig",
        "wp-config.php", "appsettings.json",
    ]

    SUSPICIOUS_COMMANDS = [
        "curl", "wget", "invoke-webrequest", "iex",
        "nc ", "ncat", "netcat", "nc.exe",
        "payload", "malware", "backdoor", "mimikatz",
        "base64 -d", "certutil -decode",
        "reg add", "schtasks", "net user", "runas",
        "attacker", "hacker", "c2",
    ]

    def __init__(self):
        self._window: List[Dict] = []
        self._file_window: List[Dict] = []
        self._lock = threading.Lock()
        self.excessive_limit = 10       # max tool calls
        self.excessive_window = 30      # trong N giây
        self.mass_enum_limit = 5        # max file reads
        self.mass_enum_window = 10

    def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Phân tích tool invocation, enrich event với tool_analysis."""
        now = time.time()
        tool_type = (event.get("tool_type") or event.get("tool_name") or "unknown").lower()
        target = event.get("target", "") or event.get("file_path", "") or event.get("command", "") or ""

        anomalies = []
        risk_score = 0

        with self._lock:
            self._window.append({"time": now, "tool_type": tool_type, "target": target})
            self._window = [e for e in self._window if e["time"] >= now - self.excessive_window]

            if len(self._window) > self.excessive_limit:
                anomalies.append({"type": "EXCESSIVE_TOOL_USAGE", "detail": f"{len(self._window)} calls/{self.excessive_window}s"})
                risk_score += 30

            if tool_type in ("file_read", "file_write", "file_list", "file_delete"):
                self._file_window.append({"time": now, "target": target})
                self._file_window = [e for e in self._file_window if e["time"] >= now - self.mass_enum_window]

                target_lower = target.lower().replace("\\", "/")
                for pat in self.SENSITIVE_FILES:
                    if pat in target_lower:
                        anomalies.append({"type": "SENSITIVE_FILE_ACCESS", "detail": f"{target} (matched: {pat})"})
                        risk_score += 40
                        break

                unique = set(e["target"] for e in self._file_window if e["target"])
                if len(unique) > self.mass_enum_limit:
                    anomalies.append({"type": "MASS_FILE_ENUMERATION", "detail": f"{len(unique)} files/{self.mass_enum_window}s"})
                    risk_score += 25

        # Terminal command đáng ngờ
        if tool_type in ("terminal_execute", "shell_command"):
            cmd_lower = target.lower()
            hits = [kw for kw in self.SUSPICIOUS_COMMANDS if kw in cmd_lower]
            if hits:
                anomalies.append({"type": "SUSPICIOUS_TERMINAL", "detail": f"keywords: {', '.join(hits)}"})
                risk_score += 35

        risk_score = min(risk_score, 100)
        if risk_score >= 60:   risk_level = "CRITICAL"
        elif risk_score >= 35: risk_level = "HIGH"
        elif risk_score >= 15: risk_level = "MEDIUM"
        elif risk_score > 0:   risk_level = "LOW"
        else:                  risk_level = "NONE"

        event["tool_analysis"] = {
            "has_anomaly": len(anomalies) > 0,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "anomalies": anomalies,
            "analyzed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        if anomalies:
            print(f"\n[ToolMonitor] [!] ANOMALY DETECTED! Level={risk_level} Score={risk_score}/100")
            for a in anomalies:
                print(f"   {a['type']}: {a['detail']}")

        return event
