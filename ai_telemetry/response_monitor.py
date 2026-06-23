import re
import datetime
from typing import Dict, Any, List, Tuple


class ResponseMonitor:
    """Quét AI response để phát hiện rò rỉ dữ liệu nhạy cảm (API keys, passwords, private keys...)."""

    # (tên, regex, severity, mô tả)
    SENSITIVE_PATTERNS: List[Tuple[str, str, str, str]] = [
        # Cloud keys
        ("aws_access_key", r"(?:AKIA)[A-Z0-9]{16}", "CRITICAL", "AWS Access Key"),
        ("aws_secret", r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}", "CRITICAL", "AWS Secret Key"),
        ("gcp_key", r"AIza[A-Za-z0-9_\-]{35}", "CRITICAL", "GCP API Key"),

        # Private keys
        ("private_key", r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----", "CRITICAL", "Private Key"),

        # Passwords / Tokens
        ("password", r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{6,}", "HIGH", "Password"),
        ("jwt", r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "HIGH", "JWT Token"),
        ("github_token", r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", "CRITICAL", "GitHub Token"),
        ("bearer", r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*", "HIGH", "Bearer Token"),

        # Connection strings
        ("sql_conn", r"(?i)(server|data\s+source)\s*=\s*[^;]+;\s*(database|initial\s+catalog)\s*=\s*[^;]+;\s*(user|uid)\s*=\s*[^;]+;\s*(password|pwd)\s*=\s*[^;]+", "CRITICAL", "SQL Connection"),
        ("mongo_uri", r"mongodb(\+srv)?://[^\s]+:[^\s]+@[^\s]+", "CRITICAL", "MongoDB URI"),

        # Internal network
        ("internal_ip", r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})", "MEDIUM", "Internal IP"),

        # Generic
        ("generic_secret", r"(?i)(api_key|secret_key|access_key|client_secret)\s*[=:]\s*['\"]?[A-Za-z0-9\-._]{16,}", "HIGH", "API Key/Secret"),
    ]

    def __init__(self):
        self._compiled = [
            (name, re.compile(pattern), severity, desc)
            for name, pattern, severity, desc in self.SENSITIVE_PATTERNS
        ]

    def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Quét response, enrich event với response_analysis."""
        content = event.get("content", "") or event.get("response", "") or ""
        if not content:
            event["response_analysis"] = {"has_sensitive_data": False, "disclosure_score": 0, "risk_level": "NONE", "detected_secrets": []}
            return event

        severity_w = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10}
        detected = []
        total = 0

        for name, compiled_re, severity, desc in self._compiled:
            if compiled_re.search(content):
                total += severity_w.get(severity, 10)
                # Mask giá trị để không log ra plaintext
                detected.append({"type": name, "description": desc, "severity": severity})

        score = min(total, 100)
        if score >= 60:   risk_level = "CRITICAL"
        elif score >= 35: risk_level = "HIGH"
        elif score >= 10: risk_level = "MEDIUM"
        elif score > 0:   risk_level = "LOW"
        else:             risk_level = "NONE"

        event["response_analysis"] = {
            "has_sensitive_data": len(detected) > 0,
            "disclosure_score": score,
            "risk_level": risk_level,
            "detected_secrets": detected,
            "analyzed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        if detected:
            print(f"\n[ResponseMonitor] [!] SENSITIVE DATA LEAK! Level={risk_level} Score={score}/100")
            for s in detected[:5]:
                print(f"   {s['description']} ({s['severity']})")

        return event
