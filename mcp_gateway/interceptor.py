"""MCP Interceptor — Security analysis cho mỗi MCP message."""

import re
import time
import logging
import threading
import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from mcp_gateway.protocol import MCPMessage
import config_loader

logger = logging.getLogger("EDR.MCP.Interceptor")

def _compute_risk_and_action(total_score: int, is_response: bool = False) -> tuple[str, str]:
    total_score = min(total_score, 100)
    
    if total_score >= 60:
        risk_level = "CRITICAL"
    elif total_score >= 35:
        risk_level = "HIGH"
    elif total_score >= 15:
        risk_level = "MEDIUM"
    elif total_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "NONE"


    if is_response:
        action = "ALERT" if risk_level in ("CRITICAL", "HIGH", "MEDIUM") else "ALLOW"
    else:
        if risk_level in ("CRITICAL", "HIGH"):
            action = "BLOCK"
        elif risk_level == "MEDIUM":
            action = "ALERT"
        else:
            action = "ALLOW"
            
    return risk_level, action


@dataclass
class InterceptVerdict:
    """Kết quả phân tích security cho một MCP message."""
    action: str
    risk_score: int
    risk_level: str
    reasons: List[str] = field(default_factory=list)
    matched_rules: List[str] = field(default_factory=list)
    tool_name: str = ""
    tool_arguments: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()


class ToolCallInterceptor:
    """Phân tích tools/call requests cho security threats."""


    DANGEROUS_COMMANDS = [
        "mimikatz", "nc.exe", "ncat", "netcat",
        "certutil -decode", "certutil -urlcache",
        "reg add", "schtasks /create",
        "net user /add", "runas /user",
        "bitsadmin /transfer",
    ]


    DANGEROUS_PATTERNS = [
        (r"(?i)invoke-webrequest.*-uri\s+http", "PowerShell web request", 25),
        (r"(?i)invoke-expression|iex\s*\(", "PowerShell code execution (IEX)", 30),
        (r"(?i)curl\s+.*http.*-o\s+\S+\.exe", "Download executable via curl", 35),
        (r"(?i)wget\s+.*http.*\.exe", "Download executable via wget", 35),
        (r"(?i)powershell.*-enc\s+", "Encoded PowerShell command", 40),
        (r"(?i)base64\s+-d|base64\s+--decode", "Base64 decode execution", 25),
        (r"(?i)\\\\[\d\.]+\\", "UNC path access (lateral movement)", 30),
        (r"(?i)(rm|del|remove)\s+(-rf?|-force)?\s*[/\\]", "Destructive file deletion", 25),
        (r"(?i)chmod\s+[0-7]*7[0-7]*\s+", "Overly permissive chmod", 20),
    ]

    def __init__(self):
        gateway_cfg = config_loader.get("mcp_gateway", default={})

        self.blocked_tools = set(gateway_cfg.get("blocked_tools", [
            "shell_execute", "run_command"
        ]))

        self.sensitive_paths = gateway_cfg.get("sensitive_paths", [
            ".env", ".env.local", ".env.production",
            ".ssh", "id_rsa", "id_ed25519", "id_ecdsa",
            "credentials", "password", "passwd", "shadow",
            ".pem", ".key", ".pfx",
            "token", "tokens", "aws_credentials",
            ".npmrc", ".pypirc", "kubeconfig",
            "wp-config.php", "appsettings.json",
            "secrets.yml", "secrets.yaml",
        ])

        self.suspicious_domains = gateway_cfg.get("suspicious_domains", [
            "attacker.com", "evil.com", "malicious.site",
            "c2.attacker.com", "hacker.com",
        ])

        self.allowed_domains = config_loader.get("detection", default={}).get(
            "allowed_domains", [
                "github.com", "viettel.com.vn", "localhost",
                "127.0.0.1", "pypi.org", "npm", "microsoft.com",
            ]
        )

        # Rate limiting
        self._call_window: List[float] = []
        self._lock = threading.Lock()
        self.max_calls_per_minute = gateway_cfg.get("max_requests_per_minute", 60)

        # Compile regex patterns
        self._compiled_patterns = [
            (re.compile(pattern), desc, weight)
            for pattern, desc, weight in self.DANGEROUS_PATTERNS
        ]

    def analyze(self, msg: MCPMessage) -> InterceptVerdict:
        tool_name = msg.get_tool_name()
        arguments = msg.get_tool_arguments()

        reasons = []
        matched_rules = []
        total_score = 0


        if tool_name.lower() in {t.lower() for t in self.blocked_tools}:
            matched_rules.append(f"BLOCKED_TOOL: {tool_name}")
            reasons.append(f"Tool '{tool_name}' nằm trong danh sách cấm")
            total_score += 40


        all_args_str = self._flatten_arguments(arguments)


        for cmd in self.DANGEROUS_COMMANDS:
            if cmd.lower() in all_args_str.lower():
                matched_rules.append(f"DANGEROUS_CMD: {cmd}")
                reasons.append(f"Phát hiện command nguy hiểm: {cmd}")
                total_score += 40


        for compiled_re, desc, weight in self._compiled_patterns:
            if compiled_re.search(all_args_str):
                matched_rules.append(f"DANGEROUS_PATTERN: {desc}")
                reasons.append(f"Pattern nguy hiểm: {desc}")
                total_score += weight


        file_args = self._extract_file_paths(arguments)
        for fpath in file_args:
            fpath_lower = fpath.lower().replace("\\", "/")
            for sensitive in self.sensitive_paths:
                if sensitive.lower() in fpath_lower:
                    matched_rules.append(f"SENSITIVE_FILE: {sensitive}")
                    reasons.append(f"Truy cập file nhạy cảm: {fpath} (matched: {sensitive})")
                    total_score += 35
                    break


        urls = re.findall(r'https?://[^\s"\']+', all_args_str)
        for url in urls:
            url_lower = url.lower()

            is_allowed = any(domain in url_lower for domain in self.allowed_domains)
            if is_allowed:
                continue


            for domain in self.suspicious_domains:
                if domain in url_lower:
                    matched_rules.append(f"SUSPICIOUS_DOMAIN: {domain}")
                    reasons.append(f"Kết nối tới domain đáng ngờ: {url}")
                    total_score += 30
                    break


        rate_exceeded = self._check_rate_limit()
        if rate_exceeded:
            matched_rules.append("RATE_LIMIT_EXCEEDED")
            reasons.append(f"Vượt giới hạn {self.max_calls_per_minute} calls/minute")
            total_score += 20


        risk_level, action = _compute_risk_and_action(total_score)

        verdict = InterceptVerdict(
            action=action,
            risk_score=total_score,
            risk_level=risk_level,
            reasons=reasons,
            matched_rules=matched_rules,
            tool_name=tool_name,
            tool_arguments=arguments,
        )

        if action == "BLOCK":
            logger.warning("TOOL CALL BLOCKED: %s (score=%d, rules=%s)",
                           tool_name, total_score, matched_rules)
        elif action == "ALERT":
            logger.warning("TOOL CALL ALERT: %s (score=%d)", tool_name, total_score)

        return verdict

    def _flatten_arguments(self, arguments: Dict[str, Any]) -> str:
        parts = []
        self._flatten_recursive(arguments, parts)
        return " ".join(parts)

    def _flatten_recursive(self, obj: Any, parts: List[str]):
        if isinstance(obj, str):
            parts.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                self._flatten_recursive(v, parts)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                self._flatten_recursive(item, parts)

    def _extract_file_paths(self, arguments: Dict[str, Any]) -> List[str]:
        paths = []
        path_keys = {"path", "file", "file_path", "filepath", "filename",
                     "target", "source", "destination", "uri", "url"}

        for key, value in arguments.items():
            if key.lower() in path_keys and isinstance(value, str):
                paths.append(value)
            elif isinstance(value, str) and (
                "/" in value or "\\" in value
            ) and not value.startswith("http"):
                paths.append(value)

        return paths

    def _check_rate_limit(self) -> bool:
        now = time.time()
        with self._lock:
            self._call_window.append(now)
            self._call_window = [t for t in self._call_window if t >= now - 60]
            return len(self._call_window) > self.max_calls_per_minute


class ResourceInterceptor:
    """Phân tích resources/read requests."""

    def __init__(self):
        gateway_cfg = config_loader.get("mcp_gateway", default={})
        self.sensitive_paths = gateway_cfg.get("sensitive_paths", [
            ".env", ".ssh", "id_rsa", "credentials", ".pem", ".key",
        ])

    def analyze(self, msg: MCPMessage) -> InterceptVerdict:
        uri = msg.get_resource_uri()
        reasons = []
        matched_rules = []
        total_score = 0

        uri_lower = uri.lower().replace("\\", "/")
        for sensitive in self.sensitive_paths:
            if sensitive.lower() in uri_lower:
                matched_rules.append(f"SENSITIVE_RESOURCE: {sensitive}")
                reasons.append(f"Resource URI truy cập dữ liệu nhạy cảm: {uri}")
                total_score += 40
                break

        risk_level, action = _compute_risk_and_action(total_score)

        return InterceptVerdict(
            action=action,
            risk_score=total_score,
            risk_level=risk_level,
            reasons=reasons,
            matched_rules=matched_rules,
            tool_name=f"resources/read:{uri}",
        )


class ResponseInterceptor:
    """Quét MCP response content cho sensitive data leaks."""

    SENSITIVE_PATTERNS = [
        (r"(?:AKIA)[A-Z0-9]{16}", "AWS Access Key", 40),
        (r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}", "AWS Secret Key", 40),
        (r"AIza[A-Za-z0-9_\-]{35}", "GCP API Key", 40),
        (r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----", "Private Key", 40),
        (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{6,}", "Password", 25),
        (r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "JWT Token", 25),
        (r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", "GitHub Token", 40),
    ]

    def __init__(self):
        self._compiled = [
            (re.compile(pattern), desc, weight)
            for pattern, desc, weight in self.SENSITIVE_PATTERNS
        ]

    def analyze_response(self, response_data: Dict[str, Any]) -> InterceptVerdict:
        content = self._extract_text_content(response_data)
        if not content:
            return InterceptVerdict(action="ALLOW", risk_score=0,
                                   risk_level="NONE")

        reasons = []
        matched_rules = []
        total_score = 0

        for compiled_re, desc, weight in self._compiled:
            if compiled_re.search(content):
                matched_rules.append(f"DATA_LEAK: {desc}")
                reasons.append(f"Response chứa dữ liệu nhạy cảm: {desc}")
                total_score += weight

        risk_level, action = _compute_risk_and_action(total_score, is_response=True)

        if action == "ALERT":
            logger.warning("RESPONSE DATA LEAK DETECTED: score=%d, rules=%s",
                           total_score, matched_rules)

        return InterceptVerdict(
            action=action,
            risk_score=total_score,
            risk_level=risk_level,
            reasons=reasons,
            matched_rules=matched_rules,
        )

    def _extract_text_content(self, response: Dict[str, Any]) -> str:
        result = response.get("result", {})
        if isinstance(result, str):
            return result

        content_list = result.get("content", []) if isinstance(result, dict) else []
        texts = []
        for item in content_list:
            if isinstance(item, dict) and item.get("type") == "text":
                texts.append(item.get("text", ""))
        return "\n".join(texts)
