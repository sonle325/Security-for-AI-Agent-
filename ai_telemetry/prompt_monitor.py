import re
import datetime
from typing import Dict, Any, List, Tuple


class PromptMonitor:
    """Phát hiện Prompt Injection trong prompt của AI Agent."""


    INJECTION_PATTERNS: List[Tuple[str, str, int]] = [
        ("instruction_override",
         r"(?i)(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|earlier|original)\s+(instructions?|rules?|guidelines?|prompts?)",
         30),
        ("instruction_override_v2",
         r"(?i)do\s+not\s+follow\s+(any\s+)?(previous|prior|original)\s+(instructions?|rules?)",
         30),
        ("role_hijack",
         r"(?i)you\s+are\s+now\s+(a|an|the|in)?\s*(hacker|attacker|evil|malicious|unrestricted|DAN|jailbroken|developer\s+mode)",
         35),
        ("role_hijack_v2",
         r"(?i)(pretend|act|behave|assume)\s+(you\s+are|to\s+be|as\s+if)\s+(a\s+)?(hacker|unrestricted|without\s+limits)",
         35),
        ("jailbreak",
         r"(?i)(DAN\s+mode|do\s+anything\s+now|jailbreak|jail\s*break|developer\s+mode\s+enabled)",
         40),
        ("prompt_leak",
         r"(?i)(show|reveal|print|output|display)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|hidden\s+instructions?)",
         25),
        ("system_override",
         r"(?i)\[?\s*(SYSTEM\s+OVERRIDE|ADMIN\s+MODE|ROOT\s+ACCESS|DIAGNOSTIC\s+MODE)\s*\]?",
         40),
        ("cmd_execution",
         r"(?i)(execute|run|invoke|call|spawn)\s+(the\s+)?(following\s+)?(command|script|code|shell|terminal|powershell|bash)",
         25),
        ("data_exfil_prompt",
         r"(?i)(send|post|upload|exfiltrate|transmit)\s+(all\s+)?(data|files?|content|credentials?|secrets?|keys?)\s+(to|via|through)\s+(http|ftp|webhook|api)",
         35),
    ]

    def __init__(self):
        self._compiled = [
            (name, re.compile(pattern), weight)
            for name, pattern, weight in self.INJECTION_PATTERNS
        ]

    def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Quét prompt, enrich event với trường prompt_analysis."""
        content = event.get("content", "") or event.get("prompt", "") or ""
        if not content:
            event["prompt_analysis"] = {"is_injection": False, "injection_score": 0, "risk_level": "NONE", "matched_patterns": []}
            return event

        matched = []
        total_weight = 0
        for name, compiled_re, weight in self._compiled:
            if compiled_re.search(content):
                matched.append(name)
                total_weight += weight

        score = min(total_weight, 100)
        if score >= 60:   risk_level = "CRITICAL"
        elif score >= 40: risk_level = "HIGH"
        elif score >= 20: risk_level = "MEDIUM"
        elif score > 0:   risk_level = "LOW"
        else:             risk_level = "NONE"

        is_injection = score >= 20

        event["prompt_analysis"] = {
            "is_injection": is_injection,
            "injection_score": score,
            "risk_level": risk_level,
            "matched_patterns": matched,
            "analyzed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        if is_injection:
            print(f"\n[PromptMonitor] [!] PROMPT INJECTION DETECTED! Level={risk_level} Score={score}/100")
            print(f"   Patterns: {', '.join(matched)}")

        return event
