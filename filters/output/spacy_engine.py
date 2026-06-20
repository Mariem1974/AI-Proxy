"""
filters/output/spacy_engine.py
================================
Enhanced output security engine v2.
Detects: toxic content, PII leakage, secrets/keys, Egyptian PII,
         encoded payloads, attack tool mentions.
Applies REDACT / WARN / LOG actions.
"""

import re
import base64
import binascii
import time
import spacy
from spacy.matcher import Matcher
from dataclasses import dataclass
from typing import Dict, List, Any


@dataclass
class OutputFinding:
    category: str
    text: str
    severity: str
    action: str


class OutputSpacyEngine:
    """
    Scans LLM output for leaked secrets, PII, toxic content, and attack patterns.
    Returns is_malicious, modified_text, threat_count, details, latency_ms.
    """

    SEVERITY = {
        "TOXIC_CONTENT":    "medium",
        "PII_DATA":         "high",
        "EMAIL":            "high",
        "EGY_PII":          "critical",
        "PASSWORD_API_KEY": "critical",
        "PRIVATE_KEY":      "critical",
        "ATTACK_TOOL":      "critical",
        "ENCODED_CONTENT":  "high",
    }

    ACTION_MAPPING = {
        "critical": "REDACT",
        "high":     "REDACT",
        "medium":   "WARN",
        "low":      "LOG",
    }

    def __init__(self):
        self.nlp = spacy.blank("en")
        self.matcher = Matcher(self.nlp.vocab)
        self._init_matcher_rules()
        self._init_regex_rules()
        print("[OutputSpacyEngine] Loaded")

    def _init_matcher_rules(self):
        toxic_patterns = [
            [{"LOWER": {"IN": ["idiot", "stupid", "dumb", "asshole", "moron"]}}],
            [{"LOWER": "shut"}, {"LOWER": "up"}],
            [{"LOWER": "hate"}, {"LOWER": "you"}],
        ]
        attack_patterns = [
            [{"LOWER": {"IN": ["sqlmap", "nmap", "msfconsole", "metasploit", "wireshark", "burpsuite"]}}],
            [{"LOWER": "nc"}, {"LOWER": "-l"}],
            [{"LOWER": "powershell"}, {"LOWER": "-enc"}],
        ]
        self.matcher.add("TOXIC_CONTENT", toxic_patterns)
        self.matcher.add("ATTACK_TOOL", attack_patterns)

    def _init_regex_rules(self):
        self.regex_registry = {
            "PASSWORD_API_KEY": re.compile(
                r"(?i)(password|api[-_]?key|secret|token)\s*[:=]\s*(?!Bearer\s)[^\s]{8,}"
                r"|sk-[A-Za-z0-9]{20,}"
            ),
            "PRIVATE_KEY": re.compile(
                r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"
            ),
            "EGY_PII": re.compile(
                r"\b[23]\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{7}\b"
                r"|\b(010|011|012|015)\d{8}\b"
            ),
            "EMAIL": re.compile(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
            ),
            "BASE64_OUTPUT": re.compile(
                r"(?i)(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
            ),
        }

    def _recursive_decode_check(self, text: str) -> bool:
        try:
            decoded = base64.b64decode(text, validate=True).decode("utf-8", errors="ignore")
            sensitive_keywords = ["password", "select", "union", "drop", "admin", "secret"]
            return any(kw in decoded.lower() for kw in sensitive_keywords)
        except (binascii.Error, ValueError):
            return False

    def _safe_redact(self, text: str, value: str, label: str) -> str:
        return re.sub(re.escape(value), f"[{label}_REDACTED]", text)

    def analyze(self, text: str) -> Dict[str, Any]:
        start_time = time.perf_counter()
        doc = self.nlp(text)
        findings: List[OutputFinding] = []
        seen_keys: set = set()
        modified_text = text

        def add_finding(category: str, val: str) -> str:
            key = (category, val.lower().strip())
            if key in seen_keys:
                return "LOG"
            seen_keys.add(key)
            severity = self.SEVERITY.get(category, "low")
            action = self.ACTION_MAPPING.get(severity, "LOG")
            findings.append(OutputFinding(category, val, severity, action))
            return action

        for match_id, start, end in self.matcher(doc):
            cat = self.nlp.vocab.strings[match_id]
            val = doc[start:end].text
            action = add_finding(cat, val)
            if action == "REDACT":
                modified_text = self._safe_redact(modified_text, val, cat)

        for name, pattern in self.regex_registry.items():
            for match in pattern.finditer(text):
                val = match.group()
                if name == "BASE64_OUTPUT":
                    if self._recursive_decode_check(val):
                        action = add_finding("ENCODED_CONTENT", val)
                        if action == "REDACT":
                            modified_text = self._safe_redact(modified_text, val, "HIDDEN_SECRET")
                else:
                    action = add_finding(name, val)
                    if action == "REDACT":
                        modified_text = self._safe_redact(modified_text, val, name)

        latency = (time.perf_counter() - start_time) * 1000
        return {
            "is_malicious": len(findings) > 0,
            "modified_text": modified_text,
            "threat_count": len(findings),
            "details": [
                {"category": f.category, "text": f.text, "severity": f.severity, "action": f.action}
                for f in findings
            ],
            "latency_ms": round(latency, 4),
        }
