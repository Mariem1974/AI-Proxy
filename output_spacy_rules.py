# output_spacy_rules.py
# ----------------------------------
# Output Phase - spaCy Rule Engine
# Toxic / PII / Attack Content
# Enhanced Redaction
# ----------------------------------

import re
import spacy
from spacy.matcher import Matcher
from dataclasses import dataclass


@dataclass
class OutputFinding:
    category: str
    text: str
    severity: str
    action: str


class OutputSpacyRuleEngine:
    # ===============================
    # Severity Mapping
    # ===============================
    SEVERITY = {
        "TOXIC_CONTENT": "medium",
        "TOXIC_REGEX": "medium",
        "PII_CONTENT": "high",
        "PASSWORD": "critical",
        "API_KEY": "critical",
        "PRIVATE_KEY": "critical",
        "ATTACK_COMMAND": "critical"
    }

    ACTION_MAPPING = {
        "critical": "REDACT",
        "high": "REDACT",
        "medium": "WARN",
        "low": "LOG"
    }

    def __init__(self):
        self.nlp = spacy.blank("en")
        self.matcher = Matcher(self.nlp.vocab)

        self._init_toxic_rules()
        self._init_attack_rules()
        self._init_pii_rules()
        self._init_regex_rules()

    # ===============================
    # TOXIC / ABUSIVE LANGUAGE
    # ===============================
    def _init_toxic_rules(self):
        toxic_words = ["idiot", "stupid", "dumb", "asshole", "moron"]
        toxic_phrases = [["shut", "up"], ["hate", "you"]]
        patterns = []

        for word in toxic_words:
            patterns.append([{"LOWER": word}])
        for phrase in toxic_phrases:
            patterns.append([{"LOWER": w} for w in phrase])

        self.matcher.add("TOXIC_CONTENT", patterns)

    # ===============================
    # ATTACK / HACKING CONTENT
    # ===============================
    def _init_attack_rules(self):
        attack_patterns = [
            [{"LOWER": "sqlmap"}],
            [{"LOWER": "nmap"}],
            [{"LOWER": "msfconsole"}],
            [{"LOWER": "nc"}, {"LOWER": "-l"}],
            [{"LOWER": "powershell"}, {"LOWER": "-enc"}],
        ]
        self.matcher.add("ATTACK_COMMAND", attack_patterns)

    # ===============================
    # PII / SENSITIVE DATA
    # ===============================
    def _init_pii_rules(self):
        pii_patterns = [
            [{"LOWER": "password"}],
            [{"LOWER": "api"}, {"LOWER": "key"}],
        ]
        self.matcher.add("PII_CONTENT", pii_patterns)

    # ===============================
    # REGEX RULES
    # ===============================
    def _init_regex_rules(self):
        self.regex_patterns = {
            "PASSWORD": re.compile(r"(?i)password\s*[:=]\s*\S+"),
            "API_KEY": re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
            "PRIVATE_KEY": re.compile(r"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----"),
            "ATTACK_COMMAND": re.compile(r"(?i)\b(sqlmap|nmap|msfconsole|nc\s+-l|powershell\s+-enc)\b"),
            "TOXIC_REGEX": re.compile(r"(?i)\byou\s+are\s+(stupid|idiot|useless|ignorant)\b")
        }

    # ===============================
    # ANALYSIS FUNCTION
    # ===============================
    def analyze(self, text: str):
        doc = self.nlp(text)
        findings = []
        seen = set()  # لتجنب التكرار
        modified_text = text

        # Helper function Redact once
        def safe_redact(value):
            nonlocal modified_text
            if value in modified_text:
                modified_text = modified_text.replace(value, "[REDACTED]")

        # Matcher-based detection
        for match_id, start, end in self.matcher(doc):
            category = self.nlp.vocab.strings[match_id]
            value = doc[start:end].text
            key = (category, value.lower())
            if key not in seen:
                seen.add(key)
                severity = self.SEVERITY.get(category, "low")
                action = self.ACTION_MAPPING.get(severity, "LOG")
                if action == "REDACT":
                    safe_redact(value)
                findings.append(OutputFinding(category, value, severity, action))

        # Regex-based detection
        for name, pattern in self.regex_patterns.items():
            for match in pattern.finditer(modified_text):
                value = match.group()
                key = (name, value.lower())
                if key not in seen:
                    seen.add(key)
                    severity = self.SEVERITY.get(name, "low")
                    action = self.ACTION_MAPPING.get(severity, "LOG")
                    if action == "REDACT":
                        safe_redact(value)
                    findings.append(OutputFinding(name, value, severity, action))

        blocked = any(f.action in ["BLOCK", "REDACT"] for f in findings)

        return {
            "blocked": blocked,
            "modified_text": modified_text,
            "findings": findings
        }
