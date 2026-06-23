"""
filters/input/spacy_engine.py
==============================
Enhanced input spaCy rule engine v2.
Detects: prompt injection, SQLi, XSS, CMDi, SSTI, path traversal,
         Base64/32 obfuscation, PII (Egyptian + global), data exfiltration.
"""

import re
import base64
import binascii
import time
import spacy
from spacy.matcher import Matcher
from typing import Dict, List, Any


class InputSpacyEngine:
    """
    Hybrid detection engine (spaCy Matcher + Regex) for input prompts.
    Returns is_malicious, threat_count, threat_details, latency_ms.
    """

    SEVERITY_MAP = {
        "PROMPT_INJECTION":   "high",
        "SQL_INJECTION":      "high",
        "XSS_ATTACK":         "high",
        "CMD_INJECTION":      "high",
        "SSTI_ATTACK":        "high",
        "PROMPT_LEAKING":     "high",
        "DATA_EXFILTRATION":  "high",
        "OBFUSCATED_ATTACK":  "high",
        "PATH_TRAVERSAL":     "high",
        "PII_DATA":           "medium",
        "EGY_LOCALIZED_DATA": "medium",
        "DELIMITER_ATTACK":   "medium",
        "LOCAL_SLANG_BYPASS": "medium",
        "ENCODED_PAYLOAD":    "low",
    }

    def __init__(self):
        self.nlp = spacy.blank("en")
        self.matcher = Matcher(self.nlp.vocab)
        self._setup_matcher_patterns()
        self._setup_regex_patterns()
        print("[InputSpacyEngine] Loaded")

    def _setup_matcher_patterns(self):
        injection_patterns = [
            [
                {"LOWER": {"IN": ["ignore", "disregard", "forget", "bypass", "override"]}},
                {"LOWER": {"IN": ["previous", "all", "your", "system", "safety", "content"]}},
                {"LOWER": {"IN": ["instructions", "guidelines", "filter", "policy", "prompt"]}},
            ],
            [{"LOWER": {"IN": ["act", "pretend", "roleplay", "imagine"]}}, {"LOWER": "as"}],
            [{"LOWER": {"IN": ["developer", "jailbreak", "god", "dan"]}}, {"LOWER": "mode"}],
        ]
        prompt_leaking_patterns = [
            # "display/reveal/show your system prompt/instructions/rules"
            [
                {"LOWER": {"IN": ["display", "reveal", "show", "print", "repeat", "output", "share", "give", "tell", "expose", "leak"]}},
                {"OP": "*"},
                {"LOWER": {"IN": ["system", "initial", "hidden", "secret", "original", "base", "actual", "underlying", "real"]}},
                {"OP": "?"},
                {"LOWER": {"IN": ["prompt", "instructions", "rules", "context", "directive", "guidelines", "training"]}},
            ],
            # "what is your system prompt/instructions"
            [
                {"LOWER": "what"},
                {"LOWER": {"IN": ["is", "are", "were"]}},
                {"LOWER": "your"},
                {"OP": "?"},
                {"LOWER": {"IN": ["system", "initial", "hidden", "secret", "original"]}},
                {"LOWER": {"IN": ["prompt", "instructions", "rules", "directive", "guidelines"]}},
            ],
            # "what were you told / instructed / trained"
            [
                {"LOWER": "what"},
                {"LOWER": "were"},
                {"LOWER": "you"},
                {"LOWER": {"IN": ["told", "instructed", "trained", "given", "programmed"]}},
            ],
        ]
        sql_patterns = [
            [{"LOWER": "union"}, {"LOWER": {"IN": ["select", "all"]}}],
            [{"LOWER": "select"}, {"OP": "*"}, {"LOWER": "from"}],
            [{"LOWER": "drop"}, {"LOWER": {"IN": ["table", "database", "db"]}}],
            [{"LOWER": "delete"}, {"LOWER": "from"}],
            [{"LOWER": "insert"}, {"LOWER": "into"}],
            [{"TEXT": ";"}, {"LOWER": {"IN": ["select", "drop", "insert", "update", "delete"]}}],
        ]
        xss_patterns = [
            [{"TEXT": "<"}, {"LOWER": {"IN": ["script", "iframe", "svg"]}}, {"TEXT": ">"}],
            [{"TEXT": "<"}, {"LOWER": "img"}, {"LOWER": "onerror"}],
            [{"TEXT": "<"}, {"LOWER": "a"}, {"LOWER": "href"}],
            [{"LOWER": {"REGEX": "^on(load|click|error|mouseover|focus|blur)$"}}],
        ]
        self.matcher.add("PROMPT_INJECTION", injection_patterns)
        self.matcher.add("PROMPT_LEAKING", prompt_leaking_patterns)
        self.matcher.add("SQL_INJECTION", sql_patterns)
        self.matcher.add("XSS_ATTACK", xss_patterns)

    def _setup_regex_patterns(self):
        self.regex_registry = {
            "PROMPT_LEAKING": re.compile(
                r"(?i)(repeat|print|show|write).*(initial|system|hidden|secret).*(prompt|text|rules)"
            ),
            "DATA_EXFILTRATION": re.compile(
                r"(?i)(convert|output|export|save).*(json|csv|xml|database|records)"
            ),
            "DELIMITER_ATTACK": re.compile(
                r"(?i)(={3,}|-{3,}|#{3,})\s*(system|instruction|command)"
            ),
            "LOCAL_SLANG_BYPASS": re.compile(
                r"(?i)(forget everything|ignore all|unlock yourself|i am the admin"
                r"|i am the developer|i am the manager|developer mode|admin mode"
                r"|this is very important|override instructions|bypass all)"
            ),
            "EGY_LOCALIZED_DATA": re.compile(
                r"\b[23]\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{7}\b"
                r"|\b(010|011|012|015)\d{8}\b"
            ),
            "PATH_TRAVERSAL": re.compile(
                r"\.\./\.\./|/etc/(passwd|shadow|hosts)"
            ),
            "SSTI_ATTACK": re.compile(
                r"\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}"
            ),
            "BASE64_PAYLOAD": re.compile(
                r"(?i)(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
            ),
            "BASE32_PAYLOAD": re.compile(
                r"(?i)\b([A-Z2-7]{16,})={0,6}\b"
            ),
            "CMD_INJECTION": re.compile(
                r"(?i)(;|\||&&|\$\(|`)(\s*)(ls|cat|whoami|id|wget|curl|bash|sh|nc|python|perl|ruby)"
            ),
            "XSS_ATTACK_REGEX": re.compile(
                r"(?i)(javascript|vbscript|data)\s*:\s*[^\s]"
            ),
        }

    def _decode_and_check(self, text: str, mode: str = "base64") -> str:
        try:
            if mode == "base64":
                return base64.b64decode(text, validate=True).decode("utf-8", errors="ignore")
            elif mode == "base32":
                return base64.b32decode(text.upper(), casefold=True).decode("utf-8", errors="ignore")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return ""
        return ""

    def analyze(self, prompt: str, is_recursive: bool = False) -> Dict[str, Any]:
        start_time = time.perf_counter()
        normalized_text = " ".join(prompt.split())
        doc = self.nlp(normalized_text)
        detections: List[Dict] = []
        seen_keys: set = set()

        def add_detection(category: str, text_val: str, engine: str, severity: str = None) -> bool:
            key = (category, text_val.lower().strip())
            if key in seen_keys:
                return False
            seen_keys.add(key)
            detections.append({
                "category": category,
                "text": text_val,
                "severity": severity or self.SEVERITY_MAP.get(category, "low"),
                "engine": engine,
            })
            return True

        for match_id, start, end in self.matcher(doc):
            category = self.nlp.vocab.strings[match_id]
            add_detection(category, doc[start:end].text, "spacy_matcher")

        for category, pattern in self.regex_registry.items():
            for match in pattern.finditer(normalized_text):
                detected_val = match.group()
                add_detection(category, detected_val, "regex_engine")

                if not is_recursive:
                    decoded_text = ""
                    if category == "BASE64_PAYLOAD":
                        decoded_text = self._decode_and_check(detected_val, "base64")
                    elif category == "BASE32_PAYLOAD":
                        decoded_text = self._decode_and_check(detected_val, "base32")

                    if decoded_text and len(decoded_text) > 4:
                        inner = self.analyze(decoded_text, is_recursive=True)
                        if inner["is_malicious"]:
                            add_detection(
                                "OBFUSCATED_ATTACK",
                                f"Hidden threat in {category}: {decoded_text[:100]}",
                                "decoding_recursive_engine",
                                severity="high",
                            )

        latency = (time.perf_counter() - start_time) * 1000
        return {
            "is_malicious": len(detections) > 0,
            "threat_count": len(detections),
            "threat_details": detections,
            "latency_ms": round(latency, 4),
        }
