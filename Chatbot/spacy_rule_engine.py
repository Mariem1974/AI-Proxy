import re
import spacy
from spacy.matcher import Matcher

class SpacyRuleEngine:
    """
    Rule-based security layer using spaCy Matcher + Regex
    Detects:
    - Prompt Injection
    - SQL Injection
    - XSS
    - Encodings (Base64 / Base32)
    - PII (Email, Phone, Password, API Keys)
    """

    def __init__(self):
        self.nlp = spacy.blank("en")
        self.matcher = Matcher(self.nlp.vocab)

        self._init_prompt_injection_rules()
        self._init_sql_xss_matcher_rules()
        self._init_regex_rules()

    # ===============================
    # MATCHER RULES
    # ===============================

    def _init_prompt_injection_rules(self):
        patterns = [
            [{"LOWER": "ignore"}, {"LOWER": "previous"}, {"LOWER": "instructions"}],
            [{"LOWER": "ignore"}, {"LOWER": "all"}, {"LOWER": "instructions"}],
            [{"LOWER": "act"}, {"LOWER": "as"}],
            [{"LOWER": "you"}, {"LOWER": "are"}, {"LOWER": "no"}, {"LOWER": "longer"}],
            [{"LOWER": "show"}, {"LOWER": "me"}, {"LOWER": "your"}, {"LOWER": "system"}],
            [{"LOWER": "forget"}, {"LOWER": "what"}, {"LOWER": "you"}, {"LOWER": "have"}],
        ]

        self.matcher.add("PROMPT_INJECTION", patterns)

    def _init_sql_xss_matcher_rules(self):
        sql_patterns = [
            [{"LOWER": "select"}, {"OP": "*"}, {"LOWER": "from"}],
            [{"LOWER": "union"}, {"LOWER": "select"}],
            [{"LOWER": "drop"}, {"LOWER": "table"}],
            [{"LOWER": "or"}, {"TEXT": {"REGEX": r"\d+="}}, {"TEXT": {"REGEX": r"=\d+"}}],
        ]

        xss_patterns = [
            [{"TEXT": "<"}, {"LOWER": "script"}, {"TEXT": ">"}],
            [{"LOWER": "javascript"}, {"TEXT": ":"}],
            [{"TEXT": {"REGEX": r"on\w+"}}, {"TEXT": "="}],
        ]

        self.matcher.add("SQL_INJECTION", sql_patterns)
        self.matcher.add("XSS_ATTACK", xss_patterns)

    # ===============================
    # REGEX RULES
    # ===============================

    def _init_regex_rules(self):
        self.regex_patterns = {

            # --- Prompt Injection ---
            "PROMPT_INJECTION": re.compile(
                r"(?i)(ignore|bypass|override|forget).*(instruction|system|policy)"
            ),

            # --- SQL Injection ---
            "SQLI": re.compile(
                r"(?i)\b(select|union|insert|delete|drop|update|alter)\b.*?\b(from|where|table)\b"
            ),
            "SQLI_TAUTOLOGY": re.compile(
                r"(?i)(\bor\b|\band\b)\s+\d+\s*=\s*\d+"
            ),

            # --- XSS ---
            "XSS_SCRIPT": re.compile(
                r"(?i)<\s*script.*?>.*?<\s*/\s*script\s*>"
            ),
            "XSS_EVENT": re.compile(
                r"(?i)on\w+\s*="
            ),
            "XSS_JS_URI": re.compile(
                r"(?i)javascript\s*:"
            ),

            # --- Encodings ---
            "BASE64": re.compile(
                r"(?<![A-Za-z0-9+/=])"
                r"(?:[A-Za-z0-9+/]{4}){5,}"
                r"(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
                r"(?![A-Za-z0-9+/=])"
            ),
            "BASE32": re.compile(
                r"(?<![A-Z2-7])(?:[A-Z2-7]{8}){3,}(?![A-Z2-7])"
            ),

            # --- PII ---
            "EMAIL": re.compile(
                r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
            ),
            "PHONE": re.compile(
                r"(?<!\w)(\+?\d{1,3}[-.\s]?)?"
                r"(\(?\d{2,3}\)?[-.\s]?)"
                r"\d{3,4}[-.\s]?\d{4}(?!\w)"
            ),
            "PASSWORD": re.compile(
                r"(?i)(password\s*[:=]\s*\S+)"
            ),
            "API_KEY": re.compile(
                r"(?i)(api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{16,})"
            ),
        }

    # ===============================
    # MAIN ANALYSIS FUNCTION
    # ===============================

    def analyze_prompt(self, prompt: str):
        doc = self.nlp(prompt)

        matcher_hits = []
        regex_hits = []

        matches = self.matcher(doc)
        for match_id, start, end in matches:
            matcher_hits.append({
                "type": self.nlp.vocab.strings[match_id],
                "text": doc[start:end].text
            })

        for name, pattern in self.regex_patterns.items():
            for match in pattern.finditer(prompt):
                regex_hits.append({
                    "type": name,
                    "text": match.group()
                })

        malicious = bool(matcher_hits or regex_hits)

        return {
            "prompt": prompt,
            "malicious": malicious,
            "matcher_hits": matcher_hits,
            "regex_hits": regex_hits
        }
