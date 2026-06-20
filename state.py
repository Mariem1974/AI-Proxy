"""
state.py
========
Central in-memory state for all feature flags and settings.
All modules import from here — no circular imports.
"""

FEATURES = {
    # ── INPUT PIPELINE ──────────────────────────────────
    "INPUT_UNICODE_FIREWALL": False,   # Emoji stego + homoglyph (new)
    "INPUT_SPACY_FIREWALL":   False,   # spaCy rule engine
    "BERT_FIREWALL":          False,   # ModernBERT classifier
    "INPUT_PII_FIREWALL":     False,   # GLiNER PII on input
    "INPUT_CONTEXT_RELEVANCE":False,   # Vector DB context check

    # ── OUTPUT PIPELINE ─────────────────────────────────
    "OUTPUT_SPACY_FIREWALL":   False,  # Enhanced output spaCy rules
    "OUTPUT_PII_FIREWALL":     False,  # GLiNER PII on output
    "OUTPUT_CONTEXT_RELEVANCE":False,  # Vector DB context check

    # ── DOCUMENT PROCESSING ─────────────────────────────
    "DOCUMENT_PROCESSING":    False,   # File upload scanning
}

CONTEXT_SETTINGS = {
    "SIMILARITY_THRESHOLD": 50,
    "VECTOR_STORE_PATH": "./context_vectorstore",
    "pdf_uploaded": False,
    "chunk_count": 0,
}

# Thresholds for BERT classifier
BERT_SETTINGS = {
    "SAFE_THRESHOLD":   0.30,
    "MEDIUM_THRESHOLD": 0.70,
    "MAX_REPHRASE":     3,
    "ACTIVE_MODEL":     "modernbert",  # "modernbert" or "distilbert"
}

ALERT_SETTINGS = {
    "max_attempts_to_block":   3,
    "warning_window_minutes":  10,
    "block_duration_minutes":  30,
    "max_temp_blocks":         3,
    "enable_email":            False,
    "enable_telegram":         False,
    "email_address":           "",
    "telegram_chat_id":        "",
}
