"""
state.py
========
Central in-memory state for all feature flags and settings.
All modules import from here — no circular imports.
"""

FEATURES = {
    # ── INPUT PIPELINE ──────────────────────────────────
    "INPUT_UNICODE_FIREWALL": True,    # Emoji stego + homoglyph — fast, zero false positives
    "INPUT_SPACY_FIREWALL":   True,    # spaCy rule engine — fast, catches injections/SQLi/XSS
    "BERT_FIREWALL":          False,   # ModernBERT — ML inference, admin opt-in
    "INPUT_PII_FIREWALL":     False,   # GLiNER PII — slower, admin opt-in
    "INPUT_CONTEXT_RELEVANCE":False,   # Requires PDF upload first

    # ── OUTPUT PIPELINE ─────────────────────────────────
    "OUTPUT_SPACY_FIREWALL":   True,   # Output rule engine — fast
    "OUTPUT_PII_FIREWALL":     False,  # Llama3.2 rewriter — slow, admin opt-in
    "OUTPUT_CONTEXT_RELEVANCE":False,  # Requires PDF upload first

    # ── DOCUMENT PROCESSING ─────────────────────────────
    "DOCUMENT_PROCESSING":    False,   # Admin opt-in
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
