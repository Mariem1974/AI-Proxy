"""
filters/input/bert_classifier.py
==================================
Classifier supporting both ModernBERT (new) and DistilBERT (legacy).
Active model is controlled by state.BERT_SETTINGS["ACTIVE_MODEL"].
"""

import os
import state

# ── Lazy-load the active model ────────────────────────────────────────────────
_modernbert_predict = None
_distilbert_predict = None


def _load_modernbert():
    global _modernbert_predict
    if _modernbert_predict is not None:
        return True
    model_dir = os.getenv("MODERNBERT_MODEL_DIR", "./models/modernbert")
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        import torch

        tokenizer = AutoTokenizer.from_pretrained(model_dir)
        model = AutoModelForSequenceClassification.from_pretrained(model_dir)
        model.eval()
        print(f"[ModernBERT] Loaded from {model_dir}")

        def _predict(prompt: str) -> float:
            encoded = tokenizer(
                prompt, return_tensors="pt",
                truncation=True, padding=True, max_length=512,
            )
            with torch.no_grad():
                logits = model(**encoded).logits
            probs = torch.nn.functional.softmax(logits, dim=-1).numpy()[0]
            return float(probs[1])

        _modernbert_predict = _predict
        return True
    except Exception as e:
        print(f"[ModernBERT] Failed to load: {e}")
        return False


def _load_distilbert():
    global _distilbert_predict
    if _distilbert_predict is not None:
        return True
    model_dir = os.getenv("DISTILBERT_MODEL_DIR", "./models/distilbert")
    try:
        import tensorflow as tf
        from transformers import DistilBertTokenizer, TFDistilBertForSequenceClassification

        tokenizer = DistilBertTokenizer.from_pretrained(model_dir)
        model = TFDistilBertForSequenceClassification.from_pretrained(model_dir)
        print(f"[DistilBERT] Loaded from {model_dir}")

        def _predict(prompt: str) -> float:
            encoded = tokenizer(
                prompt, return_tensors="tf",
                truncation=True, padding=True, max_length=128,
            )
            logits = model(encoded).logits
            probs = tf.nn.softmax(logits, axis=-1).numpy()[0]
            return float(probs[1])

        _distilbert_predict = _predict
        return True
    except Exception as e:
        print(f"[DistilBERT] Failed to load: {e}")
        return False


class BertClassifier:
    """
    Classifies prompts as malicious or benign.
    Falls back gracefully when a model is not available.
    """

    def __init__(self):
        active = state.BERT_SETTINGS.get("ACTIVE_MODEL", "modernbert")
        if active == "modernbert":
            ok = _load_modernbert()
            if not ok:
                print("[BertClassifier] ModernBERT unavailable — trying DistilBERT")
                _load_distilbert()
        else:
            ok = _load_distilbert()
            if not ok:
                print("[BertClassifier] DistilBERT unavailable — trying ModernBERT")
                _load_modernbert()

    def predict(self, prompt: str) -> float:
        """Return malicious probability in [0, 1]."""
        active = state.BERT_SETTINGS.get("ACTIVE_MODEL", "modernbert")
        if active == "modernbert" and _modernbert_predict:
            return _modernbert_predict(prompt)
        if _distilbert_predict:
            return _distilbert_predict(prompt)
        # No model loaded — safe fallback (pass everything through)
        print("[BertClassifier] No model loaded — returning 0.0")
        return 0.0

    @property
    def active_model_name(self) -> str:
        active = state.BERT_SETTINGS.get("ACTIVE_MODEL", "modernbert")
        if active == "modernbert" and _modernbert_predict:
            return "modernbert"
        if _distilbert_predict:
            return "distilbert"
        return "none"
