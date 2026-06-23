"""
filters/input/bert_classifier.py
==================================
Classifier supporting both ModernBERT (new) and DistilBERT (legacy).
Active model is controlled by state.BERT_SETTINGS["ACTIVE_MODEL"].
"""

import os
import json
import state

_modernbert_predict = None
_distilbert_predict = None


def _load_modernbert():
    global _modernbert_predict
    if _modernbert_predict is not None:
        return True

    from pathlib import Path
    raw_dir = os.getenv("MODERNBERT_MODEL_DIR", "./models/modernbert")
    model_dir = Path(raw_dir).resolve()

    if not model_dir.is_dir():
        print(f"[ModernBERT] Directory not found: {model_dir}")
        return False

    try:
        import torch
        from safetensors.torch import load_file
        from transformers import (
            ModernBertConfig,
            ModernBertForSequenceClassification,
            PreTrainedTokenizerFast,
        )

        # Load config from JSON without going through HF Hub
        with open(model_dir / "config.json") as f:
            config_dict = json.load(f)
        config = ModernBertConfig(**{
            k: v for k, v in config_dict.items()
            if k not in ("model_type", "transformers_version", "_name_or_path",
                         "architectures", "torch_dtype")
        })

        # Load tokenizer from local file (no from_pretrained)
        tokenizer = PreTrainedTokenizerFast(
            tokenizer_file=str(model_dir / "tokenizer.json")
        )
        # Pad token is defined in the checkpoint config
        tokenizer.pad_token_id = config_dict.get("pad_token_id", 50283)

        # Build model and inject safetensors weights
        model = ModernBertForSequenceClassification(config)
        state_dict = load_file(str(model_dir / "model.safetensors"))
        missing, unexpected = model.load_state_dict(state_dict, strict=False)
        if missing:
            print(f"[ModernBERT] {len(missing)} missing keys (e.g. {missing[0]})")
        model.eval()
        print(f"[ModernBERT] Loaded from {model_dir}")

        def _predict(prompt: str) -> float:
            enc = tokenizer(
                prompt, return_tensors="pt",
                truncation=True, padding=True, max_length=512,
            )
            with torch.no_grad():
                logits = model(**enc).logits
            probs = torch.nn.functional.softmax(logits, dim=-1).numpy()[0]
            return float(probs[1])

        _modernbert_predict = _predict
        return True

    except Exception as e:
        import traceback
        print(f"[ModernBERT] Failed to load: {e}")
        traceback.print_exc()
        return False


def _load_distilbert():
    global _distilbert_predict
    if _distilbert_predict is not None:
        return True

    from pathlib import Path
    raw_dir = os.getenv("DISTILBERT_MODEL_DIR", "./models/distilbert")
    model_dir = Path(raw_dir).resolve()

    if not model_dir.is_dir():
        print(f"[DistilBERT] Directory not found: {model_dir}")
        return False

    try:
        import torch
        from safetensors.torch import load_file
        from transformers import (
            DistilBertConfig,
            DistilBertForSequenceClassification,
            PreTrainedTokenizerFast,
        )

        with open(model_dir / "config.json") as f:
            config_dict = json.load(f)
        config = DistilBertConfig(**{
            k: v for k, v in config_dict.items()
            if k not in ("model_type", "transformers_version", "_name_or_path",
                         "architectures", "torch_dtype")
        })

        tokenizer = PreTrainedTokenizerFast(
            tokenizer_file=str(model_dir / "tokenizer.json")
        )

        model = DistilBertForSequenceClassification(config)
        weights = model_dir / "model.safetensors"
        if not weights.exists():
            raise FileNotFoundError("No model.safetensors found")
        model.load_state_dict(load_file(str(weights)), strict=False)
        model.eval()
        print(f"[DistilBERT] Loaded from {model_dir}")

        def _predict(prompt: str) -> float:
            enc = tokenizer(
                prompt, return_tensors="pt",
                truncation=True, padding=True, max_length=128,
            )
            with torch.no_grad():
                logits = model(**enc).logits
            probs = torch.nn.functional.softmax(logits, dim=-1).numpy()[0]
            return float(probs[1])

        _distilbert_predict = _predict
        return True

    except Exception as e:
        print(f"[DistilBERT] Failed to load: {e}")
        return False


class BertClassifier:
    """Classifies prompts as malicious or benign. Falls back gracefully."""

    def __init__(self):
        active = state.BERT_SETTINGS.get("ACTIVE_MODEL", "modernbert")
        if active == "modernbert":
            if not _load_modernbert():
                print("[BertClassifier] ModernBERT unavailable — trying DistilBERT")
                _load_distilbert()
        else:
            if not _load_distilbert():
                print("[BertClassifier] DistilBERT unavailable — trying ModernBERT")
                _load_modernbert()

    def predict(self, prompt: str) -> float:
        """Return malicious probability in [0, 1]."""
        active = state.BERT_SETTINGS.get("ACTIVE_MODEL", "modernbert")
        if active == "modernbert" and _modernbert_predict:
            return _modernbert_predict(prompt)
        if _distilbert_predict:
            return _distilbert_predict(prompt)
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
