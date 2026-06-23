"""
filters/input/pii_detector.py
==============================
GLiNER-based PII detection and masking.
Used on both input (redact before LLM) and output (redact after LLM).
"""

import os
from typing import List, Dict


PII_LABELS = [
    "medical_record_number", "date_of_birth", "ssn", "date", "first_name",
    "email", "last_name", "customer_id", "employee_id", "name",
    "street_address", "phone_number", "ipv4", "credit_card_number",
    "license_plate", "address", "user_name", "device_identifier",
    "bank_routing_number", "date_time", "company_name", "unique_identifier",
    "biometric_identifier", "account_number", "city",
    "certificate_license_number", "time", "postcode", "vehicle_identifier",
    "coordinate", "country", "api_key", "ipv6", "password",
    "health_plan_beneficiary_number", "national_id", "tax_id", "url",
    "state", "swift_bic", "cvv", "pin",
]

LABEL_PLACEHOLDERS = {label: f"<{label.upper()}>" for label in PII_LABELS}


class PIIDetector:
    """Detects and masks PII using GLiNER."""

    def __init__(self):
        from pathlib import Path
        raw_path = os.getenv(
            "GLINER_MODEL_PATH",
            "./models/gretel-gliner/hub/models--gretelai--gretel-gliner-bi-large-v1.0"
            "/snapshots/f96d1da43b97bd1846b14a7068a57e1ab15f226e"
        )
        model_path = Path(raw_path).resolve()
        try:
            from gliner import GLiNER
            self._model = GLiNER.from_pretrained(model_path, local_files_only=True)
            print("[PIIDetector] GLiNER loaded")
        except Exception as e:
            self._model = None
            print(f"[PIIDetector] GLiNER failed to load: {e}")

    def detect(self, text: str, threshold: float = 0.25) -> List[Dict]:
        """Return list of detected PII entity dicts."""
        if not self._model:
            return []
        raw = self._model.predict_entities(text, labels=PII_LABELS, threshold=threshold)
        entities = []
        for ent in raw:
            label = ent.get("type") or ent.get("label") or ent.get("entity") or "PII"
            placeholder = LABEL_PLACEHOLDERS.get(label, f"<{label.upper()}>")
            ent_text = ent.get("text") or ent.get("value")
            if ent_text:
                entities.append({
                    "start": ent.get("start"),
                    "end": ent.get("end"),
                    "text": ent_text,
                    "label": label,
                    "placeholder": placeholder,
                })
        return entities

    def mask(self, text: str, entities: List[Dict]) -> str:
        """Replace detected PII entities with placeholders."""
        masked = text
        for ent in sorted(entities, key=lambda x: x["start"], reverse=True):
            masked = masked[:ent["start"]] + ent["placeholder"] + masked[ent["end"]:]
        return masked

    def detect_and_mask(self, text: str, threshold: float = 0.25):
        """Convenience: detect and mask in one call. Returns (entities, masked_text)."""
        entities = self.detect(text, threshold)
        masked = self.mask(text, entities) if entities else text
        return entities, masked
