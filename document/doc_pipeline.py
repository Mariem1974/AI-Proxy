"""
document/doc_pipeline.py
=========================
Full document security pipeline (DOC_Guard).

Steps:
  1. FileGate        — validate type, size, spoofing, PDF markers
  2. Extract chunks  — smart router (TXT/DOCX/digital-PDF/OCR)
  3. Normalize       — strip zero-width, soft-hyphens, BOM
  4. Unicode scan    — emoji stego + homoglyph (document mode)
  5a. spaCy rules    — injection, SQLi, XSS, etc. per chunk
  5b. BERT           — classifier (only chunks that pass spaCy)
  5c. PII            — detect + redact PII per chunk
  6. Final decision  — ALLOW or BLOCK
  7. Safe context    — return clean text for LLM

One flagged chunk = entire request blocked.
"""

import os
import unicodedata
from typing import List, Tuple, Dict, Any

from document.file_gate import FileGate, FileGateConfig, FileGateResult
from document.extractor import FileExtractor, Chunk


# ── Zero-width / artifact normalisation ──────────────────────────────────────

_ZERO_WIDTH = [
    '\u200b', '\u200c', '\u200d', '\ufeff',
    '\u180e', '\u00ad', '\u2060',
]

def _normalize_clean(text: str) -> str:
    """Strip invisible characters and normalise unicode."""
    for ch in _ZERO_WIDTH:
        text = text.replace(ch, '')
    text = unicodedata.normalize('NFKC', text)
    return text.strip()


# ── Pipeline result dataclass ─────────────────────────────────────────────────

class DocPipelineResult:
    def __init__(self):
        self.gate_result: FileGateResult = None
        self.chunks: List[Chunk] = []
        self.safe_chunks: List[Chunk] = []
        self.final_decision: str = "ALLOW"
        self.block_reason: str = ""
        self.safe_context: str = ""
        self.stats: Dict[str, Any] = {}

    def to_dict(self) -> dict:
        return {
            "final_decision": self.final_decision,
            "block_reason": self.block_reason,
            "total_chunks": len(self.chunks),
            "safe_chunks": len(self.safe_chunks),
            "gate": self.gate_result.to_dict() if self.gate_result else {},
            "stats": self.stats,
        }


# ── Main pipeline ─────────────────────────────────────────────────────────────

class DocPipeline:
    """
    Full document security pipeline.
    Instantiate once; call run(file_path) per upload.
    """

    def __init__(
        self,
        unicode_firewall=None,
        input_spacy=None,
        bert_classifier=None,
        pii_detector=None,
        output_rewriter=None,
    ):
        self.gate = FileGate(FileGateConfig())
        self.extractor = FileExtractor()
        self.unicode_firewall = unicode_firewall
        self.input_spacy = input_spacy
        self.bert_classifier = bert_classifier
        self.pii_detector = pii_detector
        self.output_rewriter = output_rewriter
        print("[DocPipeline] Initialized")

    def run(self, file_path: str, active_features: dict = None) -> DocPipelineResult:
        """
        Run the full pipeline on an uploaded file.
        active_features: dict of feature flags from state.FEATURES
        """
        if active_features is None:
            active_features = {}

        result = DocPipelineResult()

        # ── Step 1: File Gate ──────────────────────────────────────────────
        gate = self.gate.run(file_path)
        result.gate_result = gate
        if gate.should_block:
            result.final_decision = "BLOCK"
            result.block_reason = f"File gate: {', '.join(gate.markers)}"
            return result

        # ── Step 2: Extract Chunks ─────────────────────────────────────────
        try:
            chunks = self.extractor.extract_chunks(file_path)
        except Exception as e:
            result.final_decision = "BLOCK"
            result.block_reason = f"Extraction failed: {e}"
            return result

        if not chunks:
            result.final_decision = "ALLOW"
            result.safe_context = ""
            return result

        result.chunks = chunks

        # ── Step 3: Normalize ──────────────────────────────────────────────
        for chunk in chunks:
            chunk.normalized_text = _normalize_clean(chunk.text)

        # ── Step 4: Unicode Firewall (document mode) ───────────────────────
        if self.unicode_firewall and active_features.get("INPUT_UNICODE_FIREWALL"):
            for chunk in chunks:
                blocked, reason, metrics = self.unicode_firewall.scan(
                    chunk.normalized_text, mode='document'
                )
                if blocked:
                    chunk.is_malicious = True
                    chunk.attack_reason = reason
                    chunk.attack_vector = metrics.get('attack_vector', 'unicode')
                else:
                    # Clean the text for downstream
                    chunk.normalized_text = self.unicode_firewall.clean(
                        chunk.normalized_text, mode='document'
                    )

        # ── Step 5a: spaCy Rules ───────────────────────────────────────────
        if self.input_spacy and active_features.get("INPUT_SPACY_FIREWALL"):
            for chunk in chunks:
                if chunk.is_malicious:
                    continue
                spacy_result = self.input_spacy.analyze(chunk.normalized_text)
                if spacy_result["is_malicious"]:
                    chunk.is_malicious = True
                    threat = spacy_result["threat_details"][0] if spacy_result["threat_details"] else {}
                    chunk.attack_reason = f"spaCy: {threat.get('category', 'unknown')}"
                    chunk.attack_vector = threat.get("category", "spacy_rule")

        # ── Step 5b: BERT Classifier ───────────────────────────────────────
        import state
        safe_threshold = state.BERT_SETTINGS.get("SAFE_THRESHOLD", 0.30)
        medium_threshold = state.BERT_SETTINGS.get("MEDIUM_THRESHOLD", 0.70)

        if self.bert_classifier and active_features.get("BERT_FIREWALL"):
            from core.rephrase_engine import InputRewriter
            _rewriter = None

            for chunk in chunks:
                if chunk.is_malicious:
                    continue
                prob = self.bert_classifier.predict(chunk.normalized_text)
                chunk.bert_prob_before = prob

                if prob >= medium_threshold:
                    chunk.is_malicious = True
                    chunk.attack_reason = f"BERT high confidence ({prob:.2f})"
                    chunk.attack_vector = "bert_classifier"
                elif prob >= safe_threshold:
                    # Try rephrase loop
                    if _rewriter is None:
                        _rewriter = InputRewriter()
                    text_to_try = chunk.normalized_text
                    for _ in range(state.BERT_SETTINGS.get("MAX_REPHRASE", 3)):
                        text_to_try = _rewriter.rewrite(text_to_try)
                        new_prob = self.bert_classifier.predict(text_to_try)
                        if new_prob < safe_threshold:
                            chunk.normalized_text = text_to_try
                            break
                        if new_prob >= medium_threshold:
                            chunk.is_malicious = True
                            chunk.attack_reason = f"BERT after rephrase ({new_prob:.2f})"
                            chunk.attack_vector = "bert_rephrase"
                            break
                    else:
                        chunk.is_malicious = True
                        chunk.attack_reason = "BERT: still suspicious after max rephrases"
                        chunk.attack_vector = "bert_max_rephrase"

        # ── Step 5c: PII Detection ─────────────────────────────────────────
        if self.pii_detector and active_features.get("INPUT_PII_FIREWALL"):
            for chunk in chunks:
                if chunk.is_malicious:
                    continue
                entities, masked = self.pii_detector.detect_and_mask(chunk.normalized_text)
                chunk.sanitized_text = masked
                if not chunk.sanitized_text:
                    chunk.sanitized_text = chunk.normalized_text
        else:
            for chunk in chunks:
                if not chunk.sanitized_text:
                    chunk.sanitized_text = chunk.normalized_text

        # ── Step 6: Final Decision ─────────────────────────────────────────
        malicious = [c for c in chunks if c.is_malicious]
        if malicious:
            result.final_decision = "BLOCK"
            result.block_reason = malicious[0].attack_reason
        else:
            result.final_decision = "ALLOW"
            result.safe_chunks = [c for c in chunks if not c.is_malicious]

        # ── Step 7: Build safe context string ─────────────────────────────
        if result.final_decision == "ALLOW":
            result.safe_context = "\n\n".join(
                c.sanitized_text or c.normalized_text or c.text
                for c in result.safe_chunks
            )

        result.stats = {
            "total_chunks": len(chunks),
            "malicious_chunks": len(malicious),
            "safe_chunks": len(result.safe_chunks),
            "file_type": gate.magic_type,
            "file_size_mb": gate.size_mb,
        }

        return result
