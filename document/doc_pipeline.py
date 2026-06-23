"""
document/doc_pipeline.py
=========================
Full document security pipeline (DOC_Guard).

Steps:
  1. FileGate        — validate type, size, spoofing, PDF markers
  2. Extract chunks  — smart router (TXT/DOCX/digital-PDF/OCR)
  3. Normalize       — strip zero-width, soft-hyphens, BOM
  4-5. Parallel scan — each chunk runs Unicode → spaCy → BERT → PII in its
                       own thread; a shared abort event short-circuits the
                       moment any malicious chunk is found.
  6. Final decision  — ALLOW or BLOCK
  7. Safe context    — return clean text for LLM

One flagged chunk = entire request blocked.
"""

import os
import unicodedata
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

from document.file_gate import FileGate, FileGateConfig, FileGateResult
from document.extractor import FileExtractor, Chunk


# ── Config ────────────────────────────────────────────────────────────────────

_SCAN_WORKERS = min(8, (os.cpu_count() or 4))

# ── Zero-width / artifact normalisation ──────────────────────────────────────

_ZERO_WIDTH = [
    '​', '‌', '‍', '﻿',
    '᠎', '­', '⁠',
]

def _normalize_clean(text: str) -> str:
    for ch in _ZERO_WIDTH:
        text = text.replace(ch, '')
    return unicodedata.normalize('NFKC', text).strip()


# ── Pipeline result ───────────────────────────────────────────────────────────

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

    # ── Per-chunk scanner (runs in its own thread) ────────────────────────────

    def _scan_chunk(
        self,
        chunk: Chunk,
        active_features: dict,
        safe_threshold: float,
        medium_threshold: float,
        max_rephrase: int,
        abort: threading.Event,
    ) -> Chunk:
        """
        Normalize → Unicode → spaCy → BERT → PII for a single chunk.
        Checks abort before each expensive step so the thread exits early
        as soon as another thread has already found a malicious chunk.
        """
        # Step 3: Normalize
        chunk.normalized_text = _normalize_clean(chunk.text)

        if abort.is_set():
            return chunk

        # Step 4: Unicode Firewall
        if self.unicode_firewall and active_features.get("INPUT_UNICODE_FIREWALL"):
            blocked, reason, metrics = self.unicode_firewall.scan(
                chunk.normalized_text, mode='document'
            )
            if blocked:
                chunk.is_malicious = True
                chunk.attack_reason = reason
                chunk.attack_vector = metrics.get('attack_vector', 'unicode')
                abort.set()
                return chunk
            chunk.normalized_text = self.unicode_firewall.clean(
                chunk.normalized_text, mode='document'
            )

        if abort.is_set():
            return chunk

        # Step 5a: spaCy Rules
        if self.input_spacy and active_features.get("INPUT_SPACY_FIREWALL"):
            spacy_result = self.input_spacy.analyze(chunk.normalized_text)
            if spacy_result["is_malicious"]:
                chunk.is_malicious = True
                threat = spacy_result["threat_details"][0] if spacy_result["threat_details"] else {}
                chunk.attack_reason = f"spaCy: {threat.get('category', 'unknown')}"
                chunk.attack_vector = threat.get("category", "spacy_rule")
                abort.set()
                return chunk

        if abort.is_set():
            return chunk

        # Step 5b: BERT Classifier + rephrase loop
        if self.bert_classifier and active_features.get("BERT_FIREWALL"):
            prob = self.bert_classifier.predict(chunk.normalized_text)
            chunk.bert_prob_before = prob

            if prob >= medium_threshold:
                chunk.is_malicious = True
                chunk.attack_reason = f"BERT high confidence ({prob:.2f})"
                chunk.attack_vector = "bert_classifier"
                abort.set()
                return chunk

            elif prob >= safe_threshold:
                # Rephrase loop — sequential within this chunk
                from core.rephrase_engine import InputRewriter
                rewriter = InputRewriter()
                text_to_try = chunk.normalized_text

                for _ in range(max_rephrase):
                    if abort.is_set():
                        return chunk
                    text_to_try = rewriter.rewrite(text_to_try)
                    new_prob = self.bert_classifier.predict(text_to_try)
                    if new_prob < safe_threshold:
                        chunk.normalized_text = text_to_try
                        break
                    if new_prob >= medium_threshold:
                        chunk.is_malicious = True
                        chunk.attack_reason = f"BERT after rephrase ({new_prob:.2f})"
                        chunk.attack_vector = "bert_rephrase"
                        abort.set()
                        return chunk
                else:
                    chunk.is_malicious = True
                    chunk.attack_reason = "BERT: still suspicious after max rephrases"
                    chunk.attack_vector = "bert_max_rephrase"
                    abort.set()
                    return chunk

        if abort.is_set():
            return chunk

        # Step 5c: PII Detection
        if self.pii_detector and active_features.get("INPUT_PII_FIREWALL"):
            entities, masked = self.pii_detector.detect_and_mask(chunk.normalized_text)
            chunk.sanitized_text = masked if masked else chunk.normalized_text
        else:
            chunk.sanitized_text = chunk.normalized_text

        return chunk

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self, file_path: str, active_features: dict = None) -> DocPipelineResult:
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

        # ── Steps 3–5: Parallel chunk scanning ────────────────────────────
        import state
        safe_threshold = state.BERT_SETTINGS.get("SAFE_THRESHOLD", 0.30)
        medium_threshold = state.BERT_SETTINGS.get("MEDIUM_THRESHOLD", 0.70)
        max_rephrase = state.BERT_SETTINGS.get("MAX_REPHRASE", 3)

        abort = threading.Event()
        workers = min(_SCAN_WORKERS, len(chunks))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    self._scan_chunk,
                    chunk,
                    active_features,
                    safe_threshold,
                    medium_threshold,
                    max_rephrase,
                    abort,
                ): chunk
                for chunk in chunks
            }
            for future in as_completed(futures):
                future.result()  # propagate any unexpected exceptions

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
            "scan_workers": workers,
        }

        return result
