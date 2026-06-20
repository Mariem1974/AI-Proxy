"""
document/extractor.py
======================
Smart file router + text extractor.
Routes: TXT→direct, DOCX→python-docx, digital PDF→PyMuPDF, scanned PDF/images→docTR.
Chunks extracted text with overlap for downstream pipeline processing.
"""

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

# ── Lazy imports (heavy models loaded once at startup) ────────────────────────
_doctr_model = None
_fitz = None
_docx_lib = None


def _get_doctr():
    global _doctr_model
    if _doctr_model is None:
        try:
            from doctr.io import DocumentFile
            from doctr.models import ocr_predictor
            _doctr_model = ocr_predictor(pretrained=True)
            print("[Extractor] docTR OCR model loaded")
        except Exception as e:
            print(f"[Extractor] docTR not available: {e}")
    return _doctr_model


def _get_fitz():
    global _fitz
    if _fitz is None:
        try:
            import fitz as _fitz_lib
            _fitz = _fitz_lib
        except Exception as e:
            print(f"[Extractor] PyMuPDF not available: {e}")
    return _fitz


def _get_docx():
    global _docx_lib
    if _docx_lib is None:
        try:
            from docx import Document as _Doc
            _docx_lib = _Doc
        except Exception as e:
            print(f"[Extractor] python-docx not available: {e}")
    return _docx_lib


# ── Chunk dataclass ───────────────────────────────────────────────────────────

@dataclass
class Chunk:
    source: str          # filename + page/section info
    text: str            # raw extracted text
    original_text: str = ""
    normalized_text: str = ""
    sanitized_text: str = ""
    bert_prob_before: float = 0.0
    bert_prob_after: float = 0.0
    is_image_only: bool = False
    is_malicious: bool = False
    attack_reason: str = ""
    attack_vector: str = ""


# ── Chunking ──────────────────────────────────────────────────────────────────

def _split_into_chunks(
    text: str,
    source: str,
    chunk_size: int = 250,
    chunk_overlap: int = 50,
) -> List[Chunk]:
    """
    Splits text into overlapping chunks of ~chunk_size words.
    Overlap prevents injection attacks split across chunk boundaries.
    """
    words = text.split()
    if not words:
        return []

    chunks = []
    start = 0
    while start < len(words):
        end = min(start + chunk_size, len(words))
        chunk_text = " ".join(words[start:end])
        chunks.append(Chunk(source=source, text=chunk_text, original_text=chunk_text))
        if end >= len(words):
            break
        start += chunk_size - chunk_overlap

    return chunks


# ── Extraction functions ──────────────────────────────────────────────────────

def _extract_txt(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _extract_docx(file_path: str) -> str:
    Document = _get_docx()
    if Document is None:
        raise RuntimeError("python-docx not installed")
    doc = Document(file_path)
    return "\n".join(para.text for para in doc.paragraphs if para.text.strip())


def _extract_pdf_digital(file_path: str) -> Optional[str]:
    """Extract text from a digital (non-scanned) PDF using PyMuPDF."""
    fitz = _get_fitz()
    if fitz is None:
        return None
    doc = fitz.open(file_path)
    pages_text = []
    for page in doc:
        pages_text.append(page.get_text())
    full_text = "\n".join(pages_text)
    return full_text if len(full_text.strip()) >= 10 else None


def _extract_with_doctr_pdf(file_path: str) -> str:
    """OCR a scanned PDF using docTR."""
    model = _get_doctr()
    if model is None:
        raise RuntimeError("docTR not installed — cannot OCR scanned PDF")
    from doctr.io import DocumentFile
    doc = DocumentFile.from_pdf(file_path)
    result = model(doc)
    return result.render()


def _extract_with_doctr_image(file_path: str) -> str:
    """OCR an image using docTR."""
    model = _get_doctr()
    if model is None:
        raise RuntimeError("docTR not installed — cannot OCR image")
    from doctr.io import DocumentFile
    doc = DocumentFile.from_images(file_path)
    result = model(doc)
    return result.render()


# ── Public API ────────────────────────────────────────────────────────────────

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tiff", ".tif"}


class FileExtractor:
    """
    Routes uploaded files to the appropriate extraction method,
    then splits extracted text into overlapping chunks.
    """

    def __init__(self, chunk_size: int = 250, chunk_overlap: int = 50):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        # Warm up docTR and PyMuPDF at startup
        _get_doctr()
        _get_fitz()
        _get_docx()

    def extract_chunks(self, file_path: str) -> List[Chunk]:
        """
        Extract text from file and return a list of Chunk objects.
        Raises RuntimeError on unsupported or unreadable files.
        """
        ext = os.path.splitext(file_path)[1].lower()
        filename = os.path.basename(file_path)

        if ext == ".txt" or ext in (".md", ".csv", ".log"):
            text = _extract_txt(file_path)
            source = filename

        elif ext == ".docx":
            text = _extract_docx(file_path)
            source = filename

        elif ext == ".pdf":
            # Try digital first
            digital_text = _extract_pdf_digital(file_path)
            if digital_text:
                text = digital_text
                source = f"{filename} [digital]"
            else:
                # Fall back to OCR
                text = _extract_with_doctr_pdf(file_path)
                source = f"{filename} [ocr]"

        elif ext in IMAGE_EXTENSIONS:
            text = _extract_with_doctr_image(file_path)
            source = f"{filename} [ocr]"

        else:
            raise RuntimeError(f"Unsupported file extension: {ext}")

        if not text or not text.strip():
            return []

        return _split_into_chunks(
            text, source, self.chunk_size, self.chunk_overlap
        )
