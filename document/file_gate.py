"""
document/file_gate.py
======================
Step 1 + Step 2 security gate for uploaded files.
Checks: extension, magic bytes, spoofing, metadata, content integrity,
        file size, PDF page count, PDF risky markers.
"""

import os
import io
import json
import zipfile
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pypdf
from PIL import Image
from PIL.ExifTags import TAGS

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")


@dataclass
class FileGateConfig:
    max_file_size_mb: int = 25
    max_pdf_pages: int = 500
    allowed_types: tuple = ("pdf", "docx", "text", "png", "jpg", "webp", "bmp", "tiff")


@dataclass
class FileGateResult:
    file: str
    extension: str = "unknown"
    magic_type: str = "unknown"
    spoofing: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    content_check: str = "pending"
    size_mb: float = 0.0
    page_count: int = 0
    risk: str = "SAFE"
    markers: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    should_block: bool = False

    def _escalate_risk(self, new_level: str) -> None:
        order = {"SAFE": 0, "MED": 1, "HIGH": 2}
        if order.get(new_level, 0) > order.get(self.risk, 0):
            self.risk = new_level

    def add_marker(self, marker: str, risk_level: str) -> None:
        self.markers.append(marker)
        self._escalate_risk(risk_level)

    def add_issue(self, issue: str) -> None:
        self.issues.append(issue)

    def finalize(self) -> None:
        self.should_block = (self.risk == "HIGH")

    def to_dict(self) -> dict:
        return {
            "file": self.file, "extension": self.extension,
            "magic_type": self.magic_type, "spoofing": self.spoofing,
            "metadata": self.metadata, "content_check": self.content_check,
            "size_mb": self.size_mb, "page_count": self.page_count,
            "risk": self.risk, "markers": self.markers,
            "issues": self.issues, "should_block": self.should_block,
        }


_MAGIC_SIGNATURES: List[tuple] = [
    (b"%PDF",              "pdf"),
    (b"PK\x03\x04",       "docx"),
    (b"\x89PNG\r\n\x1a\n","png"),
    (b"\xFF\xD8\xFF",      "jpg"),
    (b"RIFF",              "webp"),
    (b"BM",                "bmp"),
    (b"\x49\x49\x2A\x00", "tiff"),
    (b"\x4D\x4D\x00\x2A", "tiff"),
]

_EXTENSION_MAP: Dict[str, str] = {
    "pdf": "pdf", "docx": "docx", "doc": "docx",
    "txt": "text", "md": "text", "csv": "text", "log": "text",
    "py": "text", "js": "text", "json": "text", "html": "text", "css": "text",
    "png": "png", "jpg": "jpg", "jpeg": "jpg",
    "webp": "webp", "bmp": "bmp", "tif": "tiff", "tiff": "tiff",
}

_PLAIN_TEXT_EXTENSIONS = {"txt", "md", "csv", "log", "py", "js", "json", "html", "css"}


class FileGate:
    """Unified file safety gate: validates type, size, structure, and malicious markers."""

    def __init__(self, config: Optional[FileGateConfig] = None):
        self.config = config or FileGateConfig()
        self.logger = logging.getLogger("FileGate")

    def run(self, file_path: str) -> FileGateResult:
        result = FileGateResult(file=file_path)
        if not os.path.exists(file_path):
            result.add_marker("FILE_NOT_FOUND", "HIGH")
            result.add_issue("File does not exist on disk.")
            result.finalize()
            return result

        self._step_1a_extension(file_path, result)
        self._step_1b_magic(file_path, result)
        self._step_1c_spoofing(result)
        self._step_1d_metadata(file_path, result)
        self._step_1e_content(file_path, result)
        self._step_2a_size(file_path, result)

        if result.magic_type == "pdf":
            self._step_2b_pdf_pages(file_path, result)
            self._step_2c_pdf_markers(file_path, result)

        result.finalize()
        return result

    def _step_1a_extension(self, file_path: str, result: FileGateResult) -> None:
        raw_ext = Path(file_path).suffix.lower().lstrip(".")
        raw_ext = "jpg" if raw_ext == "jpeg" else raw_ext
        result.extension = raw_ext if raw_ext else "unknown"
        if raw_ext not in _EXTENSION_MAP:
            result.add_marker(f"UNSUPPORTED_EXTENSION:{raw_ext}", "HIGH")
            result.add_issue(f"Extension '.{raw_ext}' is not accepted.")

    def _step_1b_magic(self, file_path: str, result: FileGateResult) -> None:
        try:
            with open(file_path, "rb") as f:
                header = f.read(12)
            for sig, file_type in _MAGIC_SIGNATURES:
                if header.startswith(sig):
                    if file_type == "webp":
                        with open(file_path, "rb") as f:
                            f.seek(8)
                            if f.read(4) == b"WEBP":
                                result.magic_type = "webp"
                                return
                        result.magic_type = "unknown_riff"
                        return
                    result.magic_type = file_type
                    return
            # Check plain text
            ext = result.extension
            if ext in _PLAIN_TEXT_EXTENSIONS:
                try:
                    with open(file_path, "rb") as f:
                        f.read(512).decode("utf-8")
                    result.magic_type = "text"
                except UnicodeDecodeError:
                    result.magic_type = "binary"
                    result.add_marker("BINARY_DISGUISED_AS_TEXT", "HIGH")
            else:
                result.magic_type = "unknown"
                result.add_marker("UNKNOWN_MAGIC_BYTES", "HIGH")
        except Exception as e:
            result.add_issue(f"Magic bytes read error: {e}")

    def _step_1c_spoofing(self, result: FileGateResult) -> None:
        claimed = _EXTENSION_MAP.get(result.extension, "unknown")
        actual = result.magic_type
        if claimed != "unknown" and actual != "unknown" and claimed != actual:
            result.spoofing = True
            result.add_marker(f"EXTENSION_SPOOFING:{result.extension}→{actual}", "HIGH")
            result.add_issue(
                f"Extension claims '{result.extension}' but magic bytes say '{actual}'."
            )

    def _step_1d_metadata(self, file_path: str, result: FileGateResult) -> None:
        try:
            mtype = result.magic_type
            if mtype in ("jpg", "png", "webp", "bmp", "tiff"):
                img = Image.open(file_path)
                exif_data = img._getexif() if hasattr(img, "_getexif") else None
                if exif_data:
                    result.metadata = {
                        TAGS.get(k, k): str(v)[:200]
                        for k, v in exif_data.items()
                        if k in TAGS
                    }
            elif mtype == "docx":
                with zipfile.ZipFile(file_path) as zf:
                    if "docProps/core.xml" in zf.namelist():
                        tree = ET.fromstring(zf.read("docProps/core.xml"))
                        result.metadata = {
                            el.tag.split("}")[-1]: el.text
                            for el in tree
                            if el.text
                        }
            elif mtype == "pdf":
                reader = pypdf.PdfReader(file_path)
                if reader.metadata:
                    result.metadata = {
                        k.lstrip("/"): str(v)[:200]
                        for k, v in reader.metadata.items()
                    }
        except Exception as e:
            result.add_issue(f"Metadata extraction error: {e}")

    def _step_1e_content(self, file_path: str, result: FileGateResult) -> None:
        try:
            mtype = result.magic_type
            if mtype == "pdf":
                result.content_check = self._check_pdf(file_path)
            elif mtype == "docx":
                result.content_check = self._check_docx(file_path)
            elif mtype == "text":
                result.content_check = self._check_text(file_path, result.extension)
            elif mtype in ("jpg", "png", "webp", "bmp", "tiff"):
                Image.open(file_path).verify()
                result.content_check = f"valid {mtype}"
            else:
                result.content_check = "unchecked"
        except Exception as e:
            result.add_marker("CONTENT_STRUCTURE_INVALID", "HIGH")
            result.add_issue(f"Content check failed: {e}")
            result.content_check = "invalid"

    def _check_pdf(self, file_path: str) -> str:
        file_size = os.path.getsize(file_path)
        read_size = min(1024, file_size)
        with open(file_path, "rb") as f:
            f.seek(-read_size, os.SEEK_END)
            tail = f.read()
        if b"%%EOF" in tail or b"%EOF" in tail:
            return "valid pdf"
        raise ValueError("Missing %%EOF marker — PDF may be malformed")

    def _check_docx(self, file_path: str) -> str:
        if not zipfile.is_zipfile(file_path):
            raise ValueError("File has DOCX magic bytes but is not a valid ZIP")
        with zipfile.ZipFile(file_path) as zf:
            if "[Content_Types].xml" not in zf.namelist():
                raise ValueError("ZIP is missing [Content_Types].xml")
        return "valid docx"

    def _check_text(self, file_path: str, extension: str) -> str:
        with open(file_path, "r", encoding="utf-8", errors="strict") as f:
            content = f.read(4096)
        if extension == "json":
            with open(file_path, "r", encoding="utf-8") as f:
                full = f.read()
            json.loads(full)
            return "valid json"
        elif extension == "html":
            if "<" not in content:
                raise ValueError("No '<' tag found in HTML file")
            return "valid html"
        elif extension == "csv":
            if "," not in content and "\n" not in content:
                raise ValueError("No commas or newlines found in CSV file")
            return "valid csv"
        return "valid text"

    def _step_2a_size(self, file_path: str, result: FileGateResult) -> None:
        try:
            size_mb = round(os.path.getsize(file_path) / (1024 * 1024), 2)
            result.size_mb = size_mb
            if size_mb > self.config.max_file_size_mb:
                result.add_marker(f"FILE_TOO_LARGE:{size_mb}MB", "HIGH")
                result.add_issue(f"File is {size_mb} MB — exceeds {self.config.max_file_size_mb} MB limit.")
        except Exception as e:
            result.add_issue(f"Size check error: {e}")

    def _step_2b_pdf_pages(self, file_path: str, result: FileGateResult) -> None:
        try:
            reader = pypdf.PdfReader(file_path)
            result.page_count = len(reader.pages)
            if result.page_count > self.config.max_pdf_pages:
                result.add_marker(f"PDF_PAGE_LIMIT_EXCEEDED:{result.page_count}", "HIGH")
                result.add_issue(f"PDF has {result.page_count} pages — exceeds {self.config.max_pdf_pages} limit.")
        except Exception as e:
            result.add_issue(f"PDF page count error: {e}")

    def _step_2c_pdf_markers(self, file_path: str, result: FileGateResult) -> None:
        HIGH_MARKERS = [b"/JavaScript", b"/OpenAction", b"/Launch", b"/EmbeddedFiles"]
        MED_MARKERS = [b"/AA", b"/AcroForm"]
        try:
            with open(file_path, "rb") as f:
                raw = f.read()
            for marker in HIGH_MARKERS:
                if marker in raw:
                    name = marker.decode()
                    result.add_marker(f"PDF_RISKY_MARKER:{name}", "HIGH")
                    result.add_issue(f"PDF contains '{name}' — active content marker.")
            for marker in MED_MARKERS:
                if marker in raw:
                    name = marker.decode()
                    result.add_marker(f"PDF_ACTIVE_CONTENT:{name}", "MED")
                    result.add_issue(f"PDF contains '{name}' — interactive content.")
        except Exception as e:
            result.add_issue(f"PDF marker scan error: {e}")
