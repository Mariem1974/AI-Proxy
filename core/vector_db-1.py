"""
core/vector_db.py
=================
ChromaDB-backed PDF vector store for context relevance checks.

Chunking strategy:
  - Splits by WORDS (1 word ≈ 1 token for English text)
  - chunk_size    = 50 words  (static)
  - chunk_overlap = 10 words
  - Small focused chunks give much better cosine similarity scores
    because each chunk contains one idea, not many mixed ideas
"""

import os
import shutil
from typing import Dict, Any, List

from langchain_community.document_loaders import PyPDFLoader
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from langchain_core.documents import Document

# ── Word-based splitter ───────────────────────────────────────────────────────

def _split_by_words(
    documents: List[Document],
    chunk_size: int = 30,
    chunk_overlap: int = 10,
) -> List[Document]:
    """
    Split documents into chunks of exactly `chunk_size` words with
    `chunk_overlap` word overlap between consecutive chunks.

    Why words instead of characters:
      - 1 English word ≈ 1 token for English text
      - chunk_size=50 means ~50 tokens per chunk consistently
      - Independent of PDF content, font, or formatting
      - Same result regardless of which PDF you upload
    """
    chunks: List[Document] = []

    for doc in documents:
        words = doc.page_content.split()
        total = len(words)

        if total == 0:
            continue

        start = 0
        while start < total:
            end = min(start + chunk_size, total)
            chunk_text = " ".join(words[start:end])
            chunks.append(Document(
                page_content=chunk_text,
                metadata=doc.metadata,
            ))
            if end >= total:
                break
            start += chunk_size - chunk_overlap

    return chunks


# ── Main class ────────────────────────────────────────────────────────────────

class PDFVectorStore:
    """Manages building, loading, and querying a ChromaDB vector store from a PDF."""

    def __init__(
        self,
        pdf_path: str = "",
        persist_directory: str = "./context_vectorstore",
        embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
        chunk_size: int = 50,    # words per chunk (~50 tokens) — static
        chunk_overlap: int = 10, # overlapping words between consecutive chunks
    ):
        self.pdf_path = pdf_path
        self.persist_directory = persist_directory
        self.embedding_model = embedding_model
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.vectorstore = None
        self._is_loaded = False
        self._chunk_count = 0

    def _create_embeddings(self) -> HuggingFaceEmbeddings:
        return HuggingFaceEmbeddings(
            model_name=self.embedding_model,
            encode_kwargs={"normalize_embeddings": True},
        )

    def build(self):
        loader = PyPDFLoader(self.pdf_path)
        documents = loader.load()

        chunks = _split_by_words(
            documents,
            chunk_size=self.chunk_size,
            chunk_overlap=self.chunk_overlap,
        )

        embeddings = self._create_embeddings()

        if os.path.exists(self.persist_directory):
            shutil.rmtree(self.persist_directory)

        self.vectorstore = Chroma.from_documents(
            documents=chunks,
            embedding=embeddings,
            persist_directory=self.persist_directory,
            collection_metadata={"hnsw:space": "cosine"},
        )
        self._chunk_count = len(chunks)
        self._is_loaded = True
        print(f"[VectorDB] Built — {len(chunks)} chunks "
              f"({self.chunk_size} words each, {self.chunk_overlap} overlap)")

    def load(self):
        embeddings = self._create_embeddings()
        self.vectorstore = Chroma(
            persist_directory=self.persist_directory,
            embedding_function=embeddings,
        )
        if self.vectorstore:
            self._chunk_count = self.vectorstore._collection.count()
            self._is_loaded = True
        print("[VectorDB] Loaded from disk")

    def is_ready(self) -> bool:
        return self._is_loaded and self.vectorstore is not None

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_loaded": self._is_loaded,
            "chunk_count": self._chunk_count,
            "persist_directory": self.persist_directory,
        }

    def check_relevance(self, query: str, threshold: float = 50.0) -> Dict[str, Any]:
        if not self.is_ready():
            return {
                "relevant": False, "similarity": 0.0,
                "threshold": threshold, "error": "Vector store not initialized",
            }
        try:
            # k=5: retrieve top 5 matches and use the single best score.
            # With small 50-word chunks we need more candidates
            # to make sure we find the closest match.
            results = self.vectorstore.similarity_search_with_score(query, k=5)
            if not results:
                return {
                    "relevant": False, "similarity": 0.0,
                    "threshold": threshold, "message": "No matching context found",
                }
            # Lowest distance = highest similarity
            doc, score = min(results, key=lambda x: x[1])
            similarity = (1 - score) * 100
            return {
                "relevant": similarity >= threshold,
                "similarity": round(similarity, 2),
                "threshold": threshold,
                "matched_content": doc.page_content[:200],
            }
        except Exception as e:
            return {
                "relevant": False, "similarity": 0.0,
                "threshold": threshold, "error": str(e),
            }

    def rebuild_from_pdf(self, new_pdf_path: str) -> Dict[str, Any]:
        try:
            self.pdf_path = new_pdf_path
            self.build()
            return {"success": True, "chunk_count": self._chunk_count}
        except Exception as e:
            return {"success": False, "error": str(e)}
