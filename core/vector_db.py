"""
core/vector_db.py
=================
ChromaDB-backed PDF vector store for context relevance checks.
Uses ChromaDB HttpClient to talk to the standalone chromadb container.
"""

import os
import shutil
import tempfile
from typing import Dict, Any, List

import chromadb
from chromadb.config import Settings

from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings


CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
# Default 8001 for local dev (host-exposed port), 8000 inside Docker network
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8001"))

GLOBAL_COLLECTION = "global_context"


def _get_chroma_client() -> chromadb.HttpClient:
    return chromadb.HttpClient(
        host=CHROMA_HOST,
        port=CHROMA_PORT,
        settings=Settings(anonymized_telemetry=False),
    )


def _create_embeddings() -> HuggingFaceEmbeddings:
    return HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        encode_kwargs={"normalize_embeddings": True},
    )


class PDFVectorStore:
    """Manages building, loading, and querying a ChromaDB collection from a PDF."""

    def __init__(
        self,
        pdf_path: str = "",
        persist_directory: str = "./context_vectorstore",  # kept for API compat; unused
        embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
        chunk_size: int = 150,
        chunk_overlap: int = 50,
    ):
        self.pdf_path = pdf_path
        self.persist_directory = persist_directory  # not used with HttpClient
        self.embedding_model = embedding_model
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self._is_loaded = False
        self._chunk_count = 0

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _embeddings(self) -> HuggingFaceEmbeddings:
        return HuggingFaceEmbeddings(
            model_name=self.embedding_model,
            encode_kwargs={"normalize_embeddings": True},
        )

    def _get_or_create_collection(
        self,
        client: chromadb.HttpClient,
        name: str,
        reset: bool = False,
    ) -> chromadb.Collection:
        if reset:
            try:
                client.delete_collection(name)
            except Exception:
                pass
        return client.get_or_create_collection(
            name,
            metadata={"hnsw:space": "cosine"},
        )

    def _embed_texts(self, texts: List[str]) -> List[List[float]]:
        embedder = self._embeddings()
        return embedder.embed_documents(texts)

    def _embed_query(self, query: str) -> List[float]:
        embedder = self._embeddings()
        return embedder.embed_query(query)

    # ── Public API ────────────────────────────────────────────────────────────

    def build(self):
        """Index self.pdf_path into the global_context collection."""
        loader = PyPDFLoader(self.pdf_path)
        documents = loader.load()
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.chunk_size, chunk_overlap=self.chunk_overlap
        )
        chunks = splitter.split_documents(documents)

        client = _get_chroma_client()
        collection = self._get_or_create_collection(
            client, GLOBAL_COLLECTION, reset=True
        )

        texts = [c.page_content for c in chunks]
        embeddings = self._embed_texts(texts)
        ids = [f"chunk_{i}" for i in range(len(texts))]

        collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=texts,
        )

        self._chunk_count = len(chunks)
        self._is_loaded = True
        print(f"[VectorDB] Built global_context with {len(chunks)} chunks")

    def load(self):
        """Check whether the global_context collection exists and has documents."""
        try:
            client = _get_chroma_client()
            collection = client.get_or_create_collection(GLOBAL_COLLECTION)
            count = collection.count()
            self._chunk_count = count
            self._is_loaded = count > 0
            print(f"[VectorDB] Loaded global_context ({count} chunks)")
        except Exception as e:
            print(f"[VectorDB] Load failed: {e}")
            self._is_loaded = False

    def is_ready(self) -> bool:
        return self._is_loaded

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_loaded": self._is_loaded,
            "chunk_count": self._chunk_count,
            "persist_directory": self.persist_directory,
        }

    def check_relevance(
        self, query: str, threshold: float = 50.0
    ) -> Dict[str, Any]:
        if not self.is_ready():
            return {
                "relevant": False, "similarity": 0.0, "threshold": threshold,
                "error": "Vector store not initialized",
            }
        try:
            client = _get_chroma_client()
            collection = client.get_or_create_collection(GLOBAL_COLLECTION)
            query_embedding = self._embed_query(query)
            results = collection.query(
                query_embeddings=[query_embedding],
                n_results=1,
                include=["documents", "distances"],
            )
            if not results["documents"] or not results["documents"][0]:
                return {
                    "relevant": False, "similarity": 0.0, "threshold": threshold,
                    "message": "No matching context found",
                }
            distance = results["distances"][0][0]
            similarity = (1 - distance) * 100
            return {
                "relevant": similarity >= threshold,
                "similarity": round(similarity, 2),
                "threshold": threshold,
                "matched_content": results["documents"][0][0][:200],
            }
        except Exception as e:
            return {
                "relevant": False, "similarity": 0.0, "threshold": threshold,
                "error": str(e),
            }

    def rebuild_from_pdf(self, new_pdf_path: str) -> Dict[str, Any]:
        try:
            self.pdf_path = new_pdf_path
            self.build()
            return {"success": True, "chunk_count": self._chunk_count}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Per-user collections ──────────────────────────────────────────────────

    def build_user_collection(self, user_id: int, chunks: List[str]) -> Dict[str, Any]:
        """Create/replace a per-user ChromaDB collection."""
        collection_name = f"user_{user_id}"
        try:
            client = _get_chroma_client()
            collection = self._get_or_create_collection(
                client, collection_name, reset=True
            )
            embeddings = self._embed_texts(chunks)
            ids = [f"chunk_{i}" for i in range(len(chunks))]
            collection.upsert(
                ids=ids,
                embeddings=embeddings,
                documents=chunks,
            )
            return {"success": True, "chunk_count": len(chunks)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def check_relevance_for_user(
        self, query: str, user_id: int, threshold: float = 50.0
    ) -> Dict[str, Any]:
        """Check user collection first; fall back to global_context."""
        collection_name = f"user_{user_id}"
        try:
            client = _get_chroma_client()
            # Check if user collection exists and has documents
            try:
                user_col = client.get_collection(collection_name)
                if user_col.count() > 0:
                    query_embedding = self._embed_query(query)
                    results = user_col.query(
                        query_embeddings=[query_embedding],
                        n_results=1,
                        include=["documents", "distances"],
                    )
                    if results["documents"] and results["documents"][0]:
                        distance = results["distances"][0][0]
                        similarity = (1 - distance) * 100
                        return {
                            "relevant": similarity >= threshold,
                            "similarity": round(similarity, 2),
                            "threshold": threshold,
                            "matched_content": results["documents"][0][0][:200],
                            "source": "user",
                        }
            except Exception:
                pass  # Fall through to global

            # Fall back to global context
            result = self.check_relevance(query, threshold)
            result["source"] = "global"
            return result
        except Exception as e:
            return {
                "relevant": False, "similarity": 0.0, "threshold": threshold,
                "error": str(e),
            }
