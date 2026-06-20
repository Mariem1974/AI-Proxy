"""
core/vector_db.py
=================
ChromaDB-backed PDF vector store for context relevance checks.
"""

import os
import shutil
from typing import Dict, Any, List, Tuple

from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_chroma import Chroma


class PDFVectorStore:
    """Manages building, loading, and querying a ChromaDB vector store from a PDF."""

    def __init__(
        self,
        pdf_path: str = "",
        persist_directory: str = "./context_vectorstore",
        embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
        chunk_size: int = 150,
        chunk_overlap: int = 50,
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
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.chunk_size, chunk_overlap=self.chunk_overlap
        )
        chunks = splitter.split_documents(documents)
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
        print(f"[VectorDB] Built store with {len(chunks)} chunks")

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
            return {"relevant": False, "similarity": 0.0, "threshold": threshold,
                    "error": "Vector store not initialized"}
        try:
            results = self.vectorstore.similarity_search_with_score(query, k=1)
            if not results:
                return {"relevant": False, "similarity": 0.0, "threshold": threshold,
                        "message": "No matching context found"}
            doc, score = results[0]
            similarity = (1 - score) * 100
            return {
                "relevant": similarity >= threshold,
                "similarity": round(similarity, 2),
                "threshold": threshold,
                "matched_content": doc.page_content[:200],
            }
        except Exception as e:
            return {"relevant": False, "similarity": 0.0, "threshold": threshold, "error": str(e)}

    def rebuild_from_pdf(self, new_pdf_path: str) -> Dict[str, Any]:
        try:
            self.pdf_path = new_pdf_path
            self.build()
            return {"success": True, "chunk_count": self._chunk_count}
        except Exception as e:
            return {"success": False, "error": str(e)}
