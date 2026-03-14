from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from typing import List, Tuple, Dict, Any
import os
import shutil
import json


class PDFVectorStore:
    """
    Handles:
    - Loading PDF documents
    - Chunking text
    - Creating embeddings
    - Building a Chroma vector store
    - Performing similarity search
    - Dynamic PDF upload and vector store management
    """

    def __init__(
        self,
        pdf_path: str,
        persist_directory: str,
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

    # -----------------------------
    # Internal Setup Methods
    # -----------------------------
    def _load_documents(self):
        loader = PyPDFLoader(self.pdf_path)
        return loader.load()

    def _split_documents(self, documents):
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.chunk_size,
            chunk_overlap=self.chunk_overlap
        )
        return splitter.split_documents(documents)

    def _create_embeddings(self):
        return HuggingFaceEmbeddings(
            model_name=self.embedding_model,
            encode_kwargs={"normalize_embeddings": True}
        )

    # -----------------------------
    # Public API
    # -----------------------------
    def build(self):
        """Build and persist the vector store."""
        documents = self._load_documents()
        chunks = self._split_documents(documents)
        embeddings = self._create_embeddings()

        # Remove existing vector store if present
        if os.path.exists(self.persist_directory):
            shutil.rmtree(self.persist_directory)

        self.vectorstore = Chroma.from_documents(
            documents=chunks,
            embedding=embeddings,
            persist_directory=self.persist_directory,
            collection_metadata={"hnsw:space": "cosine"}
        )

        self._chunk_count = len(chunks)
        self._is_loaded = True
        print(f"[+] Vector store built with {len(chunks)} chunks")

    def load(self):
        """Load an existing vector store from disk."""
        embeddings = self._create_embeddings()
        self.vectorstore = Chroma(
            persist_directory=self.persist_directory,
            embedding_function=embeddings
        )

        # Get chunk count
        if self.vectorstore:
            self._chunk_count = self.vectorstore._collection.count()
            self._is_loaded = True

        print("[+] Vector store loaded from disk")

    def similarity_search(
        self,
        query: str,
        k: int = 1
    ) -> List[Tuple[str, float]]:
        """Perform similarity search with score."""
        if not self.vectorstore:
            raise RuntimeError("Vector store is not initialized. Call build() or load().")

        return self.vectorstore.similarity_search_with_score(query, k=k)

    @staticmethod
    def cosine_distance_to_similarity(score: float) -> float:
        """Convert cosine distance to similarity percentage."""
        return (1 - score) * 100

    def query(
        self,
        query: str,
        k: int = 1,
        min_similarity: float | None = None
    ):
        """
        Query the vector store with optional similarity threshold.
        """
        results = self.similarity_search(query, k)

        formatted_results = []
        for doc, score in results:
            similarity = self.cosine_distance_to_similarity(score)

            if min_similarity is not None and similarity < min_similarity:
                continue

            formatted_results.append({
                "similarity": round(similarity, 2),
                "content": doc.page_content,
                "metadata": doc.metadata
            })

        return formatted_results

    # -----------------------------
    # Context Relevance Methods
    # -----------------------------
    def is_ready(self) -> bool:
        """Check if vector store is ready for similarity search."""
        return self._is_loaded and self.vectorstore is not None

    def get_status(self) -> Dict[str, Any]:
        """Get current status of the vector store."""
        return {
            "is_loaded": self._is_loaded,
            "chunk_count": self._chunk_count,
            "pdf_path": self.pdf_path if os.path.exists(self.pdf_path) else None,
            "persist_directory": self.persist_directory
        }

    def check_relevance(
        self,
        query: str,
        threshold: float = 50.0
    ) -> Dict[str, Any]:
        """
        Check if a query is relevant to the stored context.
        
        Args:
            query: User's input prompt
            threshold: Minimum similarity percentage (0-100)
            
        Returns:
            Dictionary with relevance status and details
        """
        if not self.is_ready():
            return {
                "relevant": False,
                "similarity": 0.0,
                "threshold": threshold,
                "error": "Vector store not initialized"
            }

        try:
            results = self.query(query, k=1)
            
            if not results:
                return {
                    "relevant": False,
                    "similarity": 0.0,
                    "threshold": threshold,
                    "message": "No matching context found"
                }

            top_result = results[0]
            similarity = top_result["similarity"]

            return {
                "relevant": similarity >= threshold,
                "similarity": similarity,
                "threshold": threshold,
                "matched_content": top_result["content"][:200] + "..." if len(top_result["content"]) > 200 else top_result["content"]
            }

        except Exception as e:
            return {
                "relevant": False,
                "similarity": 0.0,
                "threshold": threshold,
                "error": str(e)
            }

    def rebuild_from_pdf(self, new_pdf_path: str) -> Dict[str, Any]:
        """
        Rebuild vector store from a new PDF file.
        
        Args:
            new_pdf_path: Path to the new PDF file
            
        Returns:
            Dictionary with rebuild status
        """
        try:
            self.pdf_path = new_pdf_path
            self.build()
            return {
                "success": True,
                "chunk_count": self._chunk_count,
                "message": "Vector store rebuilt successfully"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to rebuild vector store"
            }
