from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from typing import List, Tuple

class PDFVectorStore:
    """
    Handles:
    - Loading PDF documents
    - Chunking text
    - Creating embeddings
    - Building a Chroma vector store
    - Performing similarity search
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

        self.vectorstore = Chroma.from_documents(
            documents=chunks,
            embedding=embeddings,
            persist_directory=self.persist_directory,
            collection_metadata={"hnsw:space": "cosine"}
        )

        print(f"[+] Vector store built with {len(chunks)} chunks")

    def load(self):
        """Load an existing vector store from disk."""
        embeddings = self._create_embeddings()
        self.vectorstore = Chroma(
            persist_directory=self.persist_directory,
            embedding_function=embeddings
        )

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