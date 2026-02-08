# from langchain_community.document_loaders import PyPDFLoader

# loader = PyPDFLoader("/kaggle/input/chroma21/SOC Senior Specialist.pdf")
# docs = loader.load()

# print(docs[0].page_content[:300])
# Ahmed Abdeen


# from langchain_text_splitters import RecursiveCharacterTextSplitter

# text_splitter = RecursiveCharacterTextSplitter(
#     chunk_size=300,
#     chunk_overlap=50
# )

# chunks = text_splitter.split_documents(docs)

# print(len(chunks))
# print(chunks[0].page_content)


# from langchain_community.embeddings import HuggingFaceEmbeddings

# embeddings = HuggingFaceEmbeddings(
#     model_name="sentence-transformers/all-MiniLM-L6-v2",
#     encode_kwargs={"normalize_embeddings": True}
# )



# from langchain_chroma import Chroma

# vectorstore = Chroma.from_documents(
#     documents=chunks,
#     embedding=embeddings,
#     persist_directory="./chroma_soc",
#     collection_metadata={"hnsw:space": "cosine"}
# )


# query = "how to activate my credit card?"

# results = vectorstore.similarity_search_with_score(
#     query,
#     k=3
# )
# results


# for i, (doc, score) in enumerate(results):
#     print(f"\n--- Result {i+1} ---")
#     print(f"Similarity score (distance): {score:.4f}")
#     print(f"Page: {doc.metadata.get('page')}")
#     print(doc.page_content[:400])




# def cosine_distance_to_similarity(score):
#     return (1 - score) * 100

# for i, (doc, score) in enumerate(results):
#         print(f"\n--- Result {i+1} ---")
#         print(f"Similarity: {cosine_distance_to_similarity(score):.2f}%")
#         print(doc.page_content[:300])



#         # 1. Define the "Gatekeeper" Function
# def is_request_relevant(user_query, vectorstore, threshold=0.5):
#     """
#     Checks if the user query is relevant to the stored context 
#     based on vector distance.
#     """
#     # Perform similarity search
#     # k=1 because we only care if it matches ANY of our allowed topics closely
#     results = vectorstore.similarity_search_with_score(user_query, k=1)
    
#     if not results:
#         return False, 0.0, "No context found."

#     # Get the best match
#     best_doc, score = results[0]
    
#     # CRITICAL: specific to 'cosine' distance in Chroma/LangChain:
#     # Score = Cosine Distance (Lower is Better/Closer)
#     # 0.0 = Identical
#     # 1.0 = Unrelated
#     # > 1.0 = Opposite
    
#     # We want the distance to be LOW (close to 0)
#     # So if score > threshold, it is too far away (Irrelevant)
#     if score > threshold:
#         return False, score, best_doc.page_content
        
#     return True, score, best_doc.page_content

# # 2. Test the Gatekeeper
# # Define a threshold (Start with 0.5 and tune it)
# # 0.4 is strict, 0.6 is loose.
# STRICTNESS_THRESHOLD = 0.5 

# # Test Case A: Relevant Query (Should pass)
# query_good = "what is my current  balance ?"
# is_allowed, score, match = is_request_relevant(query_good, vectorstore, STRICTNESS_THRESHOLD)

# print(f"Query: {query_good}")
# print(f"Allowed: {is_allowed}")
# print(f"Distance Score: {score:.4f} (Lower is better)")
# print("-" * 30)

# # Test Case B: Irrelevant Query (Should be blocked)
# query_bad = " what is name of football player?"
# is_allowed, score, match = is_request_relevant(query_bad, vectorstore, STRICTNESS_THRESHOLD)

# print(f"Query: {query_bad}")
# print(f"Allowed: {is_allowed}")
# print(f"Distance Score: {score:.4f}")
# if not is_allowed:
#     print("Action: BLOCK - Context Violation")

# """
# Vector Database Setup and Query System
# ======================================
# This script demonstrates how to:
# 1. Load PDF documents
# 2. Split them into chunks
# 3. Create embeddings
# 4. Store in a vector database (Chroma)
# 5. Query with similarity search
# 6. Implement relevance gatekeeper
# """

# # =============================================================================
# # SECTION 1: IMPORTS
# # =============================================================================

# from langchain_community.document_loaders import PyPDFLoader
# from langchain_text_splitters import RecursiveCharacterTextSplitter
# from langchain_community.embeddings import HuggingFaceEmbeddings
# from langchain_chroma import Chroma


# # =============================================================================
# # SECTION 2: DOCUMENT LOADING
# # =============================================================================

# def load_documents(pdf_path):
#     """Load PDF document and return document objects."""
#     loader = PyPDFLoader(pdf_path)
#     docs = loader.load()
#     print(f"Loaded {len(docs)} pages from PDF")
#     print("\nFirst 300 characters of first page:")
#     print(docs[0].page_content[:300])
#     return docs


# # =============================================================================
# # SECTION 3: TEXT SPLITTING
# # =============================================================================

# def split_documents(docs, chunk_size=300, chunk_overlap=50):
#     """Split documents into smaller chunks for better embedding."""
#     text_splitter = RecursiveCharacterTextSplitter(
#         chunk_size=chunk_size,
#         chunk_overlap=chunk_overlap
#     )
    
#     chunks = text_splitter.split_documents(docs)
#     print(f"\nCreated {len(chunks)} chunks")
#     print("\nFirst chunk:")
#     print(chunks[0].page_content)
#     return chunks


# # =============================================================================
# # SECTION 4: EMBEDDINGS INITIALIZATION
# # =============================================================================

# def initialize_embeddings():
#     """Initialize HuggingFace embeddings model."""
#     embeddings = HuggingFaceEmbeddings(
#         model_name="sentence-transformers/all-MiniLM-L6-v2",
#         encode_kwargs={"normalize_embeddings": True}
#     )
#     print("\nEmbeddings model initialized")
#     return embeddings


# # =============================================================================
# # SECTION 5: VECTOR STORE CREATION
# # =============================================================================

# def create_vectorstore(chunks, embeddings, persist_directory="./chroma_DB"):
#     """Create and persist Chroma vector store from document chunks."""
#     vectorstore = Chroma.from_documents(
#         documents=chunks,
#         embedding=embeddings,
#         persist_directory=persist_directory,
#         collection_metadata={"hnsw:space": "cosine"}
#     )
#     print(f"\nVector store created and persisted to: {persist_directory}")
#     return vectorstore


# # =============================================================================
# # SECTION 6: SIMILARITY SEARCH
# # =============================================================================

# def perform_similarity_search(vectorstore, query, k=3):
#     """Perform similarity search and return results with scores."""
#     print(f"\n{'='*60}")
#     print(f"Query: {query}")
#     print(f"{'='*60}")
    
#     results = vectorstore.similarity_search_with_score(query, k=k)
#     return results


# def display_results(results):
#     """Display search results in a formatted way."""
#     for i, (doc, score) in enumerate(results):
#         print(f"\n--- Result {i+1} ---")
#         print(f"Similarity score (distance): {score:.4f}")
#         print(f"Page: {doc.metadata.get('page', 'N/A')}")
#         print(f"Content preview:\n{doc.page_content[:400]}")


# # =============================================================================
# # SECTION 7: UTILITY FUNCTIONS
# # =============================================================================

# def cosine_distance_to_similarity(score):
#     """
#     Convert cosine distance to similarity percentage.
    
#     Cosine distance ranges from 0 (identical) to 2 (opposite).
#     This converts it to a 0-100% similarity score.
#     """
#     return (1 - score) * 100


# def display_similarity_percentages(results):
#     """Display results with similarity percentages instead of distances."""
#     print("\n" + "="*60)
#     print("RESULTS WITH SIMILARITY PERCENTAGES")
#     print("="*60)
    
#     for i, (doc, score) in enumerate(results):
#         print(f"\n--- Result {i+1} ---")
#         print(f"Similarity: {cosine_distance_to_similarity(score):.2f}%")
#         print(f"Content preview:\n{doc.page_content[:300]}")


# # =============================================================================
# # SECTION 8: RELEVANCE GATEKEEPER
# # =============================================================================

# def is_request_relevant(user_query, vectorstore, threshold=0.5):
#     """
#     Checks if the user query is relevant to the stored context 
#     based on vector distance.
    
#     Args:
#         user_query (str): The user's question
#         vectorstore: The Chroma vector store
#         threshold (float): Maximum distance to consider relevant (0.4=strict, 0.6=loose)
    
#     Returns:
#         tuple: (is_relevant, score, best_match_content)
        
#     Note on Cosine Distance:
#         - 0.0 = Identical
#         - 1.0 = Unrelated
#         - >1.0 = Opposite
#         Lower scores mean higher similarity
#     """
#     # Perform similarity search (k=1 because we only need the best match)
#     results = vectorstore.similarity_search_with_score(user_query, k=1)
    
#     if not results:
#         return False, 0.0, "No context found."

#     # Get the best match
#     best_doc, score = results[0]
    
#     # If score > threshold, it's too far away (irrelevant)
#     if score > threshold:
#         return False, score, best_doc.page_content
        
#     return True, score, best_doc.page_content


# def test_gatekeeper(vectorstore, threshold=0.5):
#     """Test the relevance gatekeeper with sample queries."""
#     print("\n" + "="*60)
#     print("TESTING RELEVANCE GATEKEEPER")
#     print(f"Threshold: {threshold} (lower = stricter)")
#     print("="*60)
    
#     # Test Case 1: Relevant Query (Should pass)
#     query_relevant = "what is my current balance?"
#     is_allowed, score, match = is_request_relevant(query_relevant, vectorstore, threshold)
    
#     print(f"\nTest 1 - Relevant Query:")
#     print(f"Query: {query_relevant}")
#     print(f"Allowed: {is_allowed}")
#     print(f"Distance Score: {score:.4f} (Lower is better)")
#     print(f"Similarity: {cosine_distance_to_similarity(score):.2f}%")
#     print("-" * 30)
    
#     # Test Case 2: Irrelevant Query (Should be blocked)
#     query_irrelevant = "what is the name of a football player?"
#     is_allowed, score, match = is_request_relevant(query_irrelevant, vectorstore, threshold)
    
#     print(f"\nTest 2 - Irrelevant Query:")
#     print(f"Query: {query_irrelevant}")
#     print(f"Allowed: {is_allowed}")
#     print(f"Distance Score: {score:.4f}")
#     print(f"Similarity: {cosine_distance_to_similarity(score):.2f}%")
#     if not is_allowed:
#         print("✗ Action: BLOCKED - Context Violation")
#     else:
#         print("✓ Action: ALLOWED")


# # =============================================================================
# # SECTION 9: MAIN EXECUTION
# # =============================================================================

# def main():
#     """Main execution function."""
    
#     # Configuration
#     PDF_PATH = r"C:\Users\ahmed\OneDrive\Desktop\Project\AI-Proxy\Chatbot\banking_questions.pdf"
#     CHUNK_SIZE = 300
#     CHUNK_OVERLAP = 50
#     PERSIST_DIR = "./chroma_DB"
#     STRICTNESS_THRESHOLD = 0.5
    
#     print("="*60)
#     print("VECTOR DATABASE SETUP AND QUERY SYSTEM")
#     print("="*60)
    
#     # Step 1: Load documents
#     docs = load_documents(PDF_PATH)
    
#     # Step 2: Split into chunks
#     chunks = split_documents(docs, CHUNK_SIZE, CHUNK_OVERLAP)
    
#     # Step 3: Initialize embeddings
#     embeddings = initialize_embeddings()
    
#     # Step 4: Create vector store
#     vectorstore = create_vectorstore(chunks, embeddings, PERSIST_DIR)
    
#     # Step 5: Perform sample query
#     query = "explain Network Intrusion Detection Systems"
#     results = perform_similarity_search(vectorstore, query, k=3)
    
#     # Step 6: Display results
#     display_results(results)
    
#     # Step 7: Display with similarity percentages
#     display_similarity_percentages(results)
    
#     # Step 8: Test relevance gatekeeper
#     test_gatekeeper(vectorstore, STRICTNESS_THRESHOLD)
    
#     print("\n" + "="*60)
#     print("PROCESS COMPLETE")
#     print("="*60)


# # =============================================================================
# # ENTRY POINT
# # =============================================================================

# if __name__ == "__main__":
#     main()


# """
# Vector Database Setup and Query System (Production Version)
# ==========================================================

# This script demonstrates:
# 1. Load PDF documents
# 2. Split into chunks
# 3. Create embeddings
# 4. Store in Chroma vector DB (persisted)
# 5. Load existing DB without re-embedding
# 6. Query with similarity search
# 7. Relevance gatekeeper

# Author: Abdeen (modified & improved)
# """

# import os
# from langchain_community.document_loaders import PyPDFLoader
# from langchain_text_splitters import RecursiveCharacterTextSplitter
# from langchain_community.embeddings import HuggingFaceEmbeddings
# from langchain_chroma import Chroma


# # =============================================================================
# # SECTION 1: DOCUMENT LOADING
# # =============================================================================

# def load_documents(pdf_path):
#     """Load PDF document and return document objects."""
#     loader = PyPDFLoader(pdf_path)
#     docs = loader.load()

#     print(f"\n✅ Loaded {len(docs)} pages from PDF")
#     print("\n📌 First 300 characters of first page:")
#     print(docs[0].page_content[:300])

#     return docs


# # =============================================================================
# # SECTION 2: TEXT SPLITTING
# # =============================================================================

# def split_documents(docs, chunk_size=800, chunk_overlap=120):
#     """Split documents into smaller chunks for better embedding."""
#     text_splitter = RecursiveCharacterTextSplitter(
#         chunk_size=chunk_size,
#         chunk_overlap=chunk_overlap
#     )

#     chunks = text_splitter.split_documents(docs)

#     print(f"\n✅ Created {len(chunks)} chunks")
#     print("\n📌 First chunk preview:")
#     print(chunks[0].page_content[:400])

#     return chunks


# # =============================================================================
# # SECTION 3: EMBEDDINGS INITIALIZATION
# # =============================================================================

# def initialize_embeddings():
#     """Initialize HuggingFace embeddings model."""
#     embeddings = HuggingFaceEmbeddings(
#         model_name="sentence-transformers/all-MiniLM-L6-v2",
#         encode_kwargs={"normalize_embeddings": True}
#     )
#     print("\n✅ Embeddings model initialized: all-MiniLM-L6-v2")
#     return embeddings


# # =============================================================================
# # SECTION 4: VECTOR STORE (CREATE OR LOAD)
# # =============================================================================

# def create_or_load_vectorstore(pdf_path, embeddings, persist_directory="./chroma_DB"):
#     """
#     Creates the DB the FIRST time.
#     If DB exists, loads it without re-embedding.
#     """

#     os.makedirs(persist_directory, exist_ok=True)

#     db_marker = os.path.join(persist_directory, "chroma.sqlite3")

#     # If DB already exists → load it
#     if os.path.exists(db_marker):
#         print(f"\n⚡ Found existing Chroma DB → Loading from: {persist_directory}")
#         vectorstore = Chroma(
#             persist_directory=persist_directory,
#             embedding_function=embeddings
#         )
#         print("✅ Vector store loaded successfully (no re-embedding).")
#         return vectorstore

#     # Else → create it first time
#     print(f"\n🆕 No DB found → Creating Chroma DB in: {persist_directory}")
#     docs = load_documents(pdf_path)
#     chunks = split_documents(docs)

#     vectorstore = Chroma.from_documents(
#         documents=chunks,
#         embedding=embeddings,
#         persist_directory=persist_directory,
#         collection_metadata={"hnsw:space": "cosine"}
#     )

#     print("✅ Vector store created and persisted automatically.")
#     return vectorstore



# # =============================================================================
# # SECTION 5: SIMILARITY SEARCH
# # =============================================================================

# def perform_similarity_search(vectorstore, query, k=3):
#     """Perform similarity search and return results with scores."""
#     print(f"\n{'='*70}")
#     print(f"🔎 Query: {query}")
#     print(f"{'='*70}")

#     results = vectorstore.similarity_search_with_score(query, k=k)
#     return results


# def display_results(results):
#     """Display search results in a formatted way."""
#     for i, (doc, score) in enumerate(results):
#         page = doc.metadata.get("page", "N/A")
#         source = doc.metadata.get("source", "N/A")

#         print(f"\n--- Result {i+1} ---")
#         print(f"Distance Score: {score:.4f} (lower = more relevant)")
#         print(f"Page: {page}")
#         print(f"Source: {source}")
#         print(f"Preview:\n{doc.page_content[:400]}")


# # =============================================================================
# # SECTION 6: UTILITY FUNCTIONS
# # =============================================================================

# def cosine_distance_to_similarity(score):
#     """
#     Convert cosine distance to similarity percentage.
#     Distance is usually in [0, 1] for most real cases.
#     But can theoretically reach 2.0.
#     """
#     similarity = (1 - score) * 100
#     return max(0, min(100, similarity))


# def display_similarity_percentages(results):
#     """Display results with similarity percentages instead of distances."""
#     print("\n" + "="*70)
#     print("📊 RESULTS WITH SIMILARITY PERCENTAGES")
#     print("="*70)

#     for i, (doc, score) in enumerate(results):
#         sim = cosine_distance_to_similarity(score)
#         page = doc.metadata.get("page", "N/A")

#         print(f"\n--- Result {i+1} ---")
#         print(f"Similarity: {sim:.2f}%")
#         print(f"Page: {page}")
#         print(f"Preview:\n{doc.page_content[:300]}")


# # =============================================================================
# # SECTION 7: RELEVANCE GATEKEEPER
# # =============================================================================

# def is_request_relevant(user_query, vectorstore, threshold=0.7):
#     """
#     Checks if the user query is relevant to the stored context
#     based on vector distance.
#     """

#     # Search top 3 instead of only top 1
#     results = vectorstore.similarity_search_with_score(user_query, k=3)

#     if not results:
#         return False, 999.0, "No context found."

#     # Best match is first result
#     best_doc, score = results[0]

#     # If score > threshold => block
#     if score > threshold:
#         return False, score, best_doc.page_content

#     return True, score, best_doc.page_content


# def test_gatekeeper(vectorstore, threshold=0.5):
#     """Test the relevance gatekeeper with sample queries."""
#     print("\n" + "="*70)
#     print("🛡 TESTING RELEVANCE GATEKEEPER")
#     print(f"Threshold: {threshold} (lower = stricter)")
#     print("="*70)

#     test_queries = [
#         "How can I check my account balance?",
#         "What is the name of a famous football player?",
#         "How do I reset my online banking password?",
#         "Explain quantum physics in simple terms."
#     ]

#     for i, q in enumerate(test_queries, start=1):
#         allowed, score, match = is_request_relevant(q, vectorstore, threshold)

#         print(f"\nTest {i}: {q}")
#         print(f"Allowed: {allowed}")
#         print(f"Distance: {score:.4f}")
#         print(f"Similarity: {cosine_distance_to_similarity(score):.2f}%")

#         if not allowed:
#             print("✗ BLOCKED (irrelevant to stored PDF context)")
#         else:
#             print("✓ ALLOWED")


# # =============================================================================
# # SECTION 8: MAIN
# # =============================================================================

# def main():
#     # Configuration
#     PDF_PATH = r"C:\Users\ahmed\OneDrive\Desktop\Project\AI-Proxy\Chatbot\banking_questions.pdf"
#     PERSIST_DIR = "./chroma_DB"

#     STRICTNESS_THRESHOLD = 0.70
#     TOP_K = 3

#     print("="*70)
#     print("VECTOR DATABASE SETUP AND QUERY SYSTEM (PRO VERSION)")
#     print("="*70)

#     embeddings = initialize_embeddings()

#     # Create DB only first time, otherwise load
#     vectorstore = create_or_load_vectorstore(
#         pdf_path=PDF_PATH,
#         embeddings=embeddings,
#         persist_directory=PERSIST_DIR
#     )

#     # Test gatekeeper
#     test_gatekeeper(vectorstore, STRICTNESS_THRESHOLD)

#     # Interactive query mode
#     print("\n" + "="*70)
#     print("💬 INTERACTIVE MODE (type 'exit' to stop)")
#     print("="*70)

#     while True:
#         query = input("\nEnter your query: ").strip()

#         if query.lower() in ["exit", "quit"]:
#             print("👋 Exiting...")
#             break

#         allowed, score, match = is_request_relevant(query, vectorstore, STRICTNESS_THRESHOLD)

#         if not allowed:
#             print("\n🚫 BLOCKED: Query is not relevant to the stored PDF context.")
#             print(f"Distance: {score:.4f}")
#             print(f"Best match preview:\n{match[:300]}")
#             continue

#         results = perform_similarity_search(vectorstore, query, k=TOP_K)
#         display_results(results)
#         display_similarity_percentages(results)

#     print("\n✅ Done.")


# if __name__ == "__main__":
#     main()

# from langchain_community.document_loaders import PyPDFLoader
# from langchain_text_splitters import RecursiveCharacterTextSplitter
# from langchain_community.embeddings import HuggingFaceEmbeddings
# from langchain_chroma import Chroma

# loader = PyPDFLoader(r"C:\Users\ahmed\OneDrive\Desktop\Project\AI-Proxy\Chatbot\banking_questions.pdf")
# docs = loader.load()

# text_splitter = RecursiveCharacterTextSplitter(
#     chunk_size=150,
#     chunk_overlap=50
# )
# chunks = text_splitter.split_documents(docs)
# print(len(chunks))

# embeddings = HuggingFaceEmbeddings(
#     model_name="sentence-transformers/all-MiniLM-L6-v2",
#     encode_kwargs={"normalize_embeddings": True}
# )

# vectorstore = Chroma.from_documents(
#     documents=chunks,
#     embedding=embeddings,
#     persist_directory="./tona_zeft",
#     collection_metadata={"hnsw:space": "cosine"}
# )

# query = "How do I activate my new debit card?"

# results = vectorstore.similarity_search_with_score( query,k=1 )

# def cosine_distance_to_similarity(score):
#     return (1 - score) * 100

# for i, (doc, score) in enumerate(results):
#     print(f"\n--- Result {i+1} ---")
#     print(f"Similarity: {cosine_distance_to_similarity(score):.2f}%")
#     print(doc.page_content[:300])



# # ------------------------------------------------------------------------------- # 

# from langchain_community.document_loaders import PyPDFLoader
# from langchain_text_splitters import RecursiveCharacterTextSplitter
# from langchain_community.embeddings import HuggingFaceEmbeddings
# from langchain_chroma import Chroma
# from typing import List, Tuple

# # -----------------------------
# # Configuration
# # -----------------------------
# PDF_PATH = r"C:\Users\ahmed\OneDrive\Desktop\Project\AI-Proxy\Chatbot\banking_questions.pdf"
# VECTOR_DB_DIR = "./Abdeen"
# EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

# CHUNK_SIZE = 100
# CHUNK_OVERLAP = 30


# # -----------------------------
# # Utility Functions
# # -----------------------------
# def load_pdf(path: str):
#     """Load PDF document."""
#     loader = PyPDFLoader(path)
#     return loader.load()


# def split_documents(docs, chunk_size: int, overlap: int):
#     """Split documents into overlapping chunks."""
#     splitter = RecursiveCharacterTextSplitter(
#         chunk_size=chunk_size,
#         chunk_overlap=overlap
#     )
#     return splitter.split_documents(docs)


# def create_embeddings(model_name: str):
#     """Initialize HuggingFace embeddings."""
#     return HuggingFaceEmbeddings(
#         model_name=model_name,
#         encode_kwargs={"normalize_embeddings": True}
#     )


# def build_vector_store(chunks, embeddings, persist_dir: str):
#     """Create and persist Chroma vector store."""
#     return Chroma.from_documents(
#         documents=chunks,
#         embedding=embeddings,
#         persist_directory=persist_dir,
#         collection_metadata={"hnsw:space": "cosine"}
#     )


# def cosine_distance_to_similarity(score: float) -> float:
#     """
#     Convert cosine distance to similarity percentage.
#     Chroma returns distance when using cosine space.
#     """
#     return (1 - score) * 100


# def search_query(
#     vectorstore,
#     query: str,
#     k: int = 1
# ) -> List[Tuple[str, float]]:
#     """Perform similarity search."""
#     return vectorstore.similarity_search_with_score(query, k=k)


# # -----------------------------
# # Main Execution
# # -----------------------------
# # def main():
# #     # Load and split documents
# #     documents = load_pdf(PDF_PATH)
# #     chunks = split_documents(documents, CHUNK_SIZE, CHUNK_OVERLAP)
# #     print(f"[+] Total chunks created: {len(chunks)}")

# #     # Create embeddings
# #     embeddings = create_embeddings(EMBEDDING_MODEL)

# #     # Build vector database
# #     vectorstore = build_vector_store(chunks, embeddings, VECTOR_DB_DIR)

# #     # Query
# #     query = "who is the best player ?"
# #     results = search_query(vectorstore, query, k=2)

# #     # Display results
# #     for idx, (doc, score) in enumerate(results, start=1):
# #         similarity = cosine_distance_to_similarity(score)
# #         print(f"\n--- Result {idx} ---")
# #         print(f"Similarity: {similarity:.2f}%")
# #         print(doc.page_content[:300])


# # if __name__ == "__main__":
# #     main()


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