# state.py

FEATURES = {
    # INPUT PHASE
    "INPUT_SPACY_FIREWALL": False,
    "BERT_FIREWALL": False,
    "INPUT_PII_FIREWALL": False,
    "INPUT_CONTEXT_RELEVANCE": False,

    # OUTPUT PHASE
    "OUTPUT_SPACY_FIREWALL": False,
    "OUTPUT_PII_FIREWALL": False,
    "OUTPUT_CONTEXT_RELEVANCE": False,
}

# Shared settings for similarity checks
CONTEXT_SETTINGS = {
    "SIMILARITY_THRESHOLD": 50,          # percentage from 0 to 100
    "VECTOR_STORE_PATH": "./context_vectorstore",
    "pdf_uploaded": False,
    "chunk_count": 0,
}
