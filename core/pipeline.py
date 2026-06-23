"""
core/pipeline.py
================
Singleton filter instances — created once at import time.
All routers import from here so models are loaded only once.
"""
import state
from core.vector_db import PDFVectorStore
from core.rephrase_engine import InputRewriter, OutputRewriter
from filters.input.unicode_firewall import UnicodeFirewall
from filters.input.spacy_engine import InputSpacyEngine
from filters.input.bert_classifier import BertClassifier
from filters.input.pii_detector import PIIDetector
from filters.output.spacy_engine import OutputSpacyEngine
from document.doc_pipeline import DocPipeline
from alerts.soc_alerter import SOCAlerter

unicode_firewall    = UnicodeFirewall()
input_spacy         = InputSpacyEngine()
bert_classifier     = BertClassifier()
pii_detector        = PIIDetector()
output_spacy        = OutputSpacyEngine()
input_rewriter      = InputRewriter()
output_rewriter     = OutputRewriter()
soc_alerter         = SOCAlerter()

context_vectorstore = PDFVectorStore(
    pdf_path="",
    persist_directory=state.CONTEXT_SETTINGS["VECTOR_STORE_PATH"],
)

doc_pipeline = DocPipeline(
    unicode_firewall=unicode_firewall,
    input_spacy=input_spacy,
    bert_classifier=bert_classifier,
    pii_detector=pii_detector,
    output_rewriter=output_rewriter,
)
