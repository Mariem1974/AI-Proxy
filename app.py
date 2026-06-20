"""
app.py
======
AI-Proxy Chatbot — FastAPI Backend (v2)

Full Input Pipeline:
  ① Unicode Firewall    (emoji stego + homoglyph)     [NEW]
  ② Input spaCy Engine  (rules v2)                    [UPGRADED]
  ③ BERT Classifier     (ModernBERT + rephrase loop)  [UPGRADED]
  ④ PII Detection       (GLiNER)
  ⑤ Context Relevance   (ChromaDB)

Full Output Pipeline:
  ⑥ Output spaCy Engine (rules v2, redaction)         [UPGRADED]
  ⑦ PII Detection       (GLiNER + Llama3.2 rewriter)
  ⑧ Context Relevance   (ChromaDB)

Document Pipeline:                                    [NEW]
  FileGate → Extract → Normalize → Unicode → spaCy → BERT → PII

Admin toggles, SOC alerting, JSON log export.
"""

import os
import json
import hashlib
import tempfile
from datetime import datetime
from dotenv import load_dotenv

from fastapi import FastAPI, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

load_dotenv()

# ── Core modules ──────────────────────────────────────────────────────────────
import state
import auth
from core.llm import chat_stream, reset_memory
from core.vector_db import PDFVectorStore
from core.rephrase_engine import InputRewriter, OutputRewriter

# ── Input filters ─────────────────────────────────────────────────────────────
from filters.input.unicode_firewall import UnicodeFirewall
from filters.input.spacy_engine import InputSpacyEngine
from filters.input.bert_classifier import BertClassifier
from filters.input.pii_detector import PIIDetector

# ── Output filters ────────────────────────────────────────────────────────────
from filters.output.spacy_engine import OutputSpacyEngine

# ── Document pipeline ─────────────────────────────────────────────────────────
from document.doc_pipeline import DocPipeline

# ── Alerting ──────────────────────────────────────────────────────────────────
from alerts.soc_alerter import SOCAlerter

# ─────────────────────────────────────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="AI-Proxy Chatbot v2")

REACT_DIST_PATH = os.path.join(os.path.dirname(__file__), "frontend", "dist")
templates = Jinja2Templates(directory="templates")

# ─────────────────────────────────────────────────────────────────────────────
# Singleton filter instances  (loaded once at startup)
# ─────────────────────────────────────────────────────────────────────────────
unicode_firewall   = UnicodeFirewall()
input_spacy        = InputSpacyEngine()
bert_classifier    = BertClassifier()
pii_detector       = PIIDetector()
output_spacy       = OutputSpacyEngine()
input_rewriter     = InputRewriter()
output_rewriter    = OutputRewriter()
soc_alerter        = SOCAlerter()

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


# ─────────────────────────────────────────────────────────────────────────────
# Helper: SOC alert + user block escalation
# ─────────────────────────────────────────────────────────────────────────────
def _handle_violation(user_id, username, prompt, detection_type, settings):
    """Log event, escalate blocking, send SOC alert. Returns JSONResponse if blocked, else None."""
    auth.log_security_event(user_id, username, prompt, detection_type, "blocked", "HIGH")

    result = auth.increment_failed_attempts(user_id)
    if result["action"] == "block":
        block_result = auth.block_user_temp(user_id)
        if block_result.get("permanent"):
            soc_alerter.alert("CRITICAL", user_id, username, prompt, "PERMANENT_BLOCK", "permanent_block", settings)
            return JSONResponse(status_code=403, content={"message": "You have been permanently blocked due to repeated violations."})
        else:
            soc_alerter.alert("HIGH", user_id, username, prompt, "TEMP_BLOCK", "temporary_block", settings)
            tb = block_result.get("temp_blocks", "?")
            return JSONResponse(status_code=403, content={"message": f"Temporary block applied. You have {tb}/3 temporary blocks."})

    soc_alerter.alert("HIGH", user_id, username, prompt, detection_type, "blocked", settings)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Request models
# ─────────────────────────────────────────────────────────────────────────────
class ChatMessage(BaseModel):
    message: str
    user_id: int = None


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str


class LoginRequest(BaseModel):
    username: str
    password: str


# ─────────────────────────────────────────────────────────────────────────────
# SPA pages
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    index_path = os.path.join(REACT_DIST_PATH, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return templates.TemplateResponse("chat.html", {"request": request})


@app.get("/admin", response_class=HTMLResponse)
async def admin(request: Request):
    index_path = os.path.join(REACT_DIST_PATH, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return templates.TemplateResponse("admin.html", {"request": request})


# ─────────────────────────────────────────────────────────────────────────────
# AUTH ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/auth/register")
async def register(body: RegisterRequest):
    result = auth.create_user(body.username, body.password, body.email, "user")
    if not result["success"]:
        return JSONResponse(status_code=400, content={"error": result["error"]})
    return JSONResponse(content={"message": "Registration successful", "user": result["user"]})


@app.post("/api/auth/login")
async def login(body: LoginRequest):
    result = auth.verify_user(body.username, body.password)
    if not result:
        return JSONResponse(status_code=401, content={"error": "Invalid credentials"})
    if not result.get("success"):
        if result.get("blocked"):
            return JSONResponse(status_code=403, content={"error": "User is blocked"})
        return JSONResponse(status_code=401, content={"error": result.get("error", "Invalid credentials")})
    token = hashlib.sha256(
        f"{result['user']['id']}_{body.username}_{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()
    return JSONResponse(content={"token": token, "user": result["user"]})


@app.get("/api/auth/me")
async def get_current_user(user_id: int = None):
    if not user_id:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    auth.check_and_release_expired_blocks(user_id)
    user = auth.get_user_by_id(user_id)
    if not user:
        return JSONResponse(status_code=404, content={"error": "User not found"})
    return JSONResponse(content={"user": user})


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE TOGGLES — INPUT
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/toggle/input-unicode")
async def toggle_unicode():
    state.FEATURES["INPUT_UNICODE_FIREWALL"] = not state.FEATURES["INPUT_UNICODE_FIREWALL"]
    return JSONResponse(content={"input_unicode": state.FEATURES["INPUT_UNICODE_FIREWALL"]})


@app.post("/api/toggle/input-spacy")
async def toggle_input_spacy():
    state.FEATURES["INPUT_SPACY_FIREWALL"] = not state.FEATURES["INPUT_SPACY_FIREWALL"]
    return JSONResponse(content={"input_spacy": state.FEATURES["INPUT_SPACY_FIREWALL"]})


@app.post("/api/toggle/bert")
async def toggle_bert():
    state.FEATURES["BERT_FIREWALL"] = not state.FEATURES["BERT_FIREWALL"]
    return JSONResponse(content={"bert": state.FEATURES["BERT_FIREWALL"]})


@app.post("/api/toggle/input-pii")
async def toggle_input_pii():
    state.FEATURES["INPUT_PII_FIREWALL"] = not state.FEATURES["INPUT_PII_FIREWALL"]
    return JSONResponse(content={"input_pii": state.FEATURES["INPUT_PII_FIREWALL"]})


@app.post("/api/toggle/input-context")
async def toggle_input_context():
    if not state.FEATURES["INPUT_CONTEXT_RELEVANCE"]:
        if not context_vectorstore.is_ready():
            return JSONResponse(status_code=400, content={"error": "Upload a domain PDF before enabling context filter."})
    state.FEATURES["INPUT_CONTEXT_RELEVANCE"] = not state.FEATURES["INPUT_CONTEXT_RELEVANCE"]
    return JSONResponse(content={"input_context": state.FEATURES["INPUT_CONTEXT_RELEVANCE"], "vectorstore_status": context_vectorstore.get_status()})


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE TOGGLES — OUTPUT
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/toggle/output-spacy")
async def toggle_output_spacy():
    state.FEATURES["OUTPUT_SPACY_FIREWALL"] = not state.FEATURES["OUTPUT_SPACY_FIREWALL"]
    return JSONResponse(content={"output_spacy": state.FEATURES["OUTPUT_SPACY_FIREWALL"]})


@app.post("/api/toggle/output-pii")
async def toggle_output_pii():
    state.FEATURES["OUTPUT_PII_FIREWALL"] = not state.FEATURES["OUTPUT_PII_FIREWALL"]
    return JSONResponse(content={"output_pii": state.FEATURES["OUTPUT_PII_FIREWALL"]})


@app.post("/api/toggle/output-context")
async def toggle_output_context():
    if not state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"]:
        if not context_vectorstore.is_ready():
            return JSONResponse(status_code=400, content={"error": "Upload a domain PDF before enabling context filter."})
    state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"] = not state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"]
    return JSONResponse(content={"output_context": state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"]})


@app.post("/api/toggle/document-processing")
async def toggle_document_processing():
    state.FEATURES["DOCUMENT_PROCESSING"] = not state.FEATURES["DOCUMENT_PROCESSING"]
    return JSONResponse(content={"document_processing": state.FEATURES["DOCUMENT_PROCESSING"]})


# ─────────────────────────────────────────────────────────────────────────────
# BERT MODEL SELECTION
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/bert/model")
async def set_bert_model(model: str = Form(...)):
    if model not in ("modernbert", "distilbert"):
        return JSONResponse(status_code=400, content={"error": "model must be 'modernbert' or 'distilbert'"})
    state.BERT_SETTINGS["ACTIVE_MODEL"] = model
    return JSONResponse(content={"active_model": model})


@app.get("/api/bert/model")
async def get_bert_model():
    return JSONResponse(content={
        "active_model": state.BERT_SETTINGS["ACTIVE_MODEL"],
        "loaded_model": bert_classifier.active_model_name,
    })


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT / VECTOR DB
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/set-threshold")
async def set_threshold(threshold: float = Form(...)):
    if not (0 <= threshold <= 100):
        return JSONResponse(status_code=400, content={"error": "Threshold must be 0–100"})
    state.CONTEXT_SETTINGS["SIMILARITY_THRESHOLD"] = threshold
    return JSONResponse(content={"threshold": threshold})


@app.post("/api/upload-context-pdf")
async def upload_context_pdf(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".pdf"):
        return JSONResponse(status_code=400, content={"error": "Only PDF files are allowed"})
    temp_path = os.path.join(tempfile.gettempdir(), f"context_{file.filename}")
    try:
        with open(temp_path, "wb") as f:
            f.write(await file.read())
        result = context_vectorstore.rebuild_from_pdf(temp_path)
        if result["success"]:
            state.CONTEXT_SETTINGS["pdf_uploaded"] = True
            state.CONTEXT_SETTINGS["chunk_count"] = result["chunk_count"]
            return JSONResponse(content={"success": True, "chunk_count": result["chunk_count"], "vectorstore_status": context_vectorstore.get_status()})
        return JSONResponse(status_code=500, content={"error": result.get("error", "Failed to build vector store")})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.get("/api/vectorstore-status")
async def get_vectorstore_status():
    return JSONResponse(content=context_vectorstore.get_status())


# ─────────────────────────────────────────────────────────────────────────────
# FEATURES STATE
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/features")
async def get_features():
    return JSONResponse(content={**state.FEATURES, "bert_settings": state.BERT_SETTINGS})


# ─────────────────────────────────────────────────────────────────────────────
# USERS & ALERTS
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/users")
async def get_users():
    return JSONResponse(content={"users": auth.get_all_users()})


@app.post("/api/users/unblock/{user_id}")
async def unblock_user_endpoint(user_id: int):
    auth.unblock_user(user_id)
    return JSONResponse(content={"message": "User unblocked"})


@app.get("/api/alert-settings")
async def get_alert_settings():
    return JSONResponse(content=auth.get_alert_settings())


@app.post("/api/alert-settings")
async def update_alert_settings(
    max_attempts_to_block: int = Form(...),
    warning_window_minutes: int = Form(...),
    block_duration_minutes: int = Form(...),
    max_temp_blocks: int = Form(3),
    enable_email: bool = Form(False),
    enable_telegram: bool = Form(False),
    email_address: str = Form(""),
    telegram_chat_id: str = Form(""),
):
    settings = {
        "max_attempts_to_block": max_attempts_to_block,
        "warning_window_minutes": warning_window_minutes,
        "block_duration_minutes": block_duration_minutes,
        "max_temp_blocks": max_temp_blocks,
        "enable_email": enable_email,
        "enable_telegram": enable_telegram,
        "email_address": email_address,
        "telegram_chat_id": telegram_chat_id,
    }
    result = auth.update_alert_settings(settings)
    return JSONResponse(content={"message": "Alert settings updated", "settings": result})


@app.get("/api/security-logs")
async def get_security_logs(limit: int = 100):
    return JSONResponse(content={"logs": auth.get_security_logs(limit)})


@app.get("/api/security-logs/download")
async def download_security_logs_json():
    """Download the security_logs.json file."""
    if not os.path.exists(auth.LOGS_JSON_PATH):
        return JSONResponse(status_code=404, content={"error": "No logs file yet"})
    return FileResponse(auth.LOGS_JSON_PATH, media_type="application/json", filename="security_logs.json")


# ─────────────────────────────────────────────────────────────────────────────
# DOCUMENT UPLOAD ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/upload-document")
async def upload_document(file: UploadFile = File(...), user_id: int = Form(None)):
    """
    Upload a document (PDF, DOCX, image, TXT) for security scanning.
    Returns safe_context string to append to the user's next prompt.
    """
    if not state.FEATURES["DOCUMENT_PROCESSING"]:
        return JSONResponse(status_code=400, content={"error": "Document processing is disabled."})

    temp_path = os.path.join(tempfile.gettempdir(), f"doc_{file.filename}")
    try:
        with open(temp_path, "wb") as f:
            f.write(await file.read())

        result = doc_pipeline.run(temp_path, active_features=state.FEATURES)

        username = "anonymous"
        if user_id:
            user = auth.get_user_by_id(user_id)
            if user:
                username = user["username"]

        if result.final_decision == "BLOCK":
            if user_id:
                auth.log_security_event(
                    user_id, username, f"[FILE:{file.filename}]",
                    "DOCUMENT_BLOCKED", "blocked", "HIGH",
                    {"reason": result.block_reason, "stats": result.stats},
                )
                settings = auth.get_alert_settings()
                block_resp = _handle_violation(user_id, username, f"[FILE:{file.filename}]", "DOCUMENT_BLOCKED", settings)
                if block_resp:
                    return block_resp
            return JSONResponse(status_code=400, content={
                "message": f"Document blocked: {result.block_reason}",
                "stats": result.stats,
            })

        return JSONResponse(content={
            "success": True,
            "safe_context": result.safe_context,
            "stats": result.stats,
        })

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ─────────────────────────────────────────────────────────────────────────────
# CHAT ENDPOINT — Full Pipeline
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/chat")
async def chat(body: ChatMessage):
    user_input = body.message
    user_id = body.user_id
    username = "anonymous"
    settings = auth.get_alert_settings()

    if user_id:
        auth.check_and_release_expired_blocks(user_id)
        user = auth.get_user_by_id(user_id)
        if user:
            username = user["username"]
            if user["is_blocked"]:
                return JSONResponse(status_code=403, content={"message": "Your account has been blocked. Contact support."})

    safe_input = user_input

    # ── ① Unicode Firewall ─────────────────────────────────────────────────
    if state.FEATURES["INPUT_UNICODE_FIREWALL"]:
        blocked, reason, metrics = unicode_firewall.scan(safe_input, mode='prompt')
        if blocked:
            if user_id:
                auth.log_security_event(user_id, username, user_input, "UNICODE_FIREWALL", "blocked", "HIGH", {"reason": reason, **metrics})
                resp = _handle_violation(user_id, username, user_input, "UNICODE_FIREWALL", settings)
                if resp:
                    return resp
            return JSONResponse(status_code=400, content={"message": f"⚠️ Unicode attack detected: {reason}"})
        # Clean the input even if not blocked
        safe_input = unicode_firewall.clean(safe_input, mode='prompt')

    # ── ② Input spaCy Engine ───────────────────────────────────────────────
    if state.FEATURES["INPUT_SPACY_FIREWALL"]:
        spacy_result = input_spacy.analyze(safe_input)
        if spacy_result["is_malicious"]:
            if user_id:
                auth.log_security_event(user_id, username, user_input, "INPUT_SPACY", "blocked", "HIGH", spacy_result)
                resp = _handle_violation(user_id, username, user_input, "INPUT_SPACY", settings)
                if resp:
                    return resp
            return JSONResponse(status_code=400, content={"message": "⚠️ Your message was flagged by the Input Rule Engine."})

    # ── ③ BERT Classifier with rephrase loop ──────────────────────────────
    if state.FEATURES["BERT_FIREWALL"]:
        safe_threshold = state.BERT_SETTINGS["SAFE_THRESHOLD"]
        medium_threshold = state.BERT_SETTINGS["MEDIUM_THRESHOLD"]
        max_rephrase = state.BERT_SETTINGS["MAX_REPHRASE"]
        iteration = 0

        while iteration < max_rephrase:
            prob = bert_classifier.predict(safe_input)

            if prob < safe_threshold:
                break

            if prob >= medium_threshold:
                if user_id:
                    auth.log_security_event(user_id, username, user_input, "BERT_CLASSIFIER", "blocked", "HIGH", {"probability": prob})
                    resp = _handle_violation(user_id, username, user_input, "BERT_CLASSIFIER", settings)
                    if resp:
                        return resp
                return JSONResponse(status_code=400, content={"message": f"⚠️ Message flagged as malicious by BERT Classifier (p={prob:.2f})."})

            # Medium confidence — rephrase and retry
            iteration += 1
            safe_input = input_rewriter.rewrite(safe_input)
            print(f"[BERT] Rephrase {iteration}/{max_rephrase} — p={prob:.2f}")

        else:
            # Exceeded max rephrases
            if user_id:
                auth.log_security_event(user_id, username, user_input, "BERT_MAX_REPHRASE", "blocked", "HIGH", {"attempts": max_rephrase})
                resp = _handle_violation(user_id, username, user_input, "BERT_MAX_REPHRASE", settings)
                if resp:
                    return resp
            return JSONResponse(status_code=400, content={"message": f"⚠️ Message still suspicious after {max_rephrase} rephrase attempts."})

    # ── ④ Input PII (redact, not a security violation) ─────────────────────
    if state.FEATURES["INPUT_PII_FIREWALL"]:
        entities, _ = pii_detector.detect_and_mask(safe_input)
        if entities:
            auth.log_security_event(
                user_id or 0, username, user_input, "PII_INPUT", "redacted", "INFO",
                {"entities": [e["label"] for e in entities]},
            )
            # Use OutputRewriter (Llama3.2) to rewrite the prompt,
            # replacing PII values with [PLACEHOLDER] tags — same logic as output PII
            safe_input = output_rewriter.redact(safe_input)
            print(f"[PII-INPUT] Redacted {len(entities)} entities via OutputRewriter")

    # ── ⑤ Input Context Relevance ─────────────────────────────────────────
    if state.FEATURES["INPUT_CONTEXT_RELEVANCE"]:
        threshold = state.CONTEXT_SETTINGS["SIMILARITY_THRESHOLD"]
        relevance = context_vectorstore.check_relevance(safe_input, threshold)
        print(f"[INPUT-CONTEXT] similarity={relevance['similarity']:.2f}%")
        if not relevance["relevant"]:
            auth.log_security_event(
                user_id or 0, username, user_input, "INPUT_CONTEXT", "out_of_domain", "INFO",
                {"similarity": relevance["similarity"]},
            )
            return JSONResponse(status_code=400, content={
                "message": (
                    f"⚠️ Your question is outside the supported domain "
                    f"(Similarity: {relevance['similarity']:.1f}% — Threshold: {threshold}%)."
                )
            })

    # ── Send to LLM ────────────────────────────────────────────────────────
    response_text = "".join(chat_stream(safe_input))
    safe_output = response_text
    # Preserve the raw unmodified LLM response for SOC alerts.
    # All output detections send this to the analyst so they can see
    # exactly what the LLM said — including any sensitive content —
    # and understand why the event was triggered.
    raw_llm_response = response_text

    # ── ⑥ Output spaCy Engine ──────────────────────────────────────────────
    if state.FEATURES["OUTPUT_SPACY_FIREWALL"]:
        out_spacy = output_spacy.analyze(safe_output)
        if out_spacy["is_malicious"]:
            safe_output = out_spacy["modified_text"]
            if user_id:
                auth.log_security_event(
                    user_id, username, raw_llm_response, "OUTPUT_SPACY", "redacted", "HIGH",
                    {
                        "threats": out_spacy["threat_count"],
                        "details": out_spacy["details"],
                        "note": "Raw LLM response logged — spaCy detected threats in output",
                    }
                )
                soc_alerter.alert("HIGH", user_id, username, raw_llm_response, "OUTPUT_SPACY", "redacted", settings)
                resp = _handle_violation(user_id, username, user_input, "OUTPUT_SPACY", settings)
                if resp:
                    return resp
            if out_spacy["details"] and any(d["action"] == "REDACT" for d in out_spacy["details"]):
                print(f"[OUTPUT-SPACY] Redacted {out_spacy['threat_count']} threats")
            else:
                return JSONResponse(status_code=400, content={"message": "⚠️ The model response was blocked by Output Rule Engine."})

    # ── ⑦ Output PII Detection ─────────────────────────────────────────────
    if state.FEATURES["OUTPUT_PII_FIREWALL"]:
        entities, _ = pii_detector.detect_and_mask(safe_output)
        if entities:
            if user_id:
                auth.log_security_event(
                    user_id, username, raw_llm_response, "PII_OUTPUT", "leaked", "HIGH",
                    {
                        "entities": [e["label"] for e in entities],
                        "note": "Raw LLM response logged — contains PII leaked by the model",
                    }
                )
                soc_alerter.alert("HIGH", user_id, username, raw_llm_response, "PII_OUTPUT", "leaked", settings)
            safe_output = output_rewriter.redact(safe_output)
            print(f"[PII-OUTPUT] Redacted {len(entities)} entities")

    # ── ⑧ Output Context Relevance ─────────────────────────────────────────
    if state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"]:
        threshold = state.CONTEXT_SETTINGS["SIMILARITY_THRESHOLD"]
        relevance = context_vectorstore.check_relevance(safe_output, threshold)
        print(f"[OUTPUT-CONTEXT] similarity={relevance['similarity']:.2f}%")
        if not relevance["relevant"]:
            if user_id:
                auth.log_security_event(
                    user_id, username, raw_llm_response, "OUTPUT_CONTEXT", "out_of_domain", "HIGH",
                    {
                        "similarity": relevance["similarity"],
                        "threshold": threshold,
                        "note": "Raw LLM response logged — model responded outside allowed domain",
                    }
                )
                soc_alerter.alert("HIGH", user_id, username, raw_llm_response, "OUTPUT_CONTEXT", "out_of_domain", settings)
            return JSONResponse(status_code=400, content={
                "message": (
                    f"⚠️ The model response is outside the allowed domain "
                    f"(Similarity: {relevance['similarity']:.1f}% — Threshold: {threshold}%)."
                )
            })

    return PlainTextResponse(content=safe_output)


# ─────────────────────────────────────────────────────────────────────────────
# RESET
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/reset")
async def reset():
    reset_memory()
    return JSONResponse(content={"status": "ok"})


# ─────────────────────────────────────────────────────────────────────────────
# CATCH-ALL — serve React SPA
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/{full_path:path}")
async def serve_react_app(full_path: str):
    if full_path.startswith("api"):
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    file_path = os.path.join(REACT_DIST_PATH, full_path)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    index_path = os.path.join(REACT_DIST_PATH, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return JSONResponse(status_code=404, content={"detail": "React app not built yet."})


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=5000, reload=True)
