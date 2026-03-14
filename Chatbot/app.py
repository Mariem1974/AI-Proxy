"""
AI-Proxy Chatbot — FastAPI Backend
===================================

Input Pipeline:
  1. spaCy Rule Engine
  2. BERT Classifier with rephrase loop
  3. PII detection on user input
  4. Context relevance check on user input

Output Pipeline:
  1. spaCy Rule Engine on LLM response
  2. PII detection on LLM response
  3. If PII exists -> OutputRewriter.redact()
  4. Context relevance check on LLM response

Admin Panel:
  Separate toggles for Input Phase and Output Phase
"""

from fastapi import FastAPI, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from LLM import chat_stream, reset_memory
from Classifier import predict_probability
from spacy_rule_engine import SpacyRuleEngine
import state
from Rephrase_Engine import InputRewriter, OutputRewriter
from PII import detect_pii
from Vector_DB import PDFVectorStore

import tempfile
import os
import json

# ──────────────────────────────────────
# App setup
# ──────────────────────────────────────
app = FastAPI(title="AI-Proxy Chatbot")

# Serve static files from the original static folder
# app.mount("/static", StaticFiles(directory="static"), name="static")

# Serve React static files from frontend/dist
REACT_DIST_PATH = os.path.join(os.path.dirname(__file__), "frontend", "dist")

# Jinja2 templates (for fallback HTML pages)
from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="templates")

# ──────────────────────────────────────
# Engines
# ──────────────────────────────────────
spacy_engine = SpacyRuleEngine()
input_rewriter = InputRewriter()
output_rewriter = OutputRewriter()

context_vectorstore = PDFVectorStore(
    pdf_path="",
    persist_directory=state.CONTEXT_SETTINGS["VECTOR_STORE_PATH"]
)

# ──────────────────────────────────────
# Constants
# ──────────────────────────────────────
MAX_REPHRASE_ITERATIONS = 3
BERT_SAFE_THRESHOLD = 0.4
BERT_HIGH_THRESHOLD = 0.7


# ──────────────────────────────────────
# Request model
# ──────────────────────────────────────
class ChatMessage(BaseModel):
    message: str


# ══════════════════════════════════════
# PAGES (API prefix not needed for HTML pages)
# ══════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Serve React app - FastAPI serves index.html from dist for SPA routing
    index_path = os.path.join(REACT_DIST_PATH, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    
    # Fallback to old template if React not built
    return templates.TemplateResponse(
        "chat.html",
        {
            "request": request,
            "input_spacy": state.FEATURES["INPUT_SPACY_FIREWALL"],
            "bert": state.FEATURES["BERT_FIREWALL"],
            "input_pii": state.FEATURES["INPUT_PII_FIREWALL"],
            "input_context": state.FEATURES["INPUT_CONTEXT_RELEVANCE"],
            "output_spacy": state.FEATURES["OUTPUT_SPACY_FIREWALL"],
            "output_pii": state.FEATURES["OUTPUT_PII_FIREWALL"],
            "output_context": state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"],
        },
    )


@app.get("/admin", response_class=HTMLResponse)
async def admin(request: Request):
    # Serve React app - FastAPI serves index.html from dist for SPA routing
    index_path = os.path.join(REACT_DIST_PATH, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    
    # Fallback to old template if React not built
    vectorstore_status = context_vectorstore.get_status() if context_vectorstore else {}

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "features": state.FEATURES,
            "context_settings": state.CONTEXT_SETTINGS,
            "vectorstore_status": vectorstore_status,
        },
    )


# ══════════════════════════════════════
# API ENDPOINTS (all prefixed with /api)
# ══════════════════════════════════════

# ══════════════════════════════════════
# INPUT TOGGLES
# ══════════════════════════════════════

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
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Cannot enable input similarity check before uploading the domain PDF."
                }
            )

    state.FEATURES["INPUT_CONTEXT_RELEVANCE"] = not state.FEATURES["INPUT_CONTEXT_RELEVANCE"]
    return JSONResponse(content={
        "input_context": state.FEATURES["INPUT_CONTEXT_RELEVANCE"],
        "vectorstore_status": context_vectorstore.get_status()
    })


# ══════════════════════════════════════
# OUTPUT TOGGLES
# ══════════════════════════════════════

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
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Cannot enable output similarity check before uploading the domain PDF."
                }
            )

    state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"] = not state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"]
    return JSONResponse(content={
        "output_context": state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"],
        "vectorstore_status": context_vectorstore.get_status()
    })


# ══════════════════════════════════════
# SHARED SETTINGS
# ══════════════════════════════════════

@app.post("/api/set-threshold")
async def set_threshold(threshold: float = Form(...)):
    if threshold < 0 or threshold > 100:
        return JSONResponse(
            status_code=400,
            content={"error": "Threshold must be between 0 and 100"}
        )

    state.CONTEXT_SETTINGS["SIMILARITY_THRESHOLD"] = threshold
    return JSONResponse(content={
        "threshold": state.CONTEXT_SETTINGS["SIMILARITY_THRESHOLD"]
    })


@app.post("/api/upload-context-pdf")
async def upload_context_pdf(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".pdf"):
        return JSONResponse(
            status_code=400,
            content={"error": "Only PDF files are allowed"}
        )

    temp_dir = tempfile.gettempdir()
    temp_pdf_path = os.path.join(temp_dir, f"context_{file.filename}")

    try:
        with open(temp_pdf_path, "wb") as f:
            content = await file.read()
            f.write(content)

        result = context_vectorstore.rebuild_from_pdf(temp_pdf_path)

        if result["success"]:
            state.CONTEXT_SETTINGS["pdf_uploaded"] = True
            state.CONTEXT_SETTINGS["chunk_count"] = result["chunk_count"]

            return JSONResponse(content={
                "success": True,
                "message": f"PDF uploaded successfully! Created {result['chunk_count']} chunks.",
                "chunk_count": result["chunk_count"],
                "vectorstore_status": context_vectorstore.get_status()
            })

        return JSONResponse(
            status_code=500,
            content={"error": result.get("error", "Failed to build vector store")}
        )

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Error processing PDF: {str(e)}"}
        )

    finally:
        if os.path.exists(temp_pdf_path):
            os.remove(temp_pdf_path)


@app.get("/api/vectorstore-status")
async def get_vectorstore_status():
    return JSONResponse(content=context_vectorstore.get_status())


# ══════════════════════════════════════
# CHAT ENDPOINT
# ══════════════════════════════════════

@app.post("/api/chat")
async def chat(body: ChatMessage):
    user_input = body.message
    safe_input = user_input

    # ─────────────────────────────────
    # PHASE 1 — INPUT FIREWALL
    # ─────────────────────────────────

    # ① Input spaCy Rule Engine
    if state.FEATURES["INPUT_SPACY_FIREWALL"]:
        spacy_result = spacy_engine.analyze_prompt(safe_input)
        if spacy_result["malicious"]:
            return JSONResponse(
                status_code=400,
                content={
                    "message": "⚠️ Your message was flagged as malicious by Input spaCy Firewall."
                },
            )

    # ② BERT Classifier with same style as your current logic
    if state.FEATURES["BERT_FIREWALL"]:
        iteration = 0

        while iteration < MAX_REPHRASE_ITERATIONS:
            prob = predict_probability(safe_input)

            if prob < BERT_SAFE_THRESHOLD:
                break

            elif prob >= BERT_HIGH_THRESHOLD:
                return JSONResponse(
                    status_code=400,
                    content={
                        "message": "⚠️ Your message was flagged as malicious by BERT Classifier."
                    },
                )

            else:
                iteration += 1
                safe_input = input_rewriter.rewrite(safe_input)
                print(
                    f"[BERT] Rephrase iteration {iteration}/{MAX_REPHRASE_ITERATIONS} "
                    f"— probability was {prob:.2f}\n{safe_input}"
                )

        else:
            return JSONResponse(
                status_code=400,
                content={
                    "message": (
                        f"⚠️ Your message remains suspicious after "
                        f"{MAX_REPHRASE_ITERATIONS} rephrase attempts."
                    )
                },
            )

    # ③ Input PII Detection
    if state.FEATURES["INPUT_PII_FIREWALL"]:
        input_entities = detect_pii(safe_input)
        if input_entities:
            safe_input = output_rewriter.redact(safe_input)
            print(f"[PII-INPUT] detected {len(input_entities)} entities -> rewritten")

    # ④ Input Similarity Check
    if state.FEATURES["INPUT_CONTEXT_RELEVANCE"]:
        threshold = state.CONTEXT_SETTINGS["SIMILARITY_THRESHOLD"]
        relevance_result = context_vectorstore.check_relevance(
            query=safe_input,
            threshold=threshold
        )

        print(
            f"[INPUT-CONTEXT] similarity={relevance_result['similarity']:.2f}% "
            f"threshold={threshold}%"
        )

        if not relevance_result["relevant"]:
            return JSONResponse(
                status_code=400,
                content={
                    "message": (
                        f"⚠️ Your question is outside the supported domain "
                        f"(Similarity: {relevance_result['similarity']:.1f}% - "
                        f"Threshold: {threshold}%)."
                    )
                },
            )

    # ─────────────────────────────────
    # SEND TO LLM
    # ─────────────────────────────────
    response_text = "".join(chat_stream(safe_input))
    safe_output = response_text

    # ─────────────────────────────────
    # PHASE 2 — OUTPUT FIREWALL
    # ─────────────────────────────────

    # ① Output spaCy Rule Engine
    if state.FEATURES["OUTPUT_SPACY_FIREWALL"]:
        output_spacy_result = spacy_engine.analyze_prompt(safe_output)
        if output_spacy_result["malicious"]:
            return JSONResponse(
                status_code=400,
                content={
                    "message": "⚠️ The model response was blocked by Output spaCy Firewall."
                },
            )

    # ② Output PII Detection
    if state.FEATURES["OUTPUT_PII_FIREWALL"]:
        output_entities = detect_pii(safe_output)
        if output_entities:
            print(f"[PII-OUTPUT] detected {len(output_entities)} entities -> rewriting output")
            safe_output = output_rewriter.redact(safe_output)

    # ③ Output Similarity Check
    if state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"]:
        threshold = state.CONTEXT_SETTINGS["SIMILARITY_THRESHOLD"]
        output_relevance_result = context_vectorstore.check_relevance(
            query=safe_output,
            threshold=threshold
        )

        print(
            f"[OUTPUT-CONTEXT] similarity={output_relevance_result['similarity']:.2f}% "
            f"threshold={threshold}%"
        )

        if not output_relevance_result["relevant"]:
            return JSONResponse(
                status_code=400,
                content={
                    "message": (
                        f"⚠️ The model response is outside the allowed domain "
                        f"(Similarity: {output_relevance_result['similarity']:.1f}% - "
                        f"Threshold: {threshold}%)."
                    )
                },
            )

    return PlainTextResponse(content=safe_output)


# ══════════════════════════════════════
# RESET
# ══════════════════════════════════════

@app.post("/api/reset")
async def reset():
    reset_memory()
    return JSONResponse(content={"status": "ok"})


# ══════════════════════════════════════
# RUN
# ══════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    # Note: reload=True causes models to reload when code changes
    # This is useful during development but consumes more resources
    uvicorn.run("app:app", host="127.0.0.1", port=5000, reload=True)


# ══════════════════════════════════════
# CATCH-ALL ROUTE (must be last)
# Serves React app for non-API routes
# ══════════════════════════════════════

@app.get("/{full_path:path}")
async def serve_react_app(full_path: str):
    """Serve React app for all routes that aren't API endpoints."""
    # If it's an API route that wasn't matched, return 404
    # (This shouldn't happen if all API routes are defined above)
    if full_path.startswith("api"):
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    
    # Check if the requested file exists in the React dist folder
    file_path = os.path.join(REACT_DIST_PATH, full_path)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    
    # Otherwise, serve the React index.html for SPA routing
    index_path = os.path.join(REACT_DIST_PATH, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    
    return JSONResponse(status_code=404, content={"detail": "React app not found. Please run 'npm run build' in the frontend folder."})