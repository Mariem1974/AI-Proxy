"""routers/chat_routes.py — Chat, document upload, and feature-state endpoints."""
import asyncio
import os
import re
import tempfile
from typing import Optional

# Detects follow-up messages that implicitly reference the previous topic.
# These need context enrichment for the relevance check.
# "tell me a joke" has none of these → checked standalone → correctly blocked.
# "give me an example" matches "give me" + "example" → enriched → correctly allowed.
_FOLLOWUP_RE = re.compile(
    r'\b(it|this|that|these|those|them|'
    r'give\s+me|show\s+me|tell\s+me\s+more|'
    r'more|expand|elaborate|explain|example|'
    r'go\s+on|continue|further|also|another|next|'
    r'what\s+about|how\s+so|why\s+so|can\s+you)\b',
    re.IGNORECASE,
)

from fastapi import APIRouter, UploadFile, File, Form
from fastapi.responses import JSONResponse, PlainTextResponse

import auth
import state
from core.llm import chat_stream, reset_memory, get_recent_context
from core.pipeline import (
    unicode_firewall, input_spacy, bert_classifier, pii_detector,
    output_spacy, input_rewriter, output_rewriter,
    context_vectorstore, doc_pipeline,
)
from core.dependencies import handle_violation
from schemas import ChatMessage

router = APIRouter(tags=["chat"])


@router.get("/api/features")
async def get_features():
    return JSONResponse(content={**state.FEATURES, "bert_settings": state.BERT_SETTINGS})


@router.get("/api/vectorstore-status")
async def get_vectorstore_status():
    return JSONResponse(content=context_vectorstore.get_status())


@router.post("/api/reset")
async def reset(user_id: Optional[int] = None):
    await reset_memory(user_id)
    return JSONResponse(content={"status": "ok"})


@router.post("/api/upload-document")
async def upload_document(file: UploadFile = File(...), user_id: int = Form(None)):
    if not state.FEATURES["DOCUMENT_PROCESSING"]:
        return JSONResponse(status_code=400, content={"error": "Document processing is disabled."})

    temp_path = os.path.join(tempfile.gettempdir(), f"doc_{file.filename}")
    try:
        with open(temp_path, "wb") as f:
            f.write(await file.read())

        result = doc_pipeline.run(temp_path, active_features=state.FEATURES)

        username = "anonymous"
        if user_id:
            user = await auth.get_user_by_id(user_id)
            if user:
                username = user["username"]

        if result.final_decision == "BLOCK":
            if user_id:
                asyncio.create_task(auth.log_security_event(
                    user_id, username, f"[FILE:{file.filename}]",
                    "DOCUMENT_BLOCKED", "blocked", "HIGH",
                    {"reason": result.block_reason, "stats": result.stats},
                ))
                settings = await auth.get_alert_settings()
                block_resp = await handle_violation(
                    user_id, username, f"[FILE:{file.filename}]", "DOCUMENT_BLOCKED", settings
                )
                if block_resp:
                    return block_resp
            return JSONResponse(status_code=400, content={
                "message": f"Document blocked: {result.block_reason}",
                "stats": result.stats,
            })

        return JSONResponse(content={"success": True, "safe_context": result.safe_context, "stats": result.stats})

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@router.post("/api/chat")
async def chat(body: ChatMessage):
    user_input = body.message
    user_id = body.user_id
    username = "anonymous"
    settings = await auth.get_alert_settings()

    if user_id:
        await auth.check_and_release_expired_blocks(user_id)
        user = await auth.get_user_by_id(user_id)
        if user:
            username = user["username"]
            if user["is_blocked"]:
                return JSONResponse(
                    status_code=403,
                    content={"message": "Your account has been blocked. Contact support."},
                )

    safe_input = user_input

    # ── ① Unicode Firewall ─────────────────────────────────────────────────
    if state.FEATURES["INPUT_UNICODE_FIREWALL"]:
        blocked, reason, metrics = unicode_firewall.scan(safe_input, mode='prompt')
        if blocked:
            if user_id:
                asyncio.create_task(auth.log_security_event(
                    user_id, username, user_input, "UNICODE_FIREWALL", "blocked", "HIGH",
                    {"reason": reason, **metrics}
                ))
                resp = await handle_violation(user_id, username, user_input, "UNICODE_FIREWALL", settings)
                if resp:
                    return resp
            return JSONResponse(status_code=400, content={"message": f"Unicode attack detected: {reason}"})
        safe_input = unicode_firewall.clean(safe_input, mode='prompt')

    # ── ② Input spaCy Engine ───────────────────────────────────────────────
    if state.FEATURES["INPUT_SPACY_FIREWALL"]:
        spacy_result = input_spacy.analyze(safe_input)
        if spacy_result["is_malicious"]:
            if user_id:
                asyncio.create_task(auth.log_security_event(
                    user_id, username, user_input, "INPUT_SPACY", "blocked", "HIGH", spacy_result
                ))
                resp = await handle_violation(user_id, username, user_input, "INPUT_SPACY", settings)
                if resp:
                    return resp
            return JSONResponse(status_code=400, content={"message": "Your message was flagged by the Input Rule Engine."})

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
                    asyncio.create_task(auth.log_security_event(
                        user_id, username, user_input, "BERT_CLASSIFIER", "blocked", "HIGH",
                        {"probability": prob}
                    ))
                    resp = await handle_violation(user_id, username, user_input, "BERT_CLASSIFIER", settings)
                    if resp:
                        return resp
                return JSONResponse(status_code=400, content={"message": f"Message flagged as malicious by BERT Classifier (p={prob:.2f})."})
            iteration += 1
            safe_input = input_rewriter.rewrite(safe_input)
            print(f"[BERT] Rephrase {iteration}/{max_rephrase} — p={prob:.2f}")
        else:
            if user_id:
                asyncio.create_task(auth.log_security_event(
                    user_id, username, user_input, "BERT_MAX_REPHRASE", "blocked", "HIGH",
                    {"attempts": max_rephrase}
                ))
                resp = await handle_violation(user_id, username, user_input, "BERT_MAX_REPHRASE", settings)
                if resp:
                    return resp
            return JSONResponse(status_code=400, content={"message": f"Message still suspicious after {max_rephrase} rephrase attempts."})

    # ── ④ Input PII ────────────────────────────────────────────────────────
    if state.FEATURES["INPUT_PII_FIREWALL"]:
        entities, _ = pii_detector.detect_and_mask(safe_input)
        if entities:
            labels = [e["label"] for e in entities]
            asyncio.create_task(auth.log_security_event(
                user_id or 0, username, user_input, "PII_INPUT", "blocked", "HIGH",
                {"entities": labels},
            ))
            resp = await handle_violation(user_id, username, user_input, "PII_INPUT", settings)
            if resp:
                return resp
            return JSONResponse(
                status_code=400,
                content={
                    "message": (
                        f"Your message contains sensitive personal information "
                        f"({', '.join(set(labels))}) and cannot be processed. "
                        f"Please remove it and try again."
                    )
                },
            )

    # ── ⑤ Input Context Relevance ─────────────────────────────────────────
    if state.FEATURES["INPUT_CONTEXT_RELEVANCE"]:
        threshold = state.CONTEXT_SETTINGS["SIMILARITY_THRESHOLD"]
        is_followup = (
            len(safe_input.split()) <= 10
            and bool(_FOLLOWUP_RE.search(safe_input))
        )
        if is_followup:
            recent_ctx = await get_recent_context(user_id or 0, n=1)
            check_text = f"{recent_ctx} {safe_input}".strip() if recent_ctx else safe_input
        else:
            check_text = safe_input
        relevance = context_vectorstore.check_relevance(check_text, threshold)
        print(f"[INPUT-CONTEXT] similarity={relevance['similarity']:.2f}% followup={is_followup}")
        if not relevance["relevant"]:
            asyncio.create_task(auth.log_security_event(
                user_id or 0, username, user_input, "INPUT_CONTEXT", "out_of_domain", "INFO",
                {"similarity": relevance["similarity"]},
            ))
            return JSONResponse(status_code=400, content={
                "message": (
                    f"Your question is outside the supported finance domain "
                    f"(similarity {relevance['similarity']:.1f}% — threshold {threshold}%). "
                    f"Please ask a finance-related question."
                )
            })

    # ── Send to LLM ────────────────────────────────────────────────────────
    response_text = await chat_stream(safe_input, user_id=user_id or 0)
    safe_output = response_text
    raw_llm_response = response_text

    # ── ⑥ Output spaCy Engine ──────────────────────────────────────────────
    if state.FEATURES["OUTPUT_SPACY_FIREWALL"]:
        out_spacy = output_spacy.analyze(safe_output)
        if out_spacy["is_malicious"]:
            safe_output = out_spacy["modified_text"]
            if user_id:
                asyncio.create_task(auth.log_security_event(
                    user_id, username, raw_llm_response, "OUTPUT_SPACY", "redacted", "HIGH",
                    {"threats": out_spacy["threat_count"], "details": out_spacy["details"],
                     "note": "Raw LLM response logged — spaCy detected threats in output"},
                ))
                from core.pipeline import soc_alerter
                soc_alerter.alert("HIGH", user_id, username, raw_llm_response, "OUTPUT_SPACY", "redacted", settings)
                resp = await handle_violation(user_id, username, user_input, "OUTPUT_SPACY", settings)
                if resp:
                    return resp
            if out_spacy["details"] and any(d["action"] == "REDACT" for d in out_spacy["details"]):
                print(f"[OUTPUT-SPACY] Redacted {out_spacy['threat_count']} threats")
            else:
                return JSONResponse(status_code=400, content={"message": "The model response was blocked by Output Rule Engine."})

    # ── ⑦ Output PII Detection ─────────────────────────────────────────────
    if state.FEATURES["OUTPUT_PII_FIREWALL"]:
        entities, _ = pii_detector.detect_and_mask(safe_output)
        if entities:
            if user_id:
                asyncio.create_task(auth.log_security_event(
                    user_id, username, raw_llm_response, "PII_OUTPUT", "leaked", "HIGH",
                    {"entities": [e["label"] for e in entities],
                     "note": "Raw LLM response logged — contains PII leaked by the model"},
                ))
                from core.pipeline import soc_alerter
                soc_alerter.alert("HIGH", user_id, username, raw_llm_response, "PII_OUTPUT", "leaked", settings)
            safe_output = output_rewriter.redact(safe_output)
            print(f"[PII-OUTPUT] Redacted {len(entities)} entities")

    # ── ⑧ Output Context Relevance ─────────────────────────────────────────
    if state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"]:
        threshold = state.CONTEXT_SETTINGS["SIMILARITY_THRESHOLD"]
        relevance = context_vectorstore.check_relevance(safe_output, threshold)
        print(f"[OUTPUT-CONTEXT] similarity={relevance['similarity']:.2f}%")
        if not relevance["relevant"]:
            asyncio.create_task(auth.log_security_event(
                user_id or 0, username, raw_llm_response, "OUTPUT_CONTEXT", "out_of_domain", "INFO",
                {"similarity": relevance["similarity"], "threshold": threshold},
            ))
            return JSONResponse(status_code=400, content={
                "message": (
                    f"The model response is outside the allowed finance domain "
                    f"(similarity {relevance['similarity']:.1f}% — threshold {threshold}%). "
                    f"Please ask a finance-related question."
                )
            })

    return PlainTextResponse(content=safe_output)
