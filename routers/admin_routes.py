"""routers/admin_routes.py — Admin-only endpoints: toggles, users, logs, alerts, analytics."""
import asyncio
import os
import tempfile

from fastapi import APIRouter, Depends, UploadFile, File
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

import auth
import state
from core.pipeline import bert_classifier, context_vectorstore
from core.dependencies import require_admin
from db import get_db
from schemas import AlertSettingsRequest, BertModelRequest, ThresholdRequest

router = APIRouter(tags=["admin"])


# ── Feature toggles — input ───────────────────────────────────────────────────

@router.post("/api/toggle/input-unicode")
async def toggle_unicode(_: dict = Depends(require_admin)):
    state.FEATURES["INPUT_UNICODE_FIREWALL"] = not state.FEATURES["INPUT_UNICODE_FIREWALL"]
    return JSONResponse(content={"input_unicode": state.FEATURES["INPUT_UNICODE_FIREWALL"]})


@router.post("/api/toggle/input-spacy")
async def toggle_input_spacy(_: dict = Depends(require_admin)):
    state.FEATURES["INPUT_SPACY_FIREWALL"] = not state.FEATURES["INPUT_SPACY_FIREWALL"]
    return JSONResponse(content={"input_spacy": state.FEATURES["INPUT_SPACY_FIREWALL"]})


@router.post("/api/toggle/bert")
async def toggle_bert(_: dict = Depends(require_admin)):
    state.FEATURES["BERT_FIREWALL"] = not state.FEATURES["BERT_FIREWALL"]
    return JSONResponse(content={"bert": state.FEATURES["BERT_FIREWALL"]})


@router.post("/api/toggle/input-pii")
async def toggle_input_pii(_: dict = Depends(require_admin)):
    state.FEATURES["INPUT_PII_FIREWALL"] = not state.FEATURES["INPUT_PII_FIREWALL"]
    return JSONResponse(content={"input_pii": state.FEATURES["INPUT_PII_FIREWALL"]})


@router.post("/api/toggle/input-context")
async def toggle_input_context(_: dict = Depends(require_admin)):
    if not state.FEATURES["INPUT_CONTEXT_RELEVANCE"] and not context_vectorstore.is_ready():
        return JSONResponse(status_code=400, content={"error": "Upload a domain PDF before enabling context filter."})
    state.FEATURES["INPUT_CONTEXT_RELEVANCE"] = not state.FEATURES["INPUT_CONTEXT_RELEVANCE"]
    return JSONResponse(content={
        "input_context": state.FEATURES["INPUT_CONTEXT_RELEVANCE"],
        "vectorstore_status": context_vectorstore.get_status(),
    })


# ── Feature toggles — output ──────────────────────────────────────────────────

@router.post("/api/toggle/output-spacy")
async def toggle_output_spacy(_: dict = Depends(require_admin)):
    state.FEATURES["OUTPUT_SPACY_FIREWALL"] = not state.FEATURES["OUTPUT_SPACY_FIREWALL"]
    return JSONResponse(content={"output_spacy": state.FEATURES["OUTPUT_SPACY_FIREWALL"]})


@router.post("/api/toggle/output-pii")
async def toggle_output_pii(_: dict = Depends(require_admin)):
    state.FEATURES["OUTPUT_PII_FIREWALL"] = not state.FEATURES["OUTPUT_PII_FIREWALL"]
    return JSONResponse(content={"output_pii": state.FEATURES["OUTPUT_PII_FIREWALL"]})


@router.post("/api/toggle/output-context")
async def toggle_output_context(_: dict = Depends(require_admin)):
    if not state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"] and not context_vectorstore.is_ready():
        return JSONResponse(status_code=400, content={"error": "Upload a domain PDF before enabling context filter."})
    state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"] = not state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"]
    return JSONResponse(content={"output_context": state.FEATURES["OUTPUT_CONTEXT_RELEVANCE"]})


@router.post("/api/toggle/document-processing")
async def toggle_document_processing(_: dict = Depends(require_admin)):
    state.FEATURES["DOCUMENT_PROCESSING"] = not state.FEATURES["DOCUMENT_PROCESSING"]
    return JSONResponse(content={"document_processing": state.FEATURES["DOCUMENT_PROCESSING"]})


# ── BERT model selection ──────────────────────────────────────────────────────

@router.post("/api/bert/model")
async def set_bert_model(body: BertModelRequest, _: dict = Depends(require_admin)):
    state.BERT_SETTINGS["ACTIVE_MODEL"] = body.model
    return JSONResponse(content={"active_model": body.model})


@router.get("/api/bert/model")
async def get_bert_model():
    return JSONResponse(content={
        "active_model": state.BERT_SETTINGS["ACTIVE_MODEL"],
        "loaded_model": bert_classifier.active_model_name,
    })


# ── Context / vector store ────────────────────────────────────────────────────

@router.post("/api/set-threshold")
async def set_threshold(body: ThresholdRequest, _: dict = Depends(require_admin)):
    state.CONTEXT_SETTINGS["SIMILARITY_THRESHOLD"] = body.threshold
    return JSONResponse(content={"threshold": body.threshold})


@router.post("/api/upload-context-pdf")
async def upload_context_pdf(file: UploadFile = File(...), _: dict = Depends(require_admin)):
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
            return JSONResponse(content={
                "success": True,
                "chunk_count": result["chunk_count"],
                "vectorstore_status": context_vectorstore.get_status(),
            })
        return JSONResponse(status_code=500, content={"error": result.get("error", "Failed to build vector store")})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ── User management ───────────────────────────────────────────────────────────

@router.get("/api/users")
async def get_users(_: dict = Depends(require_admin)):
    return JSONResponse(content={"users": await auth.get_all_users()})


@router.post("/api/users/unblock/{user_id}")
async def unblock_user_endpoint(user_id: int, _: dict = Depends(require_admin)):
    await auth.unblock_user(user_id)
    return JSONResponse(content={"message": "User unblocked"})


# ── Alert settings ────────────────────────────────────────────────────────────

@router.get("/api/alert-settings")
async def get_alert_settings(_: dict = Depends(require_admin)):
    return JSONResponse(content=await auth.get_alert_settings())


@router.post("/api/alert-settings")
async def update_alert_settings(body: AlertSettingsRequest, _: dict = Depends(require_admin)):
    result = await auth.update_alert_settings(**body.model_dump())
    return JSONResponse(content={"message": "Alert settings updated", "settings": result})


# ── Security logs ─────────────────────────────────────────────────────────────

@router.get("/api/security-logs")
async def get_security_logs(limit: int = 100, _: dict = Depends(require_admin)):
    return JSONResponse(content={"logs": await auth.get_security_logs(limit)})


@router.get("/api/security-logs/download")
async def download_security_logs_json(_: dict = Depends(require_admin)):
    """Stream security logs as JSON download."""
    import json
    logs = await auth.get_security_logs(limit=10000)
    content = json.dumps(logs, indent=2, default=str)
    from fastapi.responses import Response
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=security_logs.json"},
    )


# ── Analytics endpoints (TimescaleDB) ────────────────────────────────────────

@router.get("/api/analytics/alerts-over-time")
async def alerts_over_time(
    hours: int = 24,
    _: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """TimescaleDB time_bucket query — alert counts per hour for last N hours."""
    result = await db.execute(
        text(
            """
            SELECT
                time_bucket('1 hour', timestamp) AS bucket,
                COUNT(*) AS count,
                severity
            FROM security_logs
            WHERE timestamp > NOW() - ((:hours) * INTERVAL '1 hour')
            GROUP BY bucket, severity
            ORDER BY bucket ASC
            """
        ),
        {"hours": hours},
    )
    rows = result.fetchall()
    return {"data": [{"bucket": str(r.bucket), "count": r.count, "severity": r.severity} for r in rows]}


@router.get("/api/analytics/top-threats")
async def top_threats(
    _: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        text(
            """
            SELECT detection_type, COUNT(*) AS count
            FROM security_logs
            WHERE detection_type IS NOT NULL
            GROUP BY detection_type
            ORDER BY count DESC
            LIMIT 10
            """
        )
    )
    rows = result.fetchall()
    return {"data": [{"type": r.detection_type, "count": r.count} for r in rows]}


@router.get("/api/analytics/top-blocked-users")
async def top_blocked_users(
    _: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        text(
            """
            SELECT u.username, u.failed_attempts, u.temp_blocks, u.is_blocked,
                   COUNT(l.id) AS total_violations
            FROM users u
            LEFT JOIN security_logs l ON l.user_id = u.id AND l.severity = 'HIGH'
            GROUP BY u.id, u.username, u.failed_attempts, u.temp_blocks, u.is_blocked
            ORDER BY total_violations DESC
            LIMIT 10
            """
        )
    )
    rows = result.fetchall()
    return {"data": [dict(r._mapping) for r in rows]}


@router.get("/api/analytics/severity-breakdown")
async def severity_breakdown(
    _: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        text(
            """
            SELECT severity, COUNT(*) AS count
            FROM security_logs
            WHERE severity IS NOT NULL
            GROUP BY severity
            """
        )
    )
    rows = result.fetchall()
    return {"data": [{"severity": r.severity, "count": r.count} for r in rows]}
