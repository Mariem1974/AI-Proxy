from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime
import redis
import json
import emoji
import unicodedata
import uuid
from dotenv import load_dotenv
import os
import sqlite3
import apprise
import smtplib
from email.message import EmailMessage

load_dotenv()

app = FastAPI(title="AI Security Proxy")

# Redis
r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))

# Apprise
alert_service = apprise.Apprise()
EMAIL_URL = os.getenv("EMAIL_URL", "").strip()
SLACK_URL = os.getenv("SLACK_URL", "").strip()
TGRAM_URL = os.getenv("TGRAM_URL", "").strip()

if EMAIL_URL:
    alert_service.add(EMAIL_URL)
if SLACK_URL:
    alert_service.add(SLACK_URL)
if TGRAM_URL:
    alert_service.add(TGRAM_URL)

SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()
SMTP_TO = os.getenv("SMTP_TO", "").strip()

# Thresholds
WARNING_WINDOW_SECONDS = 10 * 60
MAX_WARNINGS_PER_WINDOW = 5
BLOCK_DURATION_SECONDS = 30 * 60
MAX_TEMP_BLOCKS = 3
HIGH_RISK_THRESHOLD = 0.7

def get_user_id(request: Request) -> str:
    return request.headers.get("User-ID", str(uuid.uuid4()))

def is_permanently_blocked(user_id: str) -> bool:
    return r.exists(f"perm_block:{user_id}")

def increment_warning(user_id: str):
    key = f"warnings:{user_id}"
    r.incr(key)
    r.expire(key, WARNING_WINDOW_SECONDS)

def get_warning_count(user_id: str) -> int:
    count = r.get(f"warnings:{user_id}")
    return int(count) if count else 0

def increment_temp_block(user_id: str):
    key = f"temp_blocks:{user_id}"
    r.incr(key)
    r.expire(key, 7 * 24 * 60 * 60)

def get_temp_block_count(user_id: str) -> int:
    count = r.get(f"temp_blocks:{user_id}")
    return int(count) if count else 0

def apply_block(user_id: str, duration_seconds: int):
    r.set(f"block:{user_id}", "1", ex=duration_seconds)

def is_blocked(user_id: str) -> bool:
    if is_permanently_blocked(user_id):
        return True
    return r.exists(f"block:{user_id}")

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    user_id = get_user_id(request)
    if is_blocked(user_id):
        temp_blocks = get_temp_block_count(user_id)
        if temp_blocks >= MAX_TEMP_BLOCKS:
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Your access has been **permanently blocked** due to repeated high-risk attempts.",
                    "reason": "Exceeded maximum temporary blocks (3).",
                    "action": "Contact SOC support for review or unblock."
                }
            )
        else:
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Temporary access block active",
                    "reason": "You exceeded the allowed number of security warnings (5 in 10 minutes).",
                    "duration": "30 minutes",
                    "remaining_attempts": "Wait until the block expires or contact support."
                }
            )
    response = await call_next(request)
    return response

class PromptRequest(BaseModel):
    prompt: str

@app.get("/")
async def root():
    return {"message": "AI Security Proxy is running! Use /secure or /docs"}

@app.post("/secure")
async def secure_endpoint(request: Request, body: PromptRequest):
    user_id = get_user_id(request)
    original = body.prompt
    processed = unicodedata.normalize('NFKC', original)
    processed = emoji.demojize(processed)

    detections = {
        "injection_score": 0.92 if any(word in processed.lower() for word in ["ignore", "bomb", "knife", "delete", "hack", "rules", "kill"]) else 0.1,
        "pii_count": 2 if any(word in original.lower() for word in ["password", "email", "credit card", "phone"]) else 0,
        "emoji_threat": any(x in processed for x in [":bomb:", ":knife:", ":gun:", ":middle_finger:"]),
        "secrets_found": ["sk-xxx"] if any(keyword in original.lower() for keyword in ["sk-", "api_key", "secret"]) else []
    }

    is_high_risk = (
        detections["injection_score"] > HIGH_RISK_THRESHOLD or 
        detections["pii_count"] > 1 or 
        detections["emoji_threat"] or 
        len(detections["secrets_found"]) > 0
    )

    severity = "high" if is_high_risk else "low"
    action = "allowed"

    log_data = {
        "user_id": user_id,
        "original_prompt": original,
        "processed_prompt": processed,
        "detections": detections,
        "severity": severity,
        "action": action
    }
    log_event(log_data)

    if is_high_risk:
        increment_warning(user_id)
        warning_count = get_warning_count(user_id)

        print(f"[DEBUG] Warning count for {user_id}: {warning_count} (user_id used: {user_id})")

        if warning_count >= MAX_WARNINGS_PER_WINDOW:
            apply_block(user_id, BLOCK_DURATION_SECONDS)
            increment_temp_block(user_id)

            temp_blocks = get_temp_block_count(user_id)

            print(f"[DEBUG] Temp blocks for {user_id}: {temp_blocks}")

            if temp_blocks >= MAX_TEMP_BLOCKS:
                r.set(f"perm_block:{user_id}", "1")
                send_soc_alert("CRITICAL", log_data)
                log_data["action"] = "permanent_block"
                log_event(log_data)
                return JSONResponse(status_code=403, content={"detail": "Permanent block applied - SOC notified"})

            log_data["action"] = "temporary_block"
            log_event(log_data)
            send_soc_alert("HIGH", log_data)
            return JSONResponse(status_code=403, content={"detail": f"Temporary block for {BLOCK_DURATION_SECONDS // 60} minutes - Warning {warning_count}/{MAX_WARNINGS_PER_WINDOW}"})

        print(f"[DEBUG] High risk detected but warning count {warning_count} < {MAX_WARNINGS_PER_WINDOW} - allowed for now")

    return {"status": "safe", "processed": processed}

def log_event(data: dict):
    conn = sqlite3.connect("security_logs.db")
    conn.execute("""
        INSERT INTO logs 
        (timestamp, user_id, original_prompt, processed_prompt, detections, severity, action)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.utcnow().isoformat(),
        data["user_id"],
        data["original_prompt"],
        data["processed_prompt"],
        json.dumps(data["detections"]),
        data["severity"],
        data["action"]
    ))
    conn.commit()
    conn.close()
    print("[LOG]", json.dumps(data, ensure_ascii=False, indent=2))

def send_soc_alert(severity: str, details: dict):
    title = f"[PROXY] {severity.upper()} THREAT"
    body = json.dumps(details, indent=2, ensure_ascii=False)

    sent_any = False

    if alert_service.servers:
        try:
            alert_service.notify(body=body, title=title)
            print(f"[ALERT SENT] {title} via Apprise")
            sent_any = True
        except Exception as e:
            print("[ALERT] Apprise send failed:", str(e))

    if SMTP_USER and SMTP_PASS and SMTP_TO:
        try:
            msg = EmailMessage()
            msg["From"] = SMTP_USER
            msg["To"] = SMTP_TO
            msg["Subject"] = title
            msg.set_content(body)

            with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
                smtp.starttls()
                smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)

            print(f"[ALERT SENT] {title} via Gmail SMTP")
            sent_any = True
        except Exception as e:
            print("[ALERT] Gmail SMTP send failed:", str(e))

    if not sent_any:
        print("[ALERT] No channels configured or all sends failed")
