"""
core/dependencies.py
====================
Shared FastAPI dependencies and violation-handling logic.
Uses JWT-based auth via auth_utils + async auth functions.
"""
import asyncio
from fastapi import Header, HTTPException, Depends
from fastapi.responses import JSONResponse

import auth
from auth_utils import decode_token
from db import get_db, AsyncSession


async def require_admin(authorization: str = Header(None)) -> dict:
    """FastAPI dependency — validates Bearer JWT and enforces admin role."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization[7:]

    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = await auth.verify_session(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def require_user(authorization: str = Header(None)) -> dict:
    """FastAPI dependency — validates Bearer JWT; any authenticated user."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization[7:]

    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = await auth.verify_session(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")
    return user


async def handle_violation(
    user_id: int,
    username: str,
    prompt: str,
    detection_type: str,
    settings: dict,
):
    """
    Increment the user's failed-attempt counter and issue a block when the
    threshold is reached.  Returns a JSONResponse if the caller should stop
    processing, or None if execution can continue.
    Now fully async.
    """
    from core.pipeline import soc_alerter  # late import avoids circular dependency

    result = await auth.increment_failed_attempts(user_id)
    if result["action"] == "block":
        block_result = await auth.block_user_temp(user_id)
        if block_result.get("permanent"):
            soc_alerter.alert(
                "CRITICAL", user_id, username, prompt,
                "PERMANENT_BLOCK", "permanent_block", settings,
            )
            return JSONResponse(
                status_code=403,
                content={"message": "You have been permanently blocked due to repeated violations."},
            )
        soc_alerter.alert(
            "HIGH", user_id, username, prompt,
            "TEMP_BLOCK", "temporary_block", settings,
        )
        tb = block_result.get("temp_blocks", "?")
        return JSONResponse(
            status_code=403,
            content={"message": f"Temporary block applied. You have {tb}/3 temporary blocks."},
        )

    soc_alerter.alert("HIGH", user_id, username, prompt, detection_type, "blocked", settings)
    return None
