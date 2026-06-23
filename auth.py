"""
auth.py
=======
User management, authentication, security logging, and blocking logic.
Backed by PostgreSQL + TimescaleDB via SQLAlchemy async.
All public functions are async — callers must await them.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from sqlalchemy import text, select, update

import db as _db
from auth_utils import (
    hash_password, verify_password,
    create_access_token, decode_token,
)

SESSION_IDLE_TIMEOUT_MINUTES = int(
    os.getenv("SESSION_IDLE_TIMEOUT_MINUTES", "30")
)


# ── Database initialisation ───────────────────────────────────────────────────

async def init_database():
    """Delegates to db.init_db() — called by app.py lifespan."""
    await _db.init_db()


# ── User CRUD ─────────────────────────────────────────────────────────────────

async def register_user(
    username: str, password: str, email: str
) -> Dict[str, Any]:
    """Create a new user.  Returns user dict or raises ValueError."""
    async with _db.AsyncSessionLocal() as session:
        try:
            hashed = hash_password(password)
            session.add(
                _db.User(
                    username=username, password=hashed,
                    email=email, role="user",
                )
            )
            await session.commit()
            result = await session.execute(
                select(_db.User).where(_db.User.username == username)
            )
            user = result.scalar_one()
            return _user_to_dict(user)
        except Exception as exc:
            await session.rollback()
            raise ValueError("Username or email already exists") from exc


async def login_user(username: str, password: str) -> Dict[str, Any]:
    """
    Verify credentials.
    Returns {"token": jwt, "user": user_dict} on success.
    Raises ValueError on failure.
    """
    async with _db.AsyncSessionLocal() as session:
        result = await session.execute(
            select(_db.User).where(_db.User.username == username)
        )
        user = result.scalar_one_or_none()

    if not user:
        raise ValueError("Invalid credentials")

    if not verify_password(password, user.password):
        raise ValueError("Invalid credentials")

    if user.is_blocked:
        # Try to auto-release if the temp-block window has expired
        released = await check_and_release_expired_blocks(user.id)
        if not released:
            raise ValueError("User is blocked")
        # Re-fetch after release
        async with _db.AsyncSessionLocal() as session:
            r = await session.execute(
                select(_db.User).where(_db.User.id == user.id)
            )
            user = r.scalar_one()

    token = await create_session(user.id)
    return {"token": token, "user": _user_to_dict(user)}


async def get_current_user(token: str) -> Optional[Dict[str, Any]]:
    """Decode JWT and return user dict, or None."""
    return await verify_session(token)


async def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    async with _db.AsyncSessionLocal() as session:
        result = await session.execute(
            select(_db.User).where(_db.User.id == user_id)
        )
        user = result.scalar_one_or_none()
    return _user_to_dict(user) if user else None


async def get_all_users() -> list:
    async with _db.AsyncSessionLocal() as session:
        result = await session.execute(
            select(_db.User).order_by(_db.User.created_at.desc())
        )
        users = result.scalars().all()
    return [_user_to_dict(u) for u in users]


async def unblock_user(user_id: int):
    async with _db.AsyncSessionLocal() as session:
        await session.execute(
            update(_db.User)
            .where(_db.User.id == user_id)
            .values(
                is_blocked=False, blocked_at=None,
                failed_attempts=0, temp_blocks=0,
            )
        )
        await session.commit()


# ── Blocking logic ────────────────────────────────────────────────────────────

async def increment_failed_attempts(user_id: int) -> Dict[str, Any]:
    settings = await get_alert_settings()
    max_attempts = settings.get("max_attempts_to_block", 3)

    async with _db.AsyncSessionLocal() as session:
        result = await session.execute(
            select(_db.User.failed_attempts).where(_db.User.id == user_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return {"action": "none"}
        new_count = (row or 0) + 1
        await session.execute(
            update(_db.User)
            .where(_db.User.id == user_id)
            .values(failed_attempts=new_count)
        )
        await session.commit()

    if new_count >= max_attempts:
        return {"action": "block", "count": new_count}
    return {"action": "warn", "count": new_count}


async def block_user_temp(user_id: int) -> Dict[str, Any]:
    settings = await get_alert_settings()
    max_temp = settings.get("max_temp_blocks", 3)
    duration = settings.get("block_duration_minutes", 30)

    async with _db.AsyncSessionLocal() as session:
        result = await session.execute(
            select(_db.User.temp_blocks).where(_db.User.id == user_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return {"blocked": False}
        temp_count = (row or 0) + 1

        if temp_count > max_temp:
            await session.execute(
                update(_db.User)
                .where(_db.User.id == user_id)
                .values(
                    is_blocked=True, blocked_at=None,
                    failed_attempts=0, temp_blocks=temp_count,
                )
            )
            await session.commit()
            return {"blocked": True, "permanent": True, "temp_blocks": temp_count}

        unblock_time = datetime.now(timezone.utc) + timedelta(minutes=duration)
        await session.execute(
            update(_db.User)
            .where(_db.User.id == user_id)
            .values(
                is_blocked=True, blocked_at=unblock_time,
                failed_attempts=0, temp_blocks=temp_count,
            )
        )
        await session.commit()
        return {
            "blocked": True, "permanent": False,
            "temp_blocks": temp_count, "unblock_at": unblock_time.isoformat(),
        }


async def check_and_release_expired_blocks(user_id: int) -> bool:
    async with _db.AsyncSessionLocal() as session:
        result = await session.execute(
            select(_db.User.is_blocked, _db.User.blocked_at)
            .where(_db.User.id == user_id)
        )
        row = result.one_or_none()
        if not row or not row.is_blocked or not row.blocked_at:
            return False
        blocked_at = row.blocked_at
        if blocked_at.tzinfo is None:
            blocked_at = blocked_at.replace(tzinfo=timezone.utc)
        if blocked_at < datetime.now(timezone.utc):
            await session.execute(
                update(_db.User)
                .where(_db.User.id == user_id)
                .values(is_blocked=False, blocked_at=None, failed_attempts=0)
            )
            await session.commit()
            return True
    return False


# ── Session / token management ────────────────────────────────────────────────

async def create_session(user_id: int, hours: int = 24) -> str:
    """Create a DB session row and return a JWT token."""
    # Fetch user for token payload
    async with _db.AsyncSessionLocal() as session:
        result = await session.execute(
            select(_db.User).where(_db.User.id == user_id)
        )
        user = result.scalar_one_or_none()

    if not user:
        raise ValueError("User not found")

    token = create_access_token(user.id, user.username, user.role)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=hours)

    async with _db.AsyncSessionLocal() as session:
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        stmt = pg_insert(_db.Session).values(
            token=token,
            user_id=user_id,
            expires_at=expires_at,
            context=[],
        ).on_conflict_do_update(
            index_elements=["token"],
            set_={"expires_at": expires_at, "user_id": user_id},
        )
        await session.execute(stmt)
        await session.commit()

    return token


async def verify_session(token: str) -> Optional[Dict[str, Any]]:
    """Decode JWT, check the session row exists in DB, update last_active."""
    if not token:
        return None

    payload = decode_token(token)
    if not payload:
        return None

    user_id = int(payload["sub"])

    async with _db.AsyncSessionLocal() as session:
        result = await session.execute(
            select(_db.Session).where(_db.Session.token == token)
        )
        sess = result.scalar_one_or_none()
        if not sess:
            return None

        now = datetime.now(timezone.utc)
        expires = sess.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            return None

        # Update last_active for idle-timeout tracking
        await session.execute(
            update(_db.Session)
            .where(_db.Session.token == token)
            .values(last_active=now)
        )
        await session.commit()

    return await get_user_by_id(user_id)


async def purge_expired_sessions():
    """Delete sessions that have expired or have been idle too long."""
    now = datetime.now(timezone.utc)
    idle_cutoff = now - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES)

    async with _db.AsyncSessionLocal() as session:
        await session.execute(
            text(
                """
                DELETE FROM sessions
                WHERE expires_at < :now
                   OR last_active < :idle_cutoff
                """
            ),
            {"now": now, "idle_cutoff": idle_cutoff},
        )
        await session.commit()


# ── Session conversation context ──────────────────────────────────────────────

async def get_session_context(user_id: int) -> list:
    """Return the conversation context list from the user's active session."""
    async with _db.AsyncSessionLocal() as session:
        result = await session.execute(
            select(_db.Session.context)
            .where(_db.Session.user_id == user_id)
            .where(_db.Session.expires_at > datetime.now(timezone.utc))
            .order_by(_db.Session.last_active.desc())
            .limit(1)
        )
        row = result.scalar_one_or_none()
    if row is None:
        return []
    return row if isinstance(row, list) else []


async def save_session_context(user_id: int, context_list: list):
    """Persist conversation context to the user's most-recently-active session."""
    now = datetime.now(timezone.utc)
    async with _db.AsyncSessionLocal() as session:
        # Find the most-recent active session token
        result = await session.execute(
            select(_db.Session.token)
            .where(_db.Session.user_id == user_id)
            .where(_db.Session.expires_at > now)
            .order_by(_db.Session.last_active.desc())
            .limit(1)
        )
        token = result.scalar_one_or_none()
        if token:
            await session.execute(
                update(_db.Session)
                .where(_db.Session.token == token)
                .values(context=context_list, last_active=now)
            )
            await session.commit()


async def reset_session_context(user_id: int):
    """Clear conversation context for all active sessions of this user."""
    now = datetime.now(timezone.utc)
    async with _db.AsyncSessionLocal() as session:
        await session.execute(
            update(_db.Session)
            .where(_db.Session.user_id == user_id)
            .where(_db.Session.expires_at > now)
            .values(context=[])
        )
        await session.commit()


# ── Security logging ──────────────────────────────────────────────────────────

async def log_security_event(
    user_id: int,
    username: str,
    prompt: str,
    detection_type: str,
    action: str,
    severity: str,
    details: dict = None,
):
    """Write a security event to TimescaleDB security_logs."""
    async with _db.AsyncSessionLocal() as session:
        session.add(
            _db.SecurityLog(
                user_id=user_id,
                username=username,
                prompt=prompt,
                detection_type=detection_type,
                action=action,
                severity=severity,
                details=details,
            )
        )
        await session.commit()


async def get_security_logs(limit: int = 100) -> list:
    async with _db.AsyncSessionLocal() as session:
        result = await session.execute(
            select(_db.SecurityLog)
            .order_by(_db.SecurityLog.timestamp.desc())
            .limit(limit)
        )
        logs = result.scalars().all()
    return [_log_to_dict(log) for log in logs]


# ── Alert settings ────────────────────────────────────────────────────────────

async def get_alert_settings() -> dict:
    async with _db.AsyncSessionLocal() as session:
        result = await session.execute(
            select(_db.AlertSettings).where(_db.AlertSettings.id == 1)
        )
        row = result.scalar_one_or_none()
    if not row:
        return {}
    return {
        "max_attempts_to_block": row.max_attempts_to_block,
        "warning_window_minutes": row.warning_window_minutes,
        "block_duration_minutes": row.block_duration_minutes,
        "max_temp_blocks": row.max_temp_blocks,
        "enable_email": row.enable_email,
        "enable_telegram": row.enable_telegram,
        "email_address": row.email_address or "",
        "telegram_chat_id": row.telegram_chat_id or "",
    }


async def update_alert_settings(**kwargs) -> dict:
    """Accept keyword args matching AlertSettings column names."""
    async with _db.AsyncSessionLocal() as session:
        values = {
            k: v for k, v in kwargs.items()
            if k in {
                "max_attempts_to_block", "warning_window_minutes",
                "block_duration_minutes", "max_temp_blocks",
                "enable_email", "enable_telegram",
                "email_address", "telegram_chat_id",
            }
        }
        if values:
            await session.execute(
                update(_db.AlertSettings)
                .where(_db.AlertSettings.id == 1)
                .values(**values)
            )
            await session.commit()
    return await get_alert_settings()


# ── Private helpers ───────────────────────────────────────────────────────────

def _user_to_dict(u: _db.User) -> Dict[str, Any]:
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "is_blocked": u.is_blocked,
        "blocked_at": u.blocked_at.isoformat() if u.blocked_at else None,
        "failed_attempts": u.failed_attempts,
        "temp_blocks": u.temp_blocks,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


def _log_to_dict(log: _db.SecurityLog) -> Dict[str, Any]:
    return {
        "id": log.id,
        "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        "user_id": log.user_id,
        "username": log.username,
        "prompt": log.prompt,
        "detection_type": log.detection_type,
        "action": log.action,
        "severity": log.severity,
        "details": log.details,
    }


# ── Legacy compatibility shim (used by existing callers) ──────────────────────
# These are kept as aliases so any remaining direct `auth.create_user(...)` etc.
# calls don't hard-break during the migration.

async def create_user(username: str, password: str, email: str, role: str = "user") -> Dict[str, Any]:
    """Thin wrapper kept for backward compatibility with old callers."""
    try:
        user = await register_user(username, password, email)
        return {"success": True, "user": user}
    except ValueError as exc:
        return {"success": False, "error": str(exc)}


async def verify_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Thin wrapper kept for backward compatibility with old callers."""
    try:
        return await login_user(username, password)
    except ValueError as exc:
        msg = str(exc)
        if "blocked" in msg.lower():
            return {"success": False, "error": msg, "blocked": True}
        return None
