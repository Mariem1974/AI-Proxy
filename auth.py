"""
auth.py
=======
User management, authentication, security logging, and blocking logic.
Security logs are written to SQLite AND exported as JSON to ./security_logs.json.
"""

import sqlite3
import hashlib
import json
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

DATABASE_PATH = "users.db"
LOGS_JSON_PATH = "security_logs.json"


# ── Database initialisation ───────────────────────────────────────────────────

def init_database():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_blocked INTEGER DEFAULT 0,
            blocked_at TIMESTAMP,
            failed_attempts INTEGER DEFAULT 0,
            temp_blocks INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    for col, typedef in [
        ("blocked_at", "TIMESTAMP"),
        ("failed_attempts", "INTEGER DEFAULT 0"),
        ("temp_blocks", "INTEGER DEFAULT 0"),
    ]:
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col} {typedef}")
        except sqlite3.OperationalError:
            pass

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            username TEXT,
            prompt TEXT,
            detection_type TEXT,
            action TEXT,
            severity TEXT,
            details TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            max_attempts_to_block INTEGER DEFAULT 3,
            warning_window_minutes INTEGER DEFAULT 10,
            block_duration_minutes INTEGER DEFAULT 30,
            max_temp_blocks INTEGER DEFAULT 3,
            enable_email INTEGER DEFAULT 0,
            enable_telegram INTEGER DEFAULT 0,
            email_address TEXT,
            telegram_chat_id TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("SELECT COUNT(*) FROM alert_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO alert_settings (id, max_attempts_to_block, warning_window_minutes,
                                        block_duration_minutes, max_temp_blocks)
            VALUES (1, 3, 10, 30, 3)
        """)

    conn.commit()
    conn.close()


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ── User CRUD ─────────────────────────────────────────────────────────────────

def create_user(username: str, password: str, email: str, role: str = "user") -> Dict[str, Any]:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            (username, _hash_password(password), email, role),
        )
        conn.commit()
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username = ?", (username,)
        )
        u = cursor.fetchone()
        return {"success": True, "user": {"id": u[0], "username": u[1], "email": u[2], "role": u[3]}}
    except sqlite3.IntegrityError:
        return {"success": False, "error": "Username or email already exists"}
    finally:
        conn.close()


def verify_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, email, role, is_blocked, blocked_at, failed_attempts, temp_blocks "
        "FROM users WHERE username = ? AND password = ?",
        (username, _hash_password(password)),
    )
    user = cursor.fetchone()
    conn.close()
    if not user:
        return None

    is_blocked = bool(user[4])
    blocked_at = user[5]

    if is_blocked and blocked_at:
        was_released = check_and_release_expired_blocks(user[0])
        if was_released:
            user = get_user_by_id(user[0])
            if user:
                return {"success": True, "user": user}
            return None
        return {"success": False, "error": "User is blocked", "blocked": True}

    if is_blocked:
        return {"success": False, "error": "User is blocked", "blocked": True}

    return {
        "success": True,
        "user": {
            "id": user[0], "username": user[1], "email": user[2], "role": user[3],
            "failed_attempts": user[6], "temp_blocks": user[7],
        },
    }


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, email, role, is_blocked, blocked_at, failed_attempts, temp_blocks "
        "FROM users WHERE id = ?",
        (user_id,),
    )
    user = cursor.fetchone()
    conn.close()
    if not user:
        return None
    return {
        "id": user[0], "username": user[1], "email": user[2], "role": user[3],
        "is_blocked": bool(user[4]), "blocked_at": user[5],
        "failed_attempts": user[6], "temp_blocks": user[7],
    }


def get_all_users() -> list:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, email, role, is_blocked, failed_attempts, temp_blocks, created_at "
        "FROM users ORDER BY created_at DESC"
    )
    users = cursor.fetchall()
    conn.close()
    return [
        {
            "id": u[0], "username": u[1], "email": u[2], "role": u[3],
            "is_blocked": bool(u[4]), "failed_attempts": u[5],
            "temp_blocks": u[6], "created_at": u[7],
        }
        for u in users
    ]


def unblock_user(user_id: int):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET is_blocked=0, blocked_at=NULL, failed_attempts=0, temp_blocks=0 WHERE id=?",
        (user_id,),
    )
    conn.commit()
    conn.close()


# ── Blocking logic ────────────────────────────────────────────────────────────

def increment_failed_attempts(user_id: int) -> Dict[str, Any]:
    settings = get_alert_settings()
    max_attempts = settings.get("max_attempts_to_block", 3)
    window_minutes = settings.get("warning_window_minutes", 10)

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT failed_attempts FROM users WHERE id=?", (user_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return {"action": "none"}

    new_count = (row[0] or 0) + 1
    cursor.execute("UPDATE users SET failed_attempts=? WHERE id=?", (new_count, user_id))
    conn.commit()
    conn.close()

    if new_count >= max_attempts:
        return {"action": "block", "count": new_count}
    return {"action": "warn", "count": new_count}


def block_user_temp(user_id: int) -> Dict[str, Any]:
    settings = get_alert_settings()
    max_temp = settings.get("max_temp_blocks", 3)
    duration = settings.get("block_duration_minutes", 30)

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT temp_blocks FROM users WHERE id=?", (user_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return {"blocked": False}

    temp_count = (row[0] or 0) + 1

    if temp_count >= max_temp:
        # Permanent block
        cursor.execute(
            "UPDATE users SET is_blocked=1, blocked_at=NULL, failed_attempts=0, temp_blocks=? WHERE id=?",
            (temp_count, user_id),
        )
        conn.commit()
        conn.close()
        return {"blocked": True, "permanent": True, "temp_blocks": temp_count}

    # Temporary block
    unblock_time = datetime.utcnow() + timedelta(minutes=duration)
    cursor.execute(
        "UPDATE users SET is_blocked=1, blocked_at=?, failed_attempts=0, temp_blocks=? WHERE id=?",
        (unblock_time.isoformat(), temp_count, user_id),
    )
    conn.commit()
    conn.close()
    return {"blocked": True, "permanent": False, "temp_blocks": temp_count, "unblock_at": unblock_time.isoformat()}


def check_and_release_expired_blocks(user_id: int) -> bool:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT is_blocked, blocked_at FROM users WHERE id=?", (user_id,))
    row = cursor.fetchone()
    if not row or not row[0] or not row[1]:
        conn.close()
        return False
    try:
        unblock_time = datetime.fromisoformat(row[1])
        if datetime.utcnow() >= unblock_time:
            cursor.execute(
                "UPDATE users SET is_blocked=0, blocked_at=NULL, failed_attempts=0 WHERE id=?",
                (user_id,),
            )
            conn.commit()
            conn.close()
            return True
    except Exception:
        pass
    conn.close()
    return False


# ── Security logging with JSON export ────────────────────────────────────────

def _export_logs_to_json():
    """Write all security logs to ./security_logs.json in the current directory."""
    try:
        logs = get_security_logs(limit=10000)
        with open(LOGS_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2, default=str)
    except Exception as e:
        print(f"[Auth] JSON log export failed: {e}")


def log_security_event(
    user_id: int,
    username: str,
    prompt: str,
    detection_type: str,
    action: str,
    severity: str,
    details: dict = None,
):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO security_logs
           (user_id, username, prompt, detection_type, action, severity, details)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            user_id, username, prompt, detection_type, action, severity,
            json.dumps(details) if details else None,
        ),
    )
    conn.commit()
    conn.close()
    # Export to JSON on every new event
    _export_logs_to_json()


def get_security_logs(limit: int = 100) -> list:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, timestamp, user_id, username, prompt, detection_type, action, severity, details "
        "FROM security_logs ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    )
    logs = cursor.fetchall()
    conn.close()
    return [
        {
            "id": log[0], "timestamp": log[1], "user_id": log[2],
            "username": log[3], "prompt": log[4], "detection_type": log[5],
            "action": log[6], "severity": log[7],
            "details": json.loads(log[8]) if log[8] else None,
        }
        for log in logs
    ]


# ── Alert settings ────────────────────────────────────────────────────────────

def get_alert_settings() -> dict:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT max_attempts_to_block, warning_window_minutes, block_duration_minutes, "
        "max_temp_blocks, enable_email, enable_telegram, email_address, telegram_chat_id "
        "FROM alert_settings WHERE id=1"
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return {}
    return {
        "max_attempts_to_block": row[0], "warning_window_minutes": row[1],
        "block_duration_minutes": row[2], "max_temp_blocks": row[3],
        "enable_email": bool(row[4]), "enable_telegram": bool(row[5]),
        "email_address": row[6] or "", "telegram_chat_id": row[7] or "",
    }


def update_alert_settings(settings: dict) -> dict:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """UPDATE alert_settings SET
           max_attempts_to_block=?, warning_window_minutes=?, block_duration_minutes=?,
           max_temp_blocks=?, enable_email=?, enable_telegram=?,
           email_address=?, telegram_chat_id=?, updated_at=CURRENT_TIMESTAMP
           WHERE id=1""",
        (
            settings.get("max_attempts_to_block", 3),
            settings.get("warning_window_minutes", 10),
            settings.get("block_duration_minutes", 30),
            settings.get("max_temp_blocks", 3),
            int(settings.get("enable_email", False)),
            int(settings.get("enable_telegram", False)),
            settings.get("email_address", ""),
            settings.get("telegram_chat_id", ""),
        ),
    )
    conn.commit()
    conn.close()
    return get_alert_settings()


# Initialise on import
init_database()
