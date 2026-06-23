"""
schemas.py
==========
Pydantic request/response DTOs for all API endpoints.
"""
from pydantic import BaseModel, Field
from typing import Optional


# ── Auth ──────────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    email: str = Field(..., min_length=5)


class LoginRequest(BaseModel):
    username: str
    password: str


# ── Chat ──────────────────────────────────────────────────────────────────────
class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1, max_length=8000)
    user_id: Optional[int] = None


# ── Admin — filter configuration ──────────────────────────────────────────────
class BertModelRequest(BaseModel):
    model: str = Field(..., pattern="^(modernbert|distilbert)$")


class ThresholdRequest(BaseModel):
    threshold: float = Field(..., ge=0, le=100)


class AlertSettingsRequest(BaseModel):
    max_attempts_to_block: int = Field(..., ge=1, le=100)
    warning_window_minutes: int = Field(..., ge=1, le=1440)
    block_duration_minutes: int = Field(..., ge=1, le=10080)
    max_temp_blocks: int = Field(3, ge=1, le=20)
    enable_email: bool = False
    enable_telegram: bool = False
    email_address: str = ""
    telegram_chat_id: str = ""
