"""
db.py
=====
PostgreSQL + TimescaleDB database layer.
Replaces SQLite auth.py database logic.
"""
import os
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import (
    String, Integer, Boolean, DateTime, Text,
    func, text, BigInteger, PrimaryKeyConstraint
)
from sqlalchemy.dialects.postgresql import JSONB
import sqlalchemy as sa  # noqa: F401 — used by alembic env

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://ai_proxy:ai_proxy_secret@localhost:5432/ai_proxy",
)
# Convert to async URL for asyncpg driver
ASYNC_DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

engine = create_async_engine(ASYNC_DATABASE_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="user")
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    blocked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    temp_blocks: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    token: Mapped[str] = mapped_column(
        String(512), unique=True, nullable=False, index=True
    )
    user_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_active: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # Stores conversation history as a JSON array
    context: Mapped[Optional[dict]] = mapped_column(JSONB, default=list)


class AlertSettings(Base):
    __tablename__ = "alert_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    max_attempts_to_block: Mapped[int] = mapped_column(Integer, default=3)
    warning_window_minutes: Mapped[int] = mapped_column(Integer, default=10)
    block_duration_minutes: Mapped[int] = mapped_column(Integer, default=30)
    max_temp_blocks: Mapped[int] = mapped_column(Integer, default=3)
    enable_email: Mapped[bool] = mapped_column(Boolean, default=False)
    enable_telegram: Mapped[bool] = mapped_column(Boolean, default=False)
    email_address: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    telegram_chat_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class SecurityLog(Base):
    __tablename__ = "security_logs"
    __table_args__ = (
        # TimescaleDB requires the partition column (timestamp) in the primary key
        PrimaryKeyConstraint("id", "timestamp"),
    )

    id: Mapped[int] = mapped_column(BigInteger, autoincrement=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    user_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detection_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)


async def init_db():
    """Create tables and TimescaleDB hypertable.  Called once on app startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Create TimescaleDB hypertable for security_logs (time-series optimisation)
        await conn.execute(
            text(
                """
                SELECT create_hypertable('security_logs', 'timestamp',
                    if_not_exists => TRUE,
                    migrate_data  => TRUE)
                """
            )
        )

        # Seed alert_settings singleton row with all defaults explicit
        await conn.execute(
            text(
                """
                INSERT INTO alert_settings
                    (id, max_attempts_to_block, warning_window_minutes,
                     block_duration_minutes, max_temp_blocks,
                     enable_email, enable_telegram)
                VALUES (1, 3, 10, 30, 3, false, false)
                ON CONFLICT (id) DO NOTHING
                """
            )
        )

        # Seed admin user from env
        admin_user = os.getenv("ADMIN_USERNAME", "admin")
        admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
        from auth_utils import hash_password  # imported here to avoid circular import
        hashed = hash_password(admin_pass)
        await conn.execute(
            text(
                """
                INSERT INTO users
                    (username, password, email, role,
                     is_blocked, failed_attempts, temp_blocks)
                VALUES (:u, :p, :e, 'admin', false, 0, 0)
                ON CONFLICT (username) DO NOTHING
                """
            ),
            {"u": admin_user, "p": hashed, "e": f"{admin_user}@localhost"},
        )


@asynccontextmanager
async def get_db_session():
    """Async context-manager style — use with `async with get_db_session() as s:`"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db():
    """FastAPI dependency — yields an AsyncSession."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
