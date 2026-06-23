"""routers/auth_routes.py — Authentication endpoints."""
from fastapi import APIRouter, Depends, Header
from fastapi.responses import JSONResponse

import auth
from auth_utils import decode_token
from core.dependencies import require_user
from schemas import RegisterRequest, LoginRequest

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register")
async def register(body: RegisterRequest):
    try:
        user = await auth.register_user(body.username, body.password, body.email)
        # Create a session token so front-end can log in immediately after register
        token = await auth.create_session(user["id"])
        return JSONResponse(content={"message": "Registration successful", "token": token, "user": user})
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})


@router.post("/login")
async def login(body: LoginRequest):
    try:
        result = await auth.login_user(body.username, body.password)
        return JSONResponse(content={"token": result["token"], "user": result["user"]})
    except ValueError as exc:
        msg = str(exc)
        if "blocked" in msg.lower():
            return JSONResponse(status_code=403, content={"error": msg})
        return JSONResponse(status_code=401, content={"error": "Invalid credentials"})


@router.get("/me")
async def get_current_user(user: dict = Depends(require_user)):
    if user:
        await auth.check_and_release_expired_blocks(user["id"])
    return JSONResponse(content={"user": user})


@router.post("/logout")
async def logout(authorization: str = Header(None)):
    """Delete the session row so the token is immediately invalidated."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        from sqlalchemy import delete
        from db import AsyncSessionLocal, Session as DBSession
        async with AsyncSessionLocal() as session:
            await session.execute(
                delete(DBSession).where(DBSession.token == token)
            )
            await session.commit()
    return JSONResponse(content={"message": "Logged out"})
