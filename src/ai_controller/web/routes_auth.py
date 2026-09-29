"""Login / logout endpoints. These are the only unauthenticated API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .audit_log import record_signin
from .auth import (
    clear_login_failures,
    current_user,
    get_auth,
    login_allowed,
    record_login_failure,
    verify_credentials,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


@router.post("/login")
async def login(payload: LoginRequest, request: Request, response: Response):
    ip = request.client.host if request.client else "unknown"
    if not login_allowed(ip):
        return JSONResponse(
            status_code=429,
            content={"success": False, "detail": "Too many failed logins. Try again later."},
        )
    if not verify_credentials(payload.username, payload.password):
        record_login_failure(ip)
        record_signin("failed", payload.username, ip)
        return JSONResponse(
            status_code=401,
            content={"success": False, "detail": "Invalid username or password"},
        )
    clear_login_failures(ip)
    auth = get_auth()
    username = payload.username.strip()
    token = auth.create_session(username)
    auth.set_cookie(response, token)
    record_signin("signed_in", username, ip)
    return {"success": True}


@router.post("/logout")
async def logout(request: Request, response: Response):
    auth = get_auth()
    user = current_user(request)
    auth.revoke(request.cookies.get("sami_session"))
    auth.clear_cookie(response)
    if user:
        ip = request.client.host if request.client else ""
        record_signin("signed_out", user.get("username") or "", ip)
    return {"success": True}


@router.get("/status")
async def auth_status(request: Request):
    user = current_user(request)
    if not user:
        return {"success": True, "authenticated": False}
    return {
        "success": True,
        "authenticated": True,
        "username": user.get("username"),
    }
