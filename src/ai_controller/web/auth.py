"""
Web UI authentication: config.json password, signed sessions, login rate limits.

Every HTTP route except the login endpoints requires a valid session cookie.
WebSockets are checked separately because Starlette middleware does not run
for the WebSocket handshake.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple
from urllib.parse import quote

from fastapi import HTTPException, Request, Response, WebSocket, status
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ...core.config_storage import get_section, update_raw_section
from ...core.logging import get_logger

logger = get_logger("sami.web.auth")

COOKIE_NAME = "sami_session"
PUBLIC_PATHS = frozenset({"/login", "/api/auth/login", "/api/auth/status"})
WEAK_PASSWORD_VALUES = frozenset({"", "changeme", "admin", "password", "secret"})
PLACEHOLDER_SECRETS = frozenset(
    {
        "",
        "generate-a-random-secret-key-here-minimum-32-characters",
        "changeme",
    }
)

_sessions: Dict[str, Dict] = {}
_login_failures: Dict[str, list] = {}


@dataclass(frozen=True)
class WebAuthConfig:
    username: str
    password: str
    session_secret: str
    session_ttl_seconds: int
    cookie_secure: bool


def _consteq(left: str, right: str) -> bool:
    """Length-independent string compare."""
    return hmac.compare_digest(
        hashlib.sha256(left.encode("utf-8")).digest(),
        hashlib.sha256(right.encode("utf-8")).digest(),
    )


def load_web_auth_config(cookie_secure: bool = True) -> WebAuthConfig:
    """Load auth settings from config.json, generating a session secret if needed."""
    raw = get_section(
        "web",
        {
            "username": "admin",
            "password": "",
            "session_secret": "",
            "session_ttl_seconds": 43200,
        },
    )
    username = (raw.get("username") or "admin").strip()
    password = raw.get("password") or ""
    if not password.strip():
        raise RuntimeError(
            "config.json is missing web.password. Set a password under the 'web' section "
            "before starting the UI."
        )
    secret = (raw.get("session_secret") or "").strip()
    if secret in PLACEHOLDER_SECRETS or len(secret) < 32:
        secret = secrets.token_urlsafe(48)
        persisted = dict(raw)
        persisted["username"] = username
        persisted["password"] = password
        persisted["session_secret"] = secret
        persisted["session_ttl_seconds"] = int(raw.get("session_ttl_seconds") or 43200)
        update_raw_section("web", persisted)
        logger.warning("Generated a new web.session_secret and wrote it to config.json")
    ttl = int(raw.get("session_ttl_seconds") or 43200)
    if password.strip().lower() in WEAK_PASSWORD_VALUES:
        logger.warning(
            "web.password in config.json is a well-known default. Change it before exposing the UI."
        )
    return WebAuthConfig(
        username=username,
        password=password,
        session_secret=secret,
        session_ttl_seconds=max(ttl, 300),
        cookie_secure=cookie_secure,
    )


class SessionManagerAuth:
    """Signed cookie + in-memory session store."""

    def __init__(self, config: WebAuthConfig) -> None:
        self.config = config

    def _sign(self, value: str) -> str:
        return hmac.new(
            self.config.session_secret.encode("utf-8"),
            value.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def create_session(self, username: str) -> str:
        session_id = secrets.token_urlsafe(32)
        expires = datetime.now(timezone.utc) + timedelta(seconds=self.config.session_ttl_seconds)
        payload = f"{session_id}.{int(expires.timestamp())}"
        token = f"{payload}.{self._sign(payload)}"
        _sessions[session_id] = {
            "username": username,
            "expires": expires,
            "created": datetime.now(timezone.utc),
        }
        return token

    def revoke(self, token: Optional[str]) -> None:
        parsed = self._parse(token)
        if parsed:
            _sessions.pop(parsed[0], None)

    def authenticate_token(self, token: Optional[str]) -> Optional[Dict]:
        parsed = self._parse(token)
        if not parsed:
            return None
        session_id, _expires_ts = parsed
        record = _sessions.get(session_id)
        if not record:
            return None
        if record["expires"] <= datetime.now(timezone.utc):
            _sessions.pop(session_id, None)
            return None
        return {"session_id": session_id, **record}

    def _parse(self, token: Optional[str]) -> Optional[Tuple[str, int]]:
        if not token:
            return None
        parts = token.split(".")
        if len(parts) != 3:
            return None
        session_id, expires_raw, signature = parts
        payload = f"{session_id}.{expires_raw}"
        expected = self._sign(payload)
        if not hmac.compare_digest(signature, expected):
            return None
        try:
            expires_ts = int(expires_raw)
        except ValueError:
            return None
        if expires_ts <= int(time.time()):
            return None
        return session_id, expires_ts

    def set_cookie(self, response: Response, token: str) -> None:
        response.set_cookie(
            key=COOKIE_NAME,
            value=token,
            max_age=self.config.session_ttl_seconds,
            httponly=True,
            secure=self.config.cookie_secure,
            samesite="strict",
            path="/",
        )

    def clear_cookie(self, response: Response) -> None:
        response.delete_cookie(
            COOKIE_NAME,
            path="/",
            secure=self.config.cookie_secure,
            httponly=True,
            samesite="strict",
        )


_auth: Optional[SessionManagerAuth] = None


def init_auth(cookie_secure: bool = True) -> SessionManagerAuth:
    global _auth
    _auth = SessionManagerAuth(load_web_auth_config(cookie_secure=cookie_secure))
    return _auth


def get_auth() -> SessionManagerAuth:
    if _auth is None:
        return init_auth()
    return _auth


def current_user(request: Request) -> Optional[Dict]:
    return get_auth().authenticate_token(request.cookies.get(COOKIE_NAME))


def websocket_user(websocket: WebSocket) -> Optional[Dict]:
    return get_auth().authenticate_token(websocket.cookies.get(COOKIE_NAME))


def login_allowed(ip: str) -> bool:
    """Simple per-IP brute-force throttle."""
    now = time.time()
    window = 15 * 60
    failures = [ts for ts in _login_failures.get(ip, []) if now - ts < window]
    _login_failures[ip] = failures
    return len(failures) < 5


def record_login_failure(ip: str) -> None:
    _login_failures.setdefault(ip, []).append(time.time())


def clear_login_failures(ip: str) -> None:
    _login_failures.pop(ip, None)


def verify_credentials(username: str, password: str) -> bool:
    cfg = get_auth().config
    return _consteq(username.strip(), cfg.username) and _consteq(password, cfg.password)


class AuthMiddleware(BaseHTTPMiddleware):
    """Reject unauthenticated access to the UI, APIs, and static assets."""

    async def dispatch(self, request: Request, call_next):
        if request.url.scheme == "http":
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"success": False, "detail": "HTTPS is required"},
            )
        path = request.url.path
        if path in PUBLIC_PATHS:
            return await call_next(request)

        user = current_user(request)
        if user:
            request.state.user = user
            return await call_next(request)

        if path.startswith("/api/") or path.startswith("/ws/"):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"success": False, "detail": "Authentication required"},
            )
        login_url = "/login"
        if path and path != "/":
            login_url = f"/login?next={quote(path)}"
        return RedirectResponse(url=login_url, status_code=status.HTTP_302_FOUND)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """HTTPS-only browser hardening headers."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' wss: https:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'",
        )
        if "server" in response.headers:
            del response.headers["server"]
        return response


def require_user(request: Request) -> Dict:
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return user
