"""
Web server for SamiGPT configuration management.

This module provides a FastAPI server that exposes:
- REST API for managing configurations
- Web UI for configuring TheHive, Elastic (SIEM), and EDR integrations

The interface is protected with a secret/password that must be set via environment variable.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from ..core.config_storage import (
    CONFIG_FILE,
    ENV_FILE,
    get_config_dict,
    load_config_from_file,
    update_config_dict,
)
from ..core.errors import ConfigError

# Get admin secret from environment or use default
ADMIN_SECRET = os.getenv("SAMIGPT_ADMIN_SECRET", "admin")
SESSION_SECRET = os.getenv("SAMIGPT_SESSION_SECRET", secrets.token_urlsafe(32))

# In-memory session store (for simple implementation)
# In production, consider using Redis or database-backed sessions
_sessions: Dict[str, Dict[str, Any]] = {}


class SimpleSessionMiddleware(BaseHTTPMiddleware):
    """
    Simple session middleware that doesn't require itsdangerous.
    Uses signed cookies with HMAC for security.
    """

    def __init__(self, app, secret_key: str):
        super().__init__(app)
        self.secret_key = secret_key.encode()

    async def dispatch(self, request: Request, call_next):
        # Get session ID from cookie
        session_id = request.cookies.get("session_id")
        session_data = {}

        if session_id and session_id in _sessions:
            # Verify signature
            expected_sig = self._sign(session_id)
            provided_sig = request.cookies.get("session_sig", "")
            if hmac.compare_digest(expected_sig, provided_sig):
                session_data = _sessions[session_id].copy()

        # Attach session to request state
        request.state.session = session_data

        # Process request
        response = await call_next(request)

        # Save session if modified
        if hasattr(request.state, "session_modified") and request.state.session_modified:
            if not session_id or session_id not in _sessions:
                session_id = secrets.token_urlsafe(32)
                _sessions[session_id] = {}

            _sessions[session_id].update(request.state.session)

            # Set cookie with signature
            sig = self._sign(session_id)
            response.set_cookie(
                key="session_id",
                value=session_id,
                httponly=True,
                samesite="lax",
                max_age=86400,  # 24 hours
            )
            response.set_cookie(
                key="session_sig",
                value=sig,
                httponly=True,
                samesite="lax",
                max_age=86400,
            )

        return response

    def _sign(self, data: str) -> str:
        """Create HMAC signature for session ID."""
        return hmac.new(self.secret_key, data.encode(), hashlib.sha256).hexdigest()


# Create FastAPI app
app = FastAPI(
    title="SamiGPT Configuration Manager",
    description="Web interface for configuring SamiGPT integrations",
    version="1.0.0",
)

# Add simple session middleware (no itsdangerous dependency)
app.add_middleware(SimpleSessionMiddleware, secret_key=SESSION_SECRET)

# Determine paths
WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"
TEMPLATES_DIR = WEB_DIR / "templates"

# Create directories if they don't exist
STATIC_DIR.mkdir(exist_ok=True)
TEMPLATES_DIR.mkdir(exist_ok=True)

# Mount static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Helper function to check authentication
def is_authenticated(request: Request) -> bool:
    """Check if the request is authenticated."""
    session_data = getattr(request.state, "session", {})
    return session_data.get("authenticated", False) == True


def require_auth(request: Request) -> None:
    """Require authentication or raise 401."""
    if not is_authenticated(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )


# Pydantic models for API requests
class LoginRequest(BaseModel):
    secret: str


class TheHiveConfigUpdate(BaseModel):
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    timeout_seconds: Optional[int] = 30
    enabled: bool = True


class IrisConfigUpdate(BaseModel):
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    timeout_seconds: Optional[int] = 30
    enabled: bool = True


class ElasticConfigUpdate(BaseModel):
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    timeout_seconds: Optional[int] = 30
    verify_ssl: Optional[bool] = True
    enabled: bool = True


class EDRConfigUpdate(BaseModel):
    edr_type: Optional[str] = "velociraptor"
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    timeout_seconds: Optional[int] = 30
    enabled: bool = True


class LoggingConfigUpdate(BaseModel):
    log_dir: Optional[str] = "logs"
    log_level: Optional[str] = "INFO"


class ConfigUpdate(BaseModel):
    thehive: Optional[TheHiveConfigUpdate] = None
    iris: Optional[IrisConfigUpdate] = None
    elastic: Optional[ElasticConfigUpdate] = None
    edr: Optional[EDRConfigUpdate] = None
    logging: Optional[LoggingConfigUpdate] = None


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Serve the login page or main configuration page if authenticated."""
    session_data = getattr(request.state, "session", {})
    if not session_data.get("authenticated", False):
        login_path = TEMPLATES_DIR / "login.html"
        if login_path.exists():
            with open(login_path, "r") as f:
                return HTMLResponse(content=f.read())
        return HTMLResponse(
            content="""
            <!DOCTYPE html>
            <html>
            <head><title>Login - SamiGPT</title></head>
            <body>
                <h1>Login Required</h1>
                <p>Please set SAMIGPT_ADMIN_SECRET environment variable and login page will appear.</p>
            </body>
            </html>
            """
        )
    
    # Authenticated - serve config page
    html_path = TEMPLATES_DIR / "index.html"
    if html_path.exists():
        with open(html_path, "r") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(
        content="<h1>SamiGPT Configuration Manager</h1><p>index.html not found</p>"
    )


@app.post("/api/auth/login")
async def login(request: Request, login_data: LoginRequest):
    """Authenticate with the admin secret."""
    # Compare using constant-time comparison to prevent timing attacks
    if secrets.compare_digest(login_data.secret, ADMIN_SECRET):
        request.state.session = request.state.session if hasattr(request.state, "session") else {}
        request.state.session["authenticated"] = True
        request.state.session_modified = True
        return JSONResponse(content={"success": True, "message": "Authentication successful"})
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid secret",
        )


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    """Logout and clear session."""
    session_id = request.cookies.get("session_id")
    if session_id and session_id in _sessions:
        del _sessions[session_id]
    
    # Clear cookies
    response.delete_cookie("session_id")
    response.delete_cookie("session_sig")
    
    return JSONResponse(content={"success": True, "message": "Logged out successfully"})


@app.get("/api/auth/status")
async def auth_status(request: Request):
    """Check authentication status."""
    session_data = getattr(request.state, "session", {})
    authenticated = session_data.get("authenticated", False) == True
    return JSONResponse(
        content={"authenticated": authenticated}
    )


@app.get("/api/config", response_model=Dict[str, Any])
async def get_config(request: Request):
    """Get current configuration."""
    require_auth(request)
    try:
        config_dict = get_config_dict()
        # Remove sensitive data from response
        if "thehive" in config_dict and config_dict["thehive"]:
            config_dict["thehive"]["api_key"] = "***" if config_dict["thehive"].get("api_key") else None
        if "elastic" in config_dict and config_dict["elastic"]:
            config_dict["elastic"]["api_key"] = "***" if config_dict["elastic"].get("api_key") else None
            config_dict["elastic"]["password"] = "***" if config_dict["elastic"].get("password") else None
        if "edr" in config_dict and config_dict["edr"]:
            config_dict["edr"]["api_key"] = "***" if config_dict["edr"].get("api_key") else None
        
        # Add file location information
        from pathlib import Path
        config_dict["_meta"] = {
            "config_file": str(Path(CONFIG_FILE).absolute()),
            "env_file": str(Path(ENV_FILE).absolute()),
            "config_file_exists": Path(CONFIG_FILE).exists(),
            "env_file_exists": Path(ENV_FILE).exists(),
        }
        return JSONResponse(content=config_dict)
    except ConfigError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/config", response_model=Dict[str, Any])
async def update_config(request: Request, config_update: ConfigUpdate):
    """Update configuration."""
    require_auth(request)
    try:
        # Build update dict
        updates: Dict[str, Any] = {}

        if config_update.thehive is not None:
            if config_update.thehive.enabled:
                if not config_update.thehive.base_url or not config_update.thehive.api_key:
                    raise HTTPException(
                        status_code=400,
                        detail="TheHive base_url and api_key are required when enabled",
                    )
                updates["thehive"] = {
                    "base_url": config_update.thehive.base_url,
                    "api_key": config_update.thehive.api_key,
                    "timeout_seconds": config_update.thehive.timeout_seconds or 30,
                }
            else:
                updates["thehive"] = None

        if config_update.iris is not None:
            if config_update.iris.enabled:
                if not config_update.iris.base_url or not config_update.iris.api_key:
                    raise HTTPException(
                        status_code=400,
                        detail="IRIS base_url and api_key are required when enabled",
                    )
                updates["iris"] = {
                    "base_url": config_update.iris.base_url,
                    "api_key": config_update.iris.api_key,
                    "timeout_seconds": config_update.iris.timeout_seconds or 30,
                }
            else:
                updates["iris"] = None

        if config_update.elastic is not None:
            if config_update.elastic.enabled:
                if not config_update.elastic.base_url:
                    raise HTTPException(
                        status_code=400,
                        detail="Elastic base_url is required when enabled",
                    )
                updates["elastic"] = {
                    "base_url": config_update.elastic.base_url,
                    "api_key": config_update.elastic.api_key,
                    "username": config_update.elastic.username,
                    "password": config_update.elastic.password,
                    "timeout_seconds": config_update.elastic.timeout_seconds or 30,
                    "verify_ssl": config_update.elastic.verify_ssl,
                }
            else:
                updates["elastic"] = None

        if config_update.edr is not None:
            if config_update.edr.enabled:
                if not config_update.edr.base_url or not config_update.edr.api_key:
                    raise HTTPException(
                        status_code=400,
                        detail="EDR base_url and api_key are required when enabled",
                    )
                updates["edr"] = {
                    "edr_type": config_update.edr.edr_type or "velociraptor",
                    "base_url": config_update.edr.base_url,
                    "api_key": config_update.edr.api_key,
                    "timeout_seconds": config_update.edr.timeout_seconds or 30,
                }
            else:
                updates["edr"] = None

        if config_update.logging is not None:
            updates["logging"] = {
                "log_dir": config_update.logging.log_dir or "logs",
                "log_level": config_update.logging.log_level or "INFO",
            }

        # Update and save config
        updated_config = update_config_dict(updates)
        config_dict = get_config_dict()

        return JSONResponse(content={"success": True, "config": config_dict})
    except ConfigError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/config/test/thehive")
async def test_thehive(request: Request):
    """Test TheHive connection."""
    require_auth(request)
    try:
        config = load_config_from_file()
        if not config.thehive:
            raise HTTPException(status_code=400, detail="TheHive not configured")

        from ..integrations.case_management.thehive.thehive_client import (
            TheHiveCaseManagementClient,
        )

        client = TheHiveCaseManagementClient.from_config(config)
        is_connected = client.ping()

        return JSONResponse(
            content={
                "success": is_connected,
                "message": "Connected successfully" if is_connected else "Connection failed",
            }
        )
    except Exception as e:
        return JSONResponse(
            content={"success": False, "message": str(e)}, status_code=500
        )


@app.get("/api/config/test/iris")
async def test_iris(request: Request):
    """Test IRIS connection."""
    require_auth(request)
    try:
        config = load_config_from_file()
        if not config.iris:
            raise HTTPException(status_code=400, detail="IRIS not configured")

        from ..integrations.case_management.iris.iris_client import (
            IRISCaseManagementClient,
        )

        client = IRISCaseManagementClient.from_config(config)
        is_connected = client.ping()

        return JSONResponse(
            content={
                "success": is_connected,
                "message": "Connected successfully" if is_connected else "Connection failed",
            }
        )
    except Exception as e:
        return JSONResponse(
            content={"success": False, "message": str(e)}, status_code=500
        )


@app.get("/api/config/test/elastic")
async def test_elastic(request: Request):
    """Test Elastic connection."""
    require_auth(request)
    try:
        config = load_config_from_file()
        if not config.elastic:
            raise HTTPException(status_code=400, detail="Elastic not configured")

        # TODO: Implement Elastic client test when integration is available
        return JSONResponse(
            content={
                "success": False,
                "message": "Elastic integration not yet implemented",
            }
        )
    except Exception as e:
        return JSONResponse(
            content={"success": False, "message": str(e)}, status_code=500
        )


@app.get("/api/config/test/edr")
async def test_edr(request: Request):
    """Test EDR connection."""
    require_auth(request)
    try:
        config = load_config_from_file()
        if not config.edr:
            raise HTTPException(status_code=400, detail="EDR not configured")

        # TODO: Implement EDR client test when integration is available
        return JSONResponse(
            content={
                "success": False,
                "message": "EDR integration not yet implemented",
            }
        )
    except Exception as e:
        return JSONResponse(
            content={"success": False, "message": str(e)}, status_code=500
        )


@app.post("/api/config/reload")
async def reload_config(request: Request):
    """Reload configuration from files (sync from .env or config.json)."""
    require_auth(request)
    try:
        # Force reload from files (priority: .env > config.json)
        config = load_config_from_file()
        # Save to both files to sync them
        from ..core.config_storage import save_config_to_file
        save_config_to_file(config, save_both=True)
        
        config_dict = get_config_dict()
        return JSONResponse(
            content={
                "success": True,
                "message": "Configuration reloaded from files",
                "config": config_dict,
            }
        )
    except ConfigError as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    print(f"Starting SamiGPT Configuration Manager...")
    print(f"Admin secret is set via SAMIGPT_ADMIN_SECRET environment variable")
    if ADMIN_SECRET == "admin":
        print("WARNING: Using default admin secret! Set SAMIGPT_ADMIN_SECRET environment variable.")
    uvicorn.run(app, host="0.0.0.0", port=8080)
