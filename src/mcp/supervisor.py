"""
Lifecycle manager for the HTTP MCP server.

The MCP listener is a separate FastAPI app on its own port. The web UI talks
to this supervisor to start/stop/restart and to read health. External MCP
clients (Open WebUI, Cursor over HTTP, custom agents) connect to the same
listener.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import uvicorn

from ..core.config_storage import get_section, update_raw_section
from ..core.logging import get_logger
from ..core.tls import ensure_tls_certs
from .factory import build_mcp_server, load_runtime_config
from .http_server import create_mcp_http_app, describe_mcp_endpoints
from .mcp_server import SamiGPTMCPServer, configure_mcp_logging

logger = get_logger("sami.mcp.supervisor")

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8082


class MCPSupervisor:
    """Owns the HTTP MCP uvicorn thread and the underlying tool server."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._uvicorn: Optional[uvicorn.Server] = None
        self._server: Optional[SamiGPTMCPServer] = None
        self._host = _DEFAULT_HOST
        self._port = _DEFAULT_PORT
        self._started_at: Optional[str] = None
        self._last_error: Optional[str] = None
        self._tls = True

    @property
    def server(self) -> Optional[SamiGPTMCPServer]:
        return self._server

    @property
    def is_running(self) -> bool:
        uvicorn_server = self._uvicorn
        thread = self._thread
        return bool(
            uvicorn_server
            and thread
            and thread.is_alive()
            and not uvicorn_server.should_exit
        )

    def start(self, host: Optional[str] = None, port: Optional[int] = None) -> Dict[str, Any]:
        """Start the HTTP MCP listener. Idempotent if already running on the same bind."""
        with self._lock:
            host = host or self._host
            port = int(port or self._port)

            if self.is_running:
                if host == self._host and port == self._port:
                    return self.status()
                self._stop_locked()

            try:
                config = load_runtime_config()
                log_dir = config.logging.log_dir if config.logging else "logs"
                configure_mcp_logging(log_dir)
                built = build_mcp_server(config)
                self._server = built.server
                mcp_cfg = get_section("mcp", {})
                api_token = (mcp_cfg.get("api_token") or "").strip()
                if not api_token:
                    import secrets as _secrets

                    api_token = _secrets.token_urlsafe(32)
                    persisted = dict(mcp_cfg)
                    persisted["api_token"] = api_token
                    persisted.setdefault("host", host)
                    persisted.setdefault("port", port)
                    persisted.setdefault("enabled", True)
                    persisted.setdefault("auto_start", True)
                    update_raw_section("mcp", persisted)
                    logger.warning("Generated mcp.api_token and wrote it to config.json")

                app = create_mcp_http_app(self._server, api_token=api_token)
                cert_file, key_file = ensure_tls_certs()

                uv_config = uvicorn.Config(
                    app,
                    host=host,
                    port=port,
                    log_level="warning",
                    access_log=False,
                    ssl_certfile=cert_file,
                    ssl_keyfile=key_file,
                )
                uv_server = uvicorn.Server(uv_config)
                uv_server.install_signal_handlers = False
                thread = threading.Thread(
                    target=uv_server.run,
                    name="sami-mcp-https",
                    daemon=True,
                )
                thread.start()

                self._uvicorn = uv_server
                self._thread = thread
                self._host = host
                self._port = port
                self._started_at = datetime.now(timezone.utc).isoformat()
                self._last_error = None
                logger.info("MCP HTTPS server started on https://%s:%s", host, port)
            except Exception as e:
                self._last_error = str(e)
                logger.exception("Failed to start MCP HTTP server")
                raise

            return self.status()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            self._stop_locked()
            return self.status()

    def restart(self, host: Optional[str] = None, port: Optional[int] = None) -> Dict[str, Any]:
        with self._lock:
            self._stop_locked()
        return self.start(host=host, port=port)

    def _stop_locked(self) -> None:
        if self._uvicorn:
            self._uvicorn.should_exit = True
            try:
                self._uvicorn.force_exit = True
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._uvicorn = None
        self._thread = None
        self._started_at = None
        logger.info("MCP HTTP server stopped")

    def reload_siem_clients(self) -> Dict[str, Any]:
        """Rebuild Elastic cluster clients on the running MCP server."""
        with self._lock:
            if self._server is None:
                return {"reloaded": False, "reason": "MCP server is not built yet"}
            from .factory import load_runtime_config, _init_siem_clients

            config = load_runtime_config()
            clients, default_id, default_client = _init_siem_clients(config, logger)
            self._server.replace_siem_clients(clients, default_id, default_client)
            logger.info(
                "Reloaded %s Elastic SIEM cluster client(s); default=%s",
                len(clients),
                default_id,
            )
            return {
                "reloaded": True,
                "cluster_ids": sorted(clients.keys()),
                "default_cluster_id": default_id,
            }

    def status(self) -> Dict[str, Any]:
        running = self.is_running
        snapshot = self._server.health_snapshot() if self._server else {}
        payload: Dict[str, Any] = {
            "running": running,
            "status": "healthy" if running else "stopped",
            "host": self._host,
            "port": self._port,
            "tls": True,
            "started_at": self._started_at,
            "last_error": self._last_error,
            "endpoints": describe_mcp_endpoints(self._host, self._port),
        }
        if snapshot:
            payload.update(
                {
                    "server": snapshot.get("server"),
                    "version": snapshot.get("version"),
                    "tools_count": snapshot.get("tools_count", 0),
                    "tools": snapshot.get("tools", []),
                    "integrations": snapshot.get("integrations", {}),
                    "elastic_clusters": snapshot.get("elastic_clusters", []),
                    "elastic_default_cluster_id": snapshot.get("elastic_default_cluster_id"),
                    "eng_provider": snapshot.get("eng_provider"),
                }
            )
        else:
            payload["tools_count"] = 0
            payload["tools"] = []
            payload["integrations"] = {}
        if not running:
            payload["status"] = "unhealthy" if self._last_error else "stopped"
        return payload


_supervisor: Optional[MCPSupervisor] = None
_supervisor_lock = threading.Lock()


def get_supervisor() -> MCPSupervisor:
    """Process-wide MCP supervisor (created on first use)."""
    global _supervisor
    with _supervisor_lock:
        if _supervisor is None:
            _supervisor = MCPSupervisor()
            mcp_cfg = get_section("mcp", {"host": _DEFAULT_HOST, "port": _DEFAULT_PORT})
            _supervisor._host = mcp_cfg.get("host", _DEFAULT_HOST)
            _supervisor._port = int(mcp_cfg.get("port", _DEFAULT_PORT))
        return _supervisor
