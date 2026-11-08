"""Request-scoped Elastic cluster / session selection for MCP tool calls."""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Optional, Tuple

_elastic_cluster_id: ContextVar[Optional[str]] = ContextVar("elastic_cluster_id", default=None)
_session_id: ContextVar[Optional[str]] = ContextVar("mcp_session_id", default=None)


def get_elastic_cluster_id() -> Optional[str]:
    return _elastic_cluster_id.get()


def set_elastic_cluster_id(cluster_id: Optional[str]) -> Token:
    return _elastic_cluster_id.set(cluster_id or None)


def reset_elastic_cluster_id(token: Token) -> None:
    _elastic_cluster_id.reset(token)


def get_session_id() -> Optional[str]:
    return _session_id.get()


def set_session_id(session_id: Optional[str]) -> Token:
    return _session_id.set(session_id or None)


def reset_session_id(token: Token) -> None:
    _session_id.reset(token)


def extract_cluster_id(params: Optional[dict]) -> Optional[str]:
    """Read cluster id from MCP JSON-RPC params (`_meta` or top-level)."""
    if not params or not isinstance(params, dict):
        return None
    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
    value = meta.get("elastic_cluster_id") or params.get("elastic_cluster_id")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def extract_session_id(params: Optional[dict]) -> Optional[str]:
    """Read originating SamiGPT session id from MCP JSON-RPC params."""
    if not params or not isinstance(params, dict):
        return None
    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
    value = meta.get("session_id") or params.get("session_id")
    if isinstance(value, str) and value.strip():
        return value.strip()
    args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    nested = args.get("session_id")
    if isinstance(nested, str) and nested.strip():
        return nested.strip()
    return None


def bind_request_context(params: Optional[dict]) -> Tuple[Token, Token]:
    """Set cluster + session context for one MCP request; return reset tokens."""
    return (
        set_elastic_cluster_id(extract_cluster_id(params)),
        set_session_id(extract_session_id(params)),
    )


def reset_request_context(cluster_token: Token, session_token: Token) -> None:
    reset_elastic_cluster_id(cluster_token)
    reset_session_id(session_token)
