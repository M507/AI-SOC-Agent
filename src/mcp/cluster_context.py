"""Request-scoped Elastic cluster selection for MCP tool calls."""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Optional

_elastic_cluster_id: ContextVar[Optional[str]] = ContextVar("elastic_cluster_id", default=None)


def get_elastic_cluster_id() -> Optional[str]:
    return _elastic_cluster_id.get()


def set_elastic_cluster_id(cluster_id: Optional[str]) -> Token:
    return _elastic_cluster_id.set(cluster_id or None)


def reset_elastic_cluster_id(token: Token) -> None:
    _elastic_cluster_id.reset(token)


def extract_cluster_id(params: Optional[dict]) -> Optional[str]:
    """Read cluster id from MCP JSON-RPC params (`_meta` or top-level)."""
    if not params or not isinstance(params, dict):
        return None
    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
    value = meta.get("elastic_cluster_id") or params.get("elastic_cluster_id")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
