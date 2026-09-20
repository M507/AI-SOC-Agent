"""Resolve SIEM / EDR / case / engineering clients for approved actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Tuple

from ...core.logging import get_logger

logger = get_logger("sami.approval_queue.clients")


@dataclass
class ClientBundle:
    cluster_id: Optional[str] = None
    siem: Any = None
    edr: Any = None
    case: Any = None
    eng: Any = None


def _supervisor_server():
    try:
        from ...mcp.supervisor import get_supervisor

        supervisor = get_supervisor()
        if supervisor.is_running:
            return supervisor.server
    except Exception as exc:
        logger.debug("MCP supervisor not available: %s", exc)
    return None


def resolve_siem(cluster_id: Optional[str] = None) -> Tuple[Any, Optional[str]]:
    """Return (siem_client, cluster_id) for the request's originating cluster."""
    server = _supervisor_server()
    if server is not None:
        clients = getattr(server, "_siem_clients", {}) or {}
        default_id = getattr(server, "_default_cluster_id", None)
        if cluster_id and cluster_id in clients:
            return clients[cluster_id], cluster_id
        if cluster_id and clients:
            logger.warning("Cluster %s has no live SIEM client; trying default", cluster_id)
        if default_id and default_id in clients:
            return clients[default_id], default_id
        if clients:
            first_id = next(iter(clients))
            return clients[first_id], first_id
        live = getattr(server, "_default_siem", None) or getattr(server, "siem_client", None)
        if live is not None:
            return live, cluster_id or default_id

    from ...core.elastic_clusters import client_for_cluster, get_cluster, load_registry

    cluster = get_cluster(cluster_id) if cluster_id else None
    if cluster is None:
        registry = load_registry()
        cluster = registry.get(registry.default_cluster_id) if registry.default_cluster_id else None
        if cluster is None and registry.clusters:
            cluster = registry.clusters[0]
    if cluster is None:
        return None, cluster_id
    try:
        return client_for_cluster(cluster), cluster.id
    except Exception as exc:
        logger.warning("Could not build SIEM client for cluster %s: %s", cluster.id, exc)
        return None, cluster.id


def resolve_clients(cluster_id: Optional[str] = None) -> ClientBundle:
    siem, resolved_cluster = resolve_siem(cluster_id)
    bundle = ClientBundle(cluster_id=resolved_cluster or cluster_id, siem=siem)
    server = _supervisor_server()
    if server is not None:
        bundle.edr = getattr(server, "edr_client", None)
        bundle.case = getattr(server, "case_client", None)
        bundle.eng = getattr(server, "eng_client", None)
        return bundle

    try:
        from ...mcp.factory import load_runtime_config, _init_case_client, _init_edr_client, _init_eng_client
        from ...core.logging import get_logger as _get

        config = load_runtime_config()
        silent = _get("sami.approval_queue.clients.init")
        bundle.case = _init_case_client(config, silent)
        bundle.edr = _init_edr_client(config, silent)
        bundle.eng = _init_eng_client(config, silent)
    except Exception as exc:
        logger.debug("Could not initialize case/EDR/eng clients: %s", exc)
    return bundle
