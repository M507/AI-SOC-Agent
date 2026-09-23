"""Elastic cluster settings API."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ...core.elastic_clusters import (
    client_for_id,
    get_cluster,
    load_registry,
    probe_cluster,
    public_clusters,
    save_registry,
    upsert_cluster,
)
from ...core.logging import get_logger
from ...core.skill_vector import catalog_payload, canonicalize
from ...mcp.supervisor import get_supervisor

logger = get_logger("sami.web.elastic")

router = APIRouter(prefix="/api/elastic", tags=["elastic"])


class ElasticClusterPayload(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    base_url: str
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    timeout_seconds: Optional[int] = Field(default=None, ge=5, le=120)
    verify_ssl: Optional[bool] = None
    skill_vector: Optional[str] = None


class ElasticDefaultUpdate(BaseModel):
    cluster_id: str


class SkillVectorPayload(BaseModel):
    skill_vector: str


def _reload_mcp_clients() -> Dict[str, Any]:
    try:
        return get_supervisor().reload_siem_clients()
    except Exception as exc:
        logger.warning("Could not reload MCP SIEM clients: %s", exc)
        return {"reloaded": False, "reason": str(exc)}


def _payload_fields(payload: ElasticClusterPayload) -> Dict[str, Any]:
    """Only client-sent fields, so omitted verify_ssl does not clobber a saved False."""
    return payload.model_dump(exclude_unset=True, exclude_none=True)


def _safe_cluster_fields(cluster) -> str:
    return (
        f"id={cluster.id} name={cluster.name} url={cluster.base_url} "
        f"auth={cluster.auth_type()} verify_ssl={cluster.verify_ssl} "
        f"timeout={cluster.timeout_seconds}s"
    )


@router.get("/clusters")
async def list_clusters():
    payload = public_clusters()
    logger.info(
        "Elastic settings: listed %s cluster(s); default=%s",
        len(payload.get("clusters") or []),
        payload.get("default_cluster_id"),
    )
    return {"success": True, "skill_catalog": catalog_payload(), **payload}


@router.post("/clusters")
async def create_cluster(payload: ElasticClusterPayload):
    logger.info(
        "Elastic settings: Add cluster clicked name=%s url=%s verify_ssl=%s has_api_key=%s has_username=%s",
        payload.name,
        payload.base_url,
        payload.verify_ssl,
        bool(payload.api_key),
        bool(payload.username),
    )
    registry = load_registry()
    try:
        cluster = upsert_cluster(_payload_fields(payload))
    except ValueError as exc:
        logger.warning("Elastic settings: add cluster rejected: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if any(existing.id == cluster.id for existing in registry.clusters):
        from uuid import uuid4

        cluster.id = f"{cluster.id}-{uuid4().hex[:6]}"
    registry.clusters.append(cluster)
    if not registry.default_cluster_id:
        registry.default_cluster_id = cluster.id
    save_registry(registry)
    reload = _reload_mcp_clients()
    logger.info(
        "Elastic settings: Add cluster succeeded (%s) mcp_reload=%s",
        _safe_cluster_fields(cluster),
        reload.get("reloaded"),
    )
    return {"success": True, **public_clusters()}


@router.put("/clusters/{cluster_id}")
async def update_cluster(cluster_id: str, payload: ElasticClusterPayload):
    registry = load_registry()
    existing = next((item for item in registry.clusters if item.id == cluster_id), None)
    if not existing:
        logger.warning("Elastic settings: update cluster %s not found", cluster_id)
        raise HTTPException(status_code=404, detail="Cluster not found")
    data = _payload_fields(payload)
    data["id"] = cluster_id
    try:
        cluster = upsert_cluster(data, existing)
    except ValueError as exc:
        logger.warning("Elastic settings: update cluster %s rejected: %s", cluster_id, exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    cluster.id = cluster_id
    registry.clusters = [cluster if item.id == cluster_id else item for item in registry.clusters]
    save_registry(registry)
    reload = _reload_mcp_clients()
    logger.info(
        "Elastic settings: Update cluster succeeded (%s) mcp_reload=%s",
        _safe_cluster_fields(cluster),
        reload.get("reloaded"),
    )
    return {"success": True, **public_clusters()}


@router.delete("/clusters/{cluster_id}")
async def delete_cluster(cluster_id: str):
    registry = load_registry()
    remaining = [item for item in registry.clusters if item.id != cluster_id]
    if len(remaining) == len(registry.clusters):
        logger.warning("Elastic settings: delete cluster %s not found", cluster_id)
        raise HTTPException(status_code=404, detail="Cluster not found")
    registry.clusters = remaining
    if registry.default_cluster_id == cluster_id:
        registry.default_cluster_id = remaining[0].id if remaining else None
    save_registry(registry)
    reload = _reload_mcp_clients()
    logger.info(
        "Elastic settings: Delete cluster succeeded id=%s remaining=%s default=%s mcp_reload=%s",
        cluster_id,
        len(remaining),
        registry.default_cluster_id,
        reload.get("reloaded"),
    )
    return {"success": True, **public_clusters()}


@router.put("/default")
async def set_default_cluster(update: ElasticDefaultUpdate):
    registry = load_registry()
    if not any(item.id == update.cluster_id for item in registry.clusters):
        logger.warning("Elastic settings: set default cluster %s not found", update.cluster_id)
        raise HTTPException(status_code=404, detail="Cluster not found")
    previous = registry.default_cluster_id
    registry.default_cluster_id = update.cluster_id
    save_registry(registry)
    reload = _reload_mcp_clients()
    logger.info(
        "Elastic settings: Set default cluster %s (was %s) mcp_reload=%s",
        update.cluster_id,
        previous,
        reload.get("reloaded"),
    )
    return {"success": True, **public_clusters()}


@router.post("/test")
async def test_cluster(payload: ElasticClusterPayload):
    logger.info(
        "Elastic settings: Test connection clicked id=%s url=%s name=%s verify_ssl=%s has_api_key=%s has_username=%s",
        payload.id,
        payload.base_url,
        payload.name,
        payload.verify_ssl,
        bool(payload.api_key),
        bool(payload.username),
    )
    existing = get_cluster(payload.id) if payload.id else None
    try:
        cluster = upsert_cluster(_payload_fields(payload), existing)
    except ValueError as exc:
        logger.warning("Elastic settings: Test connection rejected: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("Elastic settings: Test connection probing (%s)", _safe_cluster_fields(cluster))
    result = probe_cluster(cluster)
    if result.get("ok"):
        logger.info(
            "Elastic settings: Test connection succeeded kind=%s message=%s details=%s",
            result.get("kind"),
            result.get("message"),
            result.get("details"),
        )
    else:
        logger.warning(
            "Elastic settings: Test connection failed url=%s message=%s error=%s attempts=%s",
            cluster.base_url,
            result.get("message"),
            result.get("error"),
            result.get("attempts"),
        )
    return {"success": result.get("ok"), **result}


@router.put("/default-skills")
async def set_default_skill_vector(payload: SkillVectorPayload):
    try:
        vector = canonicalize(payload.skill_vector, strict=True)
    except ValueError as exc:
        logger.warning("Elastic settings: default skill vector rejected: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    registry = load_registry()
    registry.default_skill_vector = vector
    save_registry(registry)
    logger.info("Elastic settings: Saved default MCP skill vector %s", vector)
    return {"success": True, **public_clusters()}


@router.put("/clusters/{cluster_id}/skills")
async def set_cluster_skill_vector(cluster_id: str, payload: SkillVectorPayload):
    try:
        vector = canonicalize(payload.skill_vector, strict=True)
    except ValueError as exc:
        logger.warning("Elastic settings: cluster %s skill vector rejected: %s", cluster_id, exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    registry = load_registry()
    cluster = next((item for item in registry.clusters if item.id == cluster_id), None)
    if not cluster:
        logger.warning("Elastic settings: skill vector cluster %s not found", cluster_id)
        raise HTTPException(status_code=404, detail="Cluster not found")
    cluster.skill_vector = vector
    save_registry(registry)
    logger.info("Elastic settings: Saved MCP skill vector for cluster %s %s", cluster_id, vector)
    return {"success": True, **public_clusters()}


@router.get("/recent-alerts")
async def recent_alerts(
    cluster_id: Optional[str] = None,
    limit: int = 10,
    hours_back: int = 24,
):
    """Return recent alerts for the New Session picker (UUID + short label).

    Prefers alerts above low severity (medium/high/critical). If none exist in
    the window, falls back to low-severity alerts.
    """
    limit = max(1, min(int(limit or 10), 25))
    hours_back = max(1, min(int(hours_back or 24), 168))
    # Fetch a wider pool so recent lows don't hide higher-severity alerts.
    pool_size = min(max(limit * 5, 50), 100)

    client = client_for_id(cluster_id)
    if client is None:
        return {
            "success": True,
            "alerts": [],
            "message": "No Elastic cluster configured",
        }

    try:
        alerts = client.get_security_alerts(
            hours_back=hours_back,
            max_alerts=pool_size,
            include_investigated=True,
        )
    except Exception as exc:
        logger.warning(
            "Elastic recent-alerts failed cluster_id=%s: %s",
            cluster_id,
            exc,
        )
        return {
            "success": False,
            "alerts": [],
            "error": str(exc),
        }

    above_low: list[dict] = []
    low_or_unknown: list[dict] = []
    for alert in alerts or []:
        if not isinstance(alert, dict):
            continue
        alert_id = str(alert.get("id") or "").strip()
        if not alert_id:
            continue
        title = (
            str(alert.get("title") or alert.get("rule_name") or "Untitled alert").strip()
            or "Untitled alert"
        )
        severity = str(alert.get("severity") or "").strip().lower() or "unknown"
        created_at = str(alert.get("created_at") or "").strip()
        item = {
            "id": alert_id,
            "title": title,
            "severity": severity,
            "status": str(alert.get("status") or "").strip() or "open",
            "created_at": created_at,
        }
        if severity in {"medium", "high", "critical"}:
            above_low.append(item)
        else:
            low_or_unknown.append(item)

    selected = above_low if above_low else low_or_unknown

    return {
        "success": True,
        "alerts": selected[:limit],
        "cluster_id": cluster_id,
        "hours_back": hours_back,
    }
