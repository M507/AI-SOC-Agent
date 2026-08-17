"""Elastic cluster settings API."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ...core.elastic_clusters import (
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
    timeout_seconds: Optional[int] = Field(default=30, ge=5, le=120)
    verify_ssl: Optional[bool] = True
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


@router.get("/clusters")
async def list_clusters():
    return {"success": True, "skill_catalog": catalog_payload(), **public_clusters()}


@router.post("/clusters")
async def create_cluster(payload: ElasticClusterPayload):
    registry = load_registry()
    try:
        cluster = upsert_cluster(payload.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if any(existing.id == cluster.id for existing in registry.clusters):
        from uuid import uuid4

        cluster.id = f"{cluster.id}-{uuid4().hex[:6]}"
    registry.clusters.append(cluster)
    if not registry.default_cluster_id:
        registry.default_cluster_id = cluster.id
    save_registry(registry)
    _reload_mcp_clients()
    logger.info("Added Elastic cluster %s (%s)", cluster.id, cluster.name)
    return {"success": True, **public_clusters()}


@router.put("/clusters/{cluster_id}")
async def update_cluster(cluster_id: str, payload: ElasticClusterPayload):
    registry = load_registry()
    existing = next((item for item in registry.clusters if item.id == cluster_id), None)
    if not existing:
        raise HTTPException(status_code=404, detail="Cluster not found")
    data = payload.model_dump(exclude_none=True)
    data["id"] = cluster_id
    try:
        cluster = upsert_cluster(data, existing)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    cluster.id = cluster_id
    registry.clusters = [cluster if item.id == cluster_id else item for item in registry.clusters]
    save_registry(registry)
    _reload_mcp_clients()
    return {"success": True, **public_clusters()}


@router.delete("/clusters/{cluster_id}")
async def delete_cluster(cluster_id: str):
    registry = load_registry()
    remaining = [item for item in registry.clusters if item.id != cluster_id]
    if len(remaining) == len(registry.clusters):
        raise HTTPException(status_code=404, detail="Cluster not found")
    registry.clusters = remaining
    if registry.default_cluster_id == cluster_id:
        registry.default_cluster_id = remaining[0].id if remaining else None
    save_registry(registry)
    _reload_mcp_clients()
    logger.info("Deleted Elastic cluster %s", cluster_id)
    return {"success": True, **public_clusters()}


@router.put("/default")
async def set_default_cluster(update: ElasticDefaultUpdate):
    registry = load_registry()
    if not any(item.id == update.cluster_id for item in registry.clusters):
        raise HTTPException(status_code=404, detail="Cluster not found")
    registry.default_cluster_id = update.cluster_id
    save_registry(registry)
    _reload_mcp_clients()
    return {"success": True, **public_clusters()}


@router.post("/test")
async def test_cluster(payload: ElasticClusterPayload):
    existing = get_cluster(payload.id) if payload.id else None
    try:
        cluster = upsert_cluster(payload.model_dump(exclude_none=True), existing)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = probe_cluster(cluster)
    return {"success": result.get("ok"), **result}


@router.put("/default-skills")
async def set_default_skill_vector(payload: SkillVectorPayload):
    try:
        vector = canonicalize(payload.skill_vector, strict=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    registry = load_registry()
    registry.default_skill_vector = vector
    save_registry(registry)
    logger.info("Updated default MCP skill vector")
    return {"success": True, **public_clusters()}


@router.put("/clusters/{cluster_id}/skills")
async def set_cluster_skill_vector(cluster_id: str, payload: SkillVectorPayload):
    try:
        vector = canonicalize(payload.skill_vector, strict=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    registry = load_registry()
    cluster = next((item for item in registry.clusters if item.id == cluster_id), None)
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")
    cluster.skill_vector = vector
    save_registry(registry)
    logger.info("Updated MCP skill vector for cluster %s", cluster_id)
    return {"success": True, **public_clusters()}
