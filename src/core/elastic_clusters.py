"""
Elastic cluster registry.

`config.json` `elastic` may be either the legacy single-cluster object
(`base_url` + credentials) or a multi-cluster document:

    {
      "default_cluster_id": "lab-88",
      "default_skill_vector": "MSV:1/IRIS:Y/TH:Y/SIEM:Y/EDR:Y/CTI:Y/KB:Y/ENG:Y/RB:Y/AG:Y/RU:Y",
      "clusters": [
        {
          "id": "lab-88",
          "name": "Lab ELK",
          "base_url": "https://10.10.10.88:5601",
          "api_key": "...",
          "username": null,
          "password": null,
          "timeout_seconds": 30,
          "verify_ssl": false,
          "skill_vector": "MSV:1/IRIS:Y/TH:Y/SIEM:Y/EDR:Y/CTI:Y/KB:Y/ENG:Y/RB:Y/AG:Y/RU:Y"
        }
      ]
    }

Legacy documents are normalized in memory. The default cluster is also
mirrored onto the flat `base_url` / `api_key` fields so existing
`ElasticConfig` / `ElasticSIEMClient.from_config` callers keep working.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from uuid import uuid4

from .config import ElasticConfig
from .config_storage import get_section, load_raw_config, update_raw_section
from .errors import IntegrationError
from .logging import get_logger
from .secrets import mask_mapping, merge_secrets
from .skill_vector import DEFAULT_SKILL_VECTOR, canonicalize, summarize

logger = get_logger("sami.elastic.clusters")

_FLAT_KEYS = (
    "base_url",
    "api_key",
    "username",
    "password",
    "timeout_seconds",
    "verify_ssl",
)


@dataclass
class ElasticCluster:
    id: str
    name: str
    base_url: str
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    timeout_seconds: int = 30
    verify_ssl: bool = True
    skill_vector: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "base_url": self.base_url,
            "api_key": self.api_key or "",
            "username": self.username or "",
            "password": self.password or "",
            "timeout_seconds": int(self.timeout_seconds or 30),
            "verify_ssl": bool(self.verify_ssl),
            "skill_vector": self.skill_vector or DEFAULT_SKILL_VECTOR,
        }

    def auth_type(self) -> str:
        if self.api_key:
            return "api_key"
        if self.username and self.password:
            return "basic"
        return "none"

    def to_elastic_config(self) -> ElasticConfig:
        return ElasticConfig(
            base_url=self.base_url,
            api_key=self.api_key or None,
            username=self.username or None,
            password=self.password or None,
            timeout_seconds=int(self.timeout_seconds or 30),
            verify_ssl=bool(self.verify_ssl),
        )

    def public_dict(self) -> Dict[str, Any]:
        payload = mask_mapping(self.to_dict())
        payload["auth_type"] = self.auth_type()
        payload["has_credentials"] = self.auth_type() != "none"
        payload.update(summarize(self.skill_vector))
        return payload


@dataclass
class ElasticClusterRegistry:
    default_cluster_id: Optional[str] = None
    default_skill_vector: str = DEFAULT_SKILL_VECTOR
    clusters: List[ElasticCluster] = field(default_factory=list)

    def get(self, cluster_id: Optional[str]) -> Optional[ElasticCluster]:
        if cluster_id:
            for cluster in self.clusters:
                if cluster.id == cluster_id:
                    return cluster
        return self.default()

    def default(self) -> Optional[ElasticCluster]:
        if self.default_cluster_id:
            for cluster in self.clusters:
                if cluster.id == self.default_cluster_id:
                    return cluster
        return self.clusters[0] if self.clusters else None

    def to_section(self) -> Dict[str, Any]:
        clusters = [cluster.to_dict() for cluster in self.clusters]
        section: Dict[str, Any] = {
            "default_cluster_id": self.default_cluster_id,
            "default_skill_vector": self.default_skill_vector or DEFAULT_SKILL_VECTOR,
            "clusters": clusters,
        }
        default = self.default()
        if default:
            for key in _FLAT_KEYS:
                section[key] = default.to_dict().get(key)
        return section


def slugify_cluster_id(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return slug or f"cluster-{uuid4().hex[:8]}"


def _host_label(base_url: str) -> str:
    parsed = urlparse(base_url if "://" in (base_url or "") else f"https://{base_url}")
    host = parsed.hostname or (base_url or "").strip().rstrip("/")
    return host or "Elastic"


def _normalize_cluster(raw: Dict[str, Any]) -> ElasticCluster:
    base_url = str(raw.get("base_url") or "").strip()
    name = str(raw.get("name") or "").strip() or _host_label(base_url)
    cluster_id = str(raw.get("id") or "").strip() or slugify_cluster_id(name)
    timeout = raw.get("timeout_seconds", 30)
    try:
        timeout_seconds = int(timeout)
    except (TypeError, ValueError):
        timeout_seconds = 30
    api_key = raw.get("api_key") or None
    username = raw.get("username") or None
    password = raw.get("password") or None
    if isinstance(api_key, str):
        api_key = api_key.strip() or None
    if isinstance(username, str):
        username = username.strip() or None
    if isinstance(password, str):
        password = password.strip() or None
    skill_vector = str(raw.get("skill_vector") or "").strip()
    return ElasticCluster(
        id=cluster_id,
        name=name,
        base_url=base_url.rstrip("/") if base_url else "",
        api_key=api_key,
        username=username,
        password=password,
        timeout_seconds=timeout_seconds,
        verify_ssl=bool(raw.get("verify_ssl", True)),
        skill_vector=skill_vector,
    )


def normalize_elastic_section(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a multi-cluster elastic section, accepting the legacy shape."""
    raw = dict(raw or {})
    clusters: List[ElasticCluster] = []
    seen_ids = set()

    listed = raw.get("clusters")
    if isinstance(listed, list) and listed:
        for item in listed:
            if not isinstance(item, dict) or not str(item.get("base_url") or "").strip():
                continue
            cluster = _normalize_cluster(item)
            if cluster.id in seen_ids:
                cluster.id = f"{cluster.id}-{uuid4().hex[:6]}"
            seen_ids.add(cluster.id)
            clusters.append(cluster)
    elif str(raw.get("base_url") or "").strip():
        clusters.append(_normalize_cluster(raw))

    default_id = raw.get("default_cluster_id")
    if not default_id or not any(cluster.id == default_id for cluster in clusters):
        default_id = clusters[0].id if clusters else None

    default_skill_vector = canonicalize(
        raw.get("default_skill_vector"),
        strict=False,
        fallback=DEFAULT_SKILL_VECTOR,
    )
    for cluster in clusters:
        if cluster.skill_vector:
            cluster.skill_vector = canonicalize(
                cluster.skill_vector,
                strict=False,
                fallback=default_skill_vector,
            )
        else:
            cluster.skill_vector = default_skill_vector

    return ElasticClusterRegistry(
        default_cluster_id=default_id,
        default_skill_vector=default_skill_vector,
        clusters=clusters,
    ).to_section()


def elastic_config_from_section(section: Optional[Dict[str, Any]]) -> Optional[ElasticConfig]:
    registry = registry_from_section(section)
    default = registry.default()
    return default.to_elastic_config() if default else None


def registry_from_section(section: Optional[Dict[str, Any]]) -> ElasticClusterRegistry:
    normalized = normalize_elastic_section(section)
    clusters = [_normalize_cluster(item) for item in normalized.get("clusters") or []]
    return ElasticClusterRegistry(
        default_cluster_id=normalized.get("default_cluster_id"),
        default_skill_vector=normalized.get("default_skill_vector") or DEFAULT_SKILL_VECTOR,
        clusters=clusters,
    )


def load_registry(config_path: Optional[str] = None) -> ElasticClusterRegistry:
    raw = load_raw_config(config_path) if config_path else get_section("elastic", {})
    if config_path:
        raw = (raw or {}).get("elastic", {})
    return registry_from_section(raw if isinstance(raw, dict) else {})


def save_registry(registry: ElasticClusterRegistry, config_path: Optional[str] = None) -> ElasticClusterRegistry:
    update_raw_section("elastic", registry.to_section(), config_path=config_path)
    return registry


def get_cluster(cluster_id: Optional[str] = None) -> Optional[ElasticCluster]:
    return load_registry().get(cluster_id)


def cluster_summary(cluster_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    cluster = get_cluster(cluster_id)
    if not cluster:
        return None
    return {
        "id": cluster.id,
        "name": cluster.name,
        "base_url": cluster.base_url,
        "auth_type": cluster.auth_type(),
    }


def public_clusters() -> Dict[str, Any]:
    """Masked cluster list for Settings and session pickers."""
    registry = load_registry()
    return {
        "default_cluster_id": registry.default_cluster_id,
        "default_skill_vector": registry.default_skill_vector or DEFAULT_SKILL_VECTOR,
        "clusters": [cluster.public_dict() for cluster in registry.clusters],
    }


def current_default_skill_vector() -> str:
    raw = get_section("elastic", {})
    return canonicalize(raw.get("default_skill_vector"), strict=False, fallback=DEFAULT_SKILL_VECTOR)


def skill_vector_for_cluster(cluster_id: Optional[str] = None) -> str:
    registry = load_registry()
    cluster = registry.get(cluster_id)
    raw = (cluster.skill_vector if cluster else None) or registry.default_skill_vector
    return canonicalize(raw, strict=False, fallback=DEFAULT_SKILL_VECTOR)


def client_for_cluster(cluster: ElasticCluster):
    from ..integrations.siem.elastic.elastic_client import ElasticSIEMClient

    return ElasticSIEMClient.from_settings(
        base_url=cluster.base_url,
        api_key=cluster.api_key,
        username=cluster.username,
        password=cluster.password,
        timeout_seconds=cluster.timeout_seconds,
        verify_ssl=cluster.verify_ssl,
    )


def client_for_id(cluster_id: Optional[str] = None):
    cluster = get_cluster(cluster_id)
    if not cluster:
        return None
    return client_for_cluster(cluster)


def upsert_cluster(payload: Dict[str, Any], existing: Optional[ElasticCluster] = None) -> ElasticCluster:
    merged = merge_secrets(payload, existing.to_dict() if existing else {})
    if not str(merged.get("base_url") or "").strip():
        raise ValueError("Cluster URL is required")
    if existing:
        merged.setdefault("id", existing.id)
        merged.setdefault("name", existing.name)
    if not str(merged.get("skill_vector") or "").strip():
        merged["skill_vector"] = (
            existing.skill_vector if existing and existing.skill_vector else current_default_skill_vector()
        )
    merged["skill_vector"] = canonicalize(merged.get("skill_vector"), strict=True)
    cluster = _normalize_cluster(merged)
    if not cluster.api_key and not (cluster.username and cluster.password):
        raise ValueError("Provide an API key, or a username and password")
    return cluster


def probe_cluster(cluster: ElasticCluster) -> Dict[str, Any]:
    """
    Lightweight connectivity check. Tries Elasticsearch then Kibana endpoints.
    Does not log credentials.
    """
    from ..integrations.siem.elastic.elastic_http import ElasticHttpClient

    http = ElasticHttpClient(
        base_url=cluster.base_url,
        api_key=cluster.api_key,
        username=cluster.username,
        password=cluster.password,
        timeout_seconds=min(int(cluster.timeout_seconds or 30), 15),
        verify_ssl=cluster.verify_ssl,
    )
    errors: List[str] = []
    for endpoint, kind in (("_cluster/health", "elasticsearch"), ("api/status", "kibana"), ("", "http")):
        try:
            body = http.request("GET", endpoint)
            return {
                "ok": True,
                "kind": kind,
                "message": _probe_message(kind, cluster.base_url, body),
                "details": _probe_details(kind, body),
            }
        except Exception as exc:
            errors.append(f"{kind}: {exc}")
    return {
        "ok": False,
        "kind": "unknown",
        "message": f"Could not reach {cluster.base_url}",
        "error": errors[-1] if errors else "No response",
        "attempts": errors,
    }


def _probe_message(kind: str, base_url: str, body: Any) -> str:
    if kind == "elasticsearch":
        status = body.get("status") if isinstance(body, dict) else None
        cluster_name = body.get("cluster_name") if isinstance(body, dict) else None
        extra = f" ({cluster_name}, {status})" if cluster_name else ""
        return f"Reached Elasticsearch at {base_url}{extra}."
    if kind == "kibana":
        name = None
        if isinstance(body, dict):
            name = (body.get("name") or (body.get("status") or {}).get("overall", {}).get("level"))
        extra = f" ({name})" if name else ""
        return (
            f"Reached Kibana at {base_url}{extra}. "
            "SIEM search tools use the Elasticsearch API; add a cluster with the ES URL (usually port 9200) if queries fail."
        )
    return f"Reached {base_url}."


def _probe_details(kind: str, body: Any) -> Dict[str, Any]:
    if not isinstance(body, dict):
        return {"kind": kind}
    if kind == "elasticsearch":
        return {
            "kind": kind,
            "cluster_name": body.get("cluster_name"),
            "status": body.get("status"),
        }
    if kind == "kibana":
        overall = (body.get("status") or {}).get("overall") if isinstance(body.get("status"), dict) else None
        return {
            "kind": kind,
            "name": body.get("name"),
            "level": (overall or {}).get("level") if isinstance(overall, dict) else None,
        }
    return {"kind": kind}
