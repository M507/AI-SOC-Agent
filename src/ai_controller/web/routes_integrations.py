"""Unified integration inventory and connection tests for Settings."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ...core.config_storage import get_section, load_config_from_file, load_raw_config
from ...core.elastic_clusters import get_cluster, load_registry, probe_cluster
from ...core.logging import get_logger
from ...llm.registry import create_provider
from ...mcp.supervisor import get_supervisor
from .integration_skill_tests import (
    run_skill_tests,
    skill_inventory,
    skills_for_integration,
)

logger = get_logger("sami.web.integrations")

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


@dataclass(frozen=True)
class IntegrationCard:
    id: str
    name: str
    category: str
    description: str
    detail: str
    configured: bool

    def public_dict(self) -> Dict[str, Any]:
        skill_count = len(skills_for_integration(self.id))
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "detail": self.detail,
            "configured": self.configured,
            "testable": True,
            "has_skill_tests": skill_count > 0,
            "skill_count": skill_count,
        }


class SkillTestRequest(BaseModel):
    skills: list[str] | None = None


SkillTestRequest.model_rebuild()


def _is_configured(*values: Any) -> bool:
    """Reject empty/example values while never returning their contents."""
    for value in values:
        text = str(value or "").strip().lower()
        if not text:
            return False
        if (
            "example.com" in text
            or text.startswith("your-")
            or "not-real" in text
            or text in {"changeme", "change-me", "placeholder"}
        ):
            return False
    return True


def _host(url: Any) -> str:
    text = str(url or "").strip()
    if not text:
        return "No endpoint configured"
    parsed = urlparse(text if "://" in text else f"https://{text}")
    return parsed.netloc or parsed.path


def _cards() -> List[IntegrationCard]:
    raw = load_raw_config()
    cards: List[IntegrationCard] = []

    thehive = raw.get("thehive") if isinstance(raw.get("thehive"), dict) else {}
    cards.append(
        IntegrationCard(
            "thehive",
            "TheHive",
            "Case management",
            "Cases, observables, comments, and incident workflows.",
            _host(thehive.get("base_url")),
            _is_configured(thehive.get("base_url"), thehive.get("api_key")),
        )
    )

    iris = raw.get("iris") if isinstance(raw.get("iris"), dict) else {}
    cards.append(
        IntegrationCard(
            "iris",
            "DFIR-IRIS",
            "Case management",
            "Incident response cases, evidence, notes, and activities.",
            _host(iris.get("base_url")),
            _is_configured(iris.get("base_url"), iris.get("api_key")),
        )
    )

    registry = load_registry()
    if registry.clusters:
        for cluster in registry.clusters:
            cards.append(
                IntegrationCard(
                    f"elastic:{cluster.id}",
                    cluster.name,
                    "Elastic",
                    "Elasticsearch or Kibana connection used by SIEM tools.",
                    f"{_host(cluster.base_url)} · {cluster.auth_type()}",
                    bool(cluster.base_url and cluster.auth_type() != "none"),
                )
            )
    else:
        cards.append(
            IntegrationCard(
                "elastic",
                "Elastic",
                "SIEM",
                "Security alerts, event search, and cluster data.",
                "No clusters configured",
                False,
            )
        )

    edr = raw.get("edr") if isinstance(raw.get("edr"), dict) else {}
    edr_type = str(edr.get("edr_type") or "EDR").replace("_", " ").title()
    cards.append(
        IntegrationCard(
            "edr",
            edr_type,
            "Endpoint security",
            "Endpoint detections and response actions.",
            _host(edr.get("base_url")),
            _is_configured(edr.get("base_url"), edr.get("api_key")),
        )
    )

    for section, default_name in (("cti", "Threat intelligence"), ("cti_opencti", "OpenCTI")):
        cti = raw.get(section) if isinstance(raw.get(section), dict) else {}
        cti_type = str(cti.get("cti_type") or default_name).replace("_", " ").title()
        needs_key = str(cti.get("cti_type") or "").lower() == "opencti" or section == "cti_opencti"
        configured = _is_configured(cti.get("base_url"))
        if needs_key:
            configured = configured and _is_configured(cti.get("api_key"))
        cards.append(
            IntegrationCard(
                section,
                cti_type,
                "Threat intelligence",
                "Indicator enrichment and threat context.",
                _host(cti.get("base_url")),
                configured,
            )
        )

    eng = raw.get("eng") if isinstance(raw.get("eng"), dict) else {}
    provider = str(eng.get("provider") or "trello").lower()
    provider_cfg = eng.get(provider) if isinstance(eng.get(provider), dict) else {}
    credential_key = "api_token" if provider in {"clickup", "github"} else "api_key"
    cards.append(
        IntegrationCard(
            "engineering",
            provider.title(),
            "Engineering",
            "Engineering tasks and improvement recommendations.",
            f"Active provider · {provider.title()}",
            _is_configured(provider_cfg.get(credential_key)),
        )
    )

    llm = raw.get("llm") if isinstance(raw.get("llm"), dict) else {}
    llm_provider = str(llm.get("provider") or "cursor_agent")
    llm_cfg = llm.get(llm_provider) if isinstance(llm.get(llm_provider), dict) else {}
    llm_configured = llm_provider == "cursor_agent" or _is_configured(
        llm_cfg.get("base_url"), llm_cfg.get("model")
    )
    cards.append(
        IntegrationCard(
            "llm",
            llm_provider.replace("_", " ").title(),
            "AI provider",
            "Language model used for investigations and tool orchestration.",
            str(llm_cfg.get("model") or "Active provider"),
            llm_configured,
        )
    )

    mcp = raw.get("mcp") if isinstance(raw.get("mcp"), dict) else {}
    enabled = bool(mcp.get("enabled", True))
    cards.append(
        IntegrationCard(
            "mcp",
            "MCP server",
            "Agent tools",
            "Tool gateway used by agents and external MCP clients.",
            f"{mcp.get('host', '127.0.0.1')}:{mcp.get('port', 8082)}",
            enabled,
        )
    )
    return cards


def _result(ok: bool, message: str, *, level: str | None = None, details: Dict[str, Any] | None = None):
    return {
        "success": ok,
        "ok": ok,
        "level": level or ("success" if ok else "error"),
        "message": message,
        "details": details or {},
    }


def _card(card_id: str) -> IntegrationCard:
    card = next((item for item in _cards() if item.id == card_id), None)
    if not card:
        raise HTTPException(status_code=404, detail="Unknown integration")
    if not card.configured:
        raise HTTPException(status_code=400, detail=f"{card.name} is not configured")
    return card


def _reachable_http(
    section: Dict[str, Any],
    *,
    endpoint: str = "",
    authorization: str | None = None,
) -> Dict[str, Any]:
    base_url = str(section.get("base_url") or "").rstrip("/")
    headers = {"Accept": "application/json"}
    if authorization:
        headers["Authorization"] = authorization
    response = requests.get(
        f"{base_url}/{endpoint.lstrip('/')}" if endpoint else base_url,
        headers=headers,
        timeout=min(int(section.get("timeout_seconds") or 30), 15),
        verify=bool(section.get("verify_ssl", True)),
    )
    if response.status_code in {401, 403}:
        return _result(False, f"Reached {_host(base_url)}, but authentication was rejected.")
    if response.status_code >= 500:
        return _result(False, f"{_host(base_url)} returned HTTP {response.status_code}.")
    return _result(
        True,
        f"Reached {_host(base_url)} (HTTP {response.status_code}).",
        level="success" if response.status_code < 400 else "warning",
        details={"status_code": response.status_code},
    )


async def _test_integration(card_id: str) -> Dict[str, Any]:
    raw = load_raw_config()

    if card_id == "thehive":
        from ...integrations.case_management.thehive.thehive_client import TheHiveCaseManagementClient

        ok = await asyncio.to_thread(TheHiveCaseManagementClient.from_config(load_config_from_file()).ping)
        return _result(ok, "TheHive health check passed." if ok else "TheHive health check failed.")

    if card_id == "iris":
        from ...integrations.case_management.iris.iris_client import IRISCaseManagementClient

        ok = await asyncio.to_thread(IRISCaseManagementClient.from_config(load_config_from_file()).ping)
        return _result(ok, "DFIR-IRIS ping passed." if ok else "DFIR-IRIS ping failed.")

    if card_id.startswith("elastic:"):
        cluster_id = card_id.split(":", 1)[1]
        cluster = get_cluster(cluster_id)
        if not cluster:
            raise HTTPException(status_code=404, detail="Elastic cluster not found")
        probe = await asyncio.to_thread(probe_cluster, cluster)
        return {"success": bool(probe.get("ok")), **probe}

    if card_id == "elastic":
        raise HTTPException(status_code=400, detail="Configure an Elastic cluster first")

    if card_id == "edr":
        edr = raw.get("edr") if isinstance(raw.get("edr"), dict) else {}
        token = str(edr.get("api_key") or "")
        auth = f"ApiKey {token.removeprefix('ApiKey ')}" if token else None
        endpoint = "api/fleet/agents?perPage=1" if edr.get("edr_type") == "elastic_defend" else ""
        result = await asyncio.to_thread(_reachable_http, edr, endpoint=endpoint, authorization=auth)
        if edr.get("edr_type") != "elastic_defend" and result["ok"]:
            result["level"] = "warning"
            result["message"] += " Service reachability passed; provider API authentication is not validated."
        return result

    if card_id in {"cti", "cti_opencti"}:
        cti = raw.get(card_id) if isinstance(raw.get(card_id), dict) else {}
        token = str(cti.get("api_key") or "")
        auth = f"Bearer {token}" if token else None
        is_local_tip = str(cti.get("cti_type") or "").lower() == "local_tip"
        endpoint = "hashes/recents?limit=1" if is_local_tip else ""
        result = await asyncio.to_thread(
            _reachable_http,
            cti,
            endpoint=endpoint,
            authorization=auth,
        )
        if result["ok"]:
            if is_local_tip:
                result["message"] = f"Local TIP API is reachable at {_host(cti.get('base_url'))}; safe hash reads work."
            else:
                result["level"] = "warning"
                result["message"] += " Service reachability passed; run an indicator lookup to validate the full workflow."
        return result

    if card_id == "engineering":
        config = load_config_from_file()
        provider = str((raw.get("eng") or {}).get("provider") or "trello").lower()
        if provider == "trello":
            from ...integrations.eng.trello.trello_client import TrelloClient

            client = TrelloClient.from_config(config)
        elif provider == "clickup":
            from ...integrations.eng.clickup.clickup_client import ClickUpClient

            client = ClickUpClient.from_config(config)
        elif provider == "github":
            from ...integrations.eng.github.github_client import GitHubClient

            client = GitHubClient.from_config(config)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported engineering provider: {provider}")
        ok = await asyncio.to_thread(client.ping)
        return _result(ok, f"{provider.title()} connection passed." if ok else f"{provider.title()} connection failed.")

    if card_id == "llm":
        llm = get_section("llm", {})
        provider_id = str(llm.get("provider") or "cursor_agent")
        settings = llm.get(provider_id) if isinstance(llm.get(provider_id), dict) else {}
        health = await create_provider(provider_id, settings).health_check()
        payload = health.to_dict()
        ok = bool(payload.get("ok", payload.get("success", False)))
        return _result(ok, payload.get("message") or f"{provider_id} health check {'passed' if ok else 'failed'}.")

    if card_id == "mcp":
        status = get_supervisor().status()
        running = bool(status.get("running"))
        return _result(
            running,
            "MCP server is running." if running else "MCP server is not running.",
            details={
                "running": running,
                "host": status.get("host"),
                "port": status.get("port"),
                "tool_count": status.get("tool_count"),
            },
        )

    raise HTTPException(status_code=404, detail="Unknown integration")


@router.get("")
async def list_integrations():
    cards = [card.public_dict() for card in _cards()]
    logger.info("Integration settings: listed %s integration(s)", len(cards))
    return {"success": True, "integrations": cards}


@router.post("/{integration_id}/test")
async def test_integration(integration_id: str):
    card = _card(integration_id)
    logger.info("Integration settings: Test clicked id=%s name=%s", card.id, card.name)
    try:
        result = await _test_integration(integration_id)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Integration settings: Test failed id=%s error=%s", card.id, exc)
        return _result(False, f"{card.name} test failed: {exc}")
    logger.info(
        "Integration settings: Test completed id=%s ok=%s message=%s",
        card.id,
        result.get("ok"),
        result.get("message"),
    )
    return result


@router.get("/{integration_id}/skills")
async def list_integration_skills(integration_id: str):
    card = _card(integration_id)
    skills = skill_inventory(integration_id)
    logger.info(
        "Integration settings: listed %s skill test(s) id=%s",
        len(skills),
        integration_id,
    )
    return {
        "success": True,
        "integration_id": integration_id,
        "integration_name": card.name,
        "skills": skills,
    }


@router.post("/{integration_id}/skills/test")
async def test_integration_skills(integration_id: str, request: SkillTestRequest):
    card = _card(integration_id)
    if not skills_for_integration(integration_id):
        raise HTTPException(status_code=400, detail=f"{card.name} does not expose MCP skills")
    logger.info(
        "Integration settings: Skill test clicked id=%s selected=%s",
        integration_id,
        request.skills or "all-safe",
    )
    try:
        result = await run_skill_tests(integration_id, request.skills)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Integration settings: skill test suite failed id=%s", integration_id)
        raise HTTPException(status_code=500, detail=f"Could not run skill tests: {exc}") from exc
    logger.info(
        "Integration settings: Skill test completed id=%s counts=%s",
        integration_id,
        result.get("counts"),
    )
    return result
