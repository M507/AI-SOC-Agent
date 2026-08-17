"""
Build a configured SamiGPTMCPServer from SamiConfig / config.json.

Shared by the stdio MCP entry point and the HTTP MCP supervisor so both
transports expose the same tools and integrations.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from ..core.config import CTIConfig, LoggingConfig, SamiConfig
from ..core.config_storage import _dict_to_config
from ..core.logging import get_logger
from ..integrations.case_management.iris.iris_client import IRISCaseManagementClient
from ..integrations.case_management.thehive.thehive_client import TheHiveCaseManagementClient
from ..integrations.cti.local_tip.local_tip_client import LocalTipCTIClient
from ..integrations.cti.opencti.opencti_client import OpenCTIClient
from ..integrations.edr.elastic_defend.elastic_defend_client import ElasticDefendEDRClient
from ..integrations.eng.clickup.clickup_client import ClickUpClient
from ..integrations.eng.github.github_client import GitHubClient
from ..integrations.eng.trello.trello_client import TrelloClient
from ..integrations.siem.elastic.elastic_client import ElasticSIEMClient
from .mcp_server import SamiGPTMCPServer

logger = get_logger(__name__)


@dataclass
class MCPBuildResult:
    """Configured MCP server plus a summary of which integrations bound."""

    server: SamiGPTMCPServer
    integrations: Dict[str, Any]


def project_root() -> Path:
    """Return the repository root (parent of `src/`)."""
    return Path(__file__).resolve().parent.parent.parent


def load_runtime_config() -> SamiConfig:
    """Load config.json from the project root, falling back to empty defaults."""
    config_file = project_root() / "config.json"
    try:
        if config_file.exists():
            with open(config_file, "r") as f:
                data = json.load(f)
            config = _dict_to_config(data)
            logger.info("Configuration loaded from %s", config_file)
            return config
        logger.warning("config.json not found at %s, using defaults", config_file)
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in %s: %s", config_file, e, exc_info=True)
    except Exception as e:
        logger.error("Failed to load %s: %s", config_file, e, exc_info=True)

    return SamiConfig(logging=LoggingConfig())


def _load_raw_config_dict() -> Dict[str, Any]:
    config_file = os.getenv("SAMIGPT_CONFIG_FILE", str(project_root() / "config.json"))
    try:
        if os.path.exists(config_file):
            with open(config_file, "r") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _init_case_client(config: SamiConfig, mcp_logger: logging.Logger):
    if config.iris:
        try:
            client = IRISCaseManagementClient.from_config(config)
            mcp_logger.info("IRIS case management client initialized")
            return client
        except Exception as e:
            mcp_logger.error("Failed to initialize IRIS client: %s", e, exc_info=True)
            return None
    if config.thehive:
        try:
            client = TheHiveCaseManagementClient.from_config(config)
            mcp_logger.info("TheHive case management client initialized")
            return client
        except Exception as e:
            mcp_logger.error("Failed to initialize TheHive client: %s", e, exc_info=True)
            return None
    mcp_logger.warning("No case management system configured")
    return None


def _init_siem_clients(config: SamiConfig, mcp_logger: logging.Logger):
    """
    Build SIEM clients for every configured Elastic cluster.

    Returns (clients_by_id, default_cluster_id, default_client).
    """
    from ..core.elastic_clusters import load_registry, client_for_cluster

    registry = load_registry()
    clients = {}
    for cluster in registry.clusters:
        try:
            clients[cluster.id] = client_for_cluster(cluster)
            mcp_logger.info("Elastic SIEM client initialized for cluster %s (%s)", cluster.id, cluster.name)
        except Exception as e:
            mcp_logger.error(
                "Failed to initialize Elastic SIEM client for cluster %s: %s",
                cluster.id,
                e,
                exc_info=True,
            )
    default_id = registry.default_cluster_id
    default_client = clients.get(default_id) if default_id else None
    if default_client is None and clients:
        default_client = next(iter(clients.values()))
        default_id = next(iter(clients))
    if not clients and config.elastic:
        try:
            default_client = ElasticSIEMClient.from_config(config)
            mcp_logger.info("Elastic SIEM client initialized from legacy config")
        except Exception as e:
            mcp_logger.error("Failed to initialize Elastic SIEM client: %s", e, exc_info=True)
    return clients, default_id, default_client


def _init_edr_client(config: SamiConfig, mcp_logger: logging.Logger):
    if not config.edr:
        return None
    if config.edr.edr_type != "elastic_defend":
        mcp_logger.warning(
            "EDR type '%s' is not implemented. Only 'elastic_defend' is supported.",
            config.edr.edr_type,
        )
        return None
    try:
        client = ElasticDefendEDRClient.from_config(config)
        mcp_logger.info("Elastic Defend EDR client initialized")
        return client
    except Exception as e:
        mcp_logger.error("Failed to initialize Elastic Defend EDR client: %s", e, exc_info=True)
        return None


def _init_cti_clients(config: SamiConfig, mcp_logger: logging.Logger):
    cti_clients = []
    if config.cti:
        if config.cti.cti_type == "local_tip":
            try:
                cti_clients.append(LocalTipCTIClient.from_config(config))
                mcp_logger.info("Local TIP CTI client initialized")
            except Exception as e:
                mcp_logger.error("Failed to initialize Local TIP CTI client: %s", e, exc_info=True)
        elif config.cti.cti_type == "opencti":
            try:
                cti_clients.append(OpenCTIClient.from_config(config))
                mcp_logger.info("OpenCTI client initialized")
            except Exception as e:
                mcp_logger.error("Failed to initialize OpenCTI client: %s", e, exc_info=True)
        else:
            mcp_logger.warning(
                "CTI type '%s' is not implemented. Supported: local_tip, opencti.",
                config.cti.cti_type,
            )

    raw = _load_raw_config_dict()
    extra_opencti = raw.get("cti_opencti") or {}
    if extra_opencti.get("cti_type") == "opencti" and extra_opencti.get("base_url"):
        if not any("OpenCTI" in c.__class__.__name__ for c in cti_clients):
            try:
                opencti_cfg = CTIConfig(
                    cti_type="opencti",
                    base_url=extra_opencti.get("base_url"),
                    api_key=extra_opencti.get("api_key"),
                    timeout_seconds=extra_opencti.get("timeout_seconds", 30),
                    verify_ssl=extra_opencti.get("verify_ssl", True),
                )
                cti_clients.append(OpenCTIClient.from_config(SamiConfig(cti=opencti_cfg)))
                mcp_logger.info("Additional OpenCTI client initialized")
            except Exception as e:
                mcp_logger.error("Failed to initialize additional OpenCTI client: %s", e, exc_info=True)

    extra_local = raw.get("cti_local_tip") or {}
    if extra_local.get("cti_type") == "local_tip" and extra_local.get("base_url"):
        if not any("LocalTip" in c.__class__.__name__ for c in cti_clients):
            try:
                local_cfg = CTIConfig(
                    cti_type="local_tip",
                    base_url=extra_local.get("base_url"),
                    api_key=extra_local.get("api_key"),
                    timeout_seconds=extra_local.get("timeout_seconds", 30),
                    verify_ssl=extra_local.get("verify_ssl", False),
                )
                cti_clients.append(LocalTipCTIClient.from_config(SamiConfig(cti=local_cfg)))
                mcp_logger.info("Additional Local TIP client initialized")
            except Exception as e:
                mcp_logger.error("Failed to initialize additional Local TIP client: %s", e, exc_info=True)

    return cti_clients


def _init_eng_client(config: SamiConfig, mcp_logger: logging.Logger):
    if not config.eng:
        return None

    provider = (config.eng.provider or "trello").lower()
    attempts = []
    if provider == "github" and config.eng.github:
        attempts.append(("GitHub", GitHubClient))
    elif provider == "clickup" and config.eng.clickup:
        attempts.append(("ClickUp", ClickUpClient))
    elif provider == "trello" and config.eng.trello:
        attempts.append(("Trello", TrelloClient))
    else:
        if config.eng.github:
            attempts.append(("GitHub", GitHubClient))
        if config.eng.clickup:
            attempts.append(("ClickUp", ClickUpClient))
        if config.eng.trello:
            attempts.append(("Trello", TrelloClient))

    for name, cls in attempts:
        try:
            client = cls.from_config(config)
            mcp_logger.info("%s engineering client initialized", name)
            return client
        except Exception as e:
            mcp_logger.warning("Failed to initialize %s client: %s", name, e)
    return None


def build_mcp_server(config: Optional[SamiConfig] = None) -> MCPBuildResult:
    """
    Construct a SamiGPTMCPServer with whatever integrations are configured.

    Missing or broken integrations are skipped so the server still starts.
    """
    config = config or load_runtime_config()
    mcp_logger = logging.getLogger("sami.mcp")

    case_client = _init_case_client(config, mcp_logger)
    siem_clients, default_cluster_id, siem_client = _init_siem_clients(config, mcp_logger)
    edr_client = _init_edr_client(config, mcp_logger)
    cti_clients = _init_cti_clients(config, mcp_logger)
    eng_client = _init_eng_client(config, mcp_logger)

    server = SamiGPTMCPServer(
        case_client=case_client,
        siem_client=siem_client,
        siem_clients=siem_clients,
        default_cluster_id=default_cluster_id,
        edr_client=edr_client,
        cti_client=cti_clients[0] if cti_clients else None,
        cti_clients=cti_clients or None,
        eng_client=eng_client,
    )

    integrations = {
        "case_management": case_client is not None,
        "siem": siem_client is not None,
        "edr": edr_client is not None,
        "cti": bool(cti_clients),
        "eng": eng_client is not None,
        "tools_count": len(server.tools),
    }
    mcp_logger.info(
        "MCP server built with %s tools (case=%s siem=%s edr=%s cti=%s eng=%s)",
        integrations["tools_count"],
        integrations["case_management"],
        integrations["siem"],
        integrations["edr"],
        integrations["cti"],
        integrations["eng"],
    )
    return MCPBuildResult(server=server, integrations=integrations)
