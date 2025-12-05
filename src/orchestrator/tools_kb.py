"""
LLM-callable tools for client infrastructure knowledge base (KB) operations.

These functions wrap the KBClient interface and provide LLM-friendly error
handling and return values, reading from ``client_env/*`` on the filesystem.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..api.kb import KBClient
from ..core.errors import IntegrationError


def list_kb_clients(
    client: KBClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    List available client environments.

    Tool schema:
    - name: kb_list_clients
    - description: List available client environments based on folders under client_env/*.
    - parameters: none

    Args:
        client: The KB client.

    Returns:
        Dictionary containing list of clients.

    Raises:
        IntegrationError: If KB client is not provided.
    """
    if client is None:
        raise IntegrationError("KB client not provided")

    try:
        clients = client.list_clients()
        return {
            "success": True,
            "count": len(clients),
            "clients": clients,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to list KB clients: {str(e)}") from e


def get_client_infra(
    client_name: str,
    client: KBClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get an aggregated view of a client's infrastructure.

    Tool schema:
    - name: kb_get_client_infra
    - description: Load and summarize client infrastructure (subnets, servers, users, naming schemas, env rules) from client_env/*.
    - parameters:
      - client_name (str, required): Name of the client environment (e.g., "acme_corp_client" or "acme_corp").

    Args:
        client_name: Client identifier.
        client: The KB client.

    Returns:
        Dictionary with normalized infrastructure data and a concise summary.

    Raises:
        IntegrationError: If KB client is not provided or loading fails.
    """
    if client is None:
        raise IntegrationError("KB client not provided")

    try:
        infra = client.get_client_infra(client_name)

        return {
            "success": True,
            "client_name": infra.client_name,
            "summary": infra.summary,
            "subnets": [
                {
                    "name": s.name,
                    "cidr": s.cidr,
                    "network_type": s.network_type,
                    "access_method": s.access_method,
                    "description": s.description,
                    "tags": s.tags or [],
                }
                for s in infra.subnets
            ],
            "servers": [
                {
                    "hostname": srv.hostname,
                    "ip_address": srv.ip_address,
                    "role": srv.role,
                    "environment": srv.environment,
                    "os": srv.os,
                    "description": srv.description,
                    "criticality": srv.criticality,
                    "tags": srv.tags or [],
                }
                for srv in infra.servers
            ],
            "users": [
                {
                    "username": u.username,
                    "display_name": u.display_name,
                    "account_type": u.account_type,
                    "department": u.department,
                    "privilege_level": u.privilege_level,
                    "description": u.description,
                    "tags": u.tags or [],
                }
                for u in infra.users
            ],
            "device_schemas": [
                {
                    "pattern": d.pattern,
                    "pattern_style": d.pattern_style,
                    "device_type": d.device_type,
                    "example": d.example,
                    "description": d.description,
                    "tags": d.tags or [],
                }
                for d in infra.device_schemas
            ],
            "user_schemas": [
                {
                    "pattern": us.pattern,
                    "pattern_style": us.pattern_style,
                    "user_type": us.user_type,
                    "example": us.example,
                    "description": us.description,
                    "tags": us.tags or [],
                }
                for us in infra.user_schemas
            ],
            "env_rules": {
                "version": infra.env_rules.version if infra.env_rules else None,
                "environment_types": infra.env_rules.environment_types if infra.env_rules else None,
                "network_classification": infra.env_rules.network_classification if infra.env_rules else None,
                "user_categories": infra.env_rules.user_categories if infra.env_rules else None,
                "general_rules": infra.env_rules.general_rules if infra.env_rules else None,
            }
            if infra.env_rules
            else None,
        }
    except Exception as e:
        raise IntegrationError(
            f"Failed to load infrastructure for client '{client_name}': {str(e)}"
        ) from e


