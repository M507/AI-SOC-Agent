"""
Knowledge Base (KB) API for client infrastructure.

This module defines DTOs and the ``KBClient`` interface that orchestrator code
and MCP tools will use to read and present client infrastructure knowledge from
the local filesystem (``client_env/*``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Protocol, Dict, Any

from ..core.dto import BaseDTO


@dataclass
class KBSubnet(BaseDTO):
    """Represents a logical subnet or network segment."""

    name: str
    cidr: str
    network_type: Optional[str] = None
    access_method: Optional[List[str]] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None


@dataclass
class KBServer(BaseDTO):
    """Represents an internal server or infrastructure node."""

    hostname: str
    ip_address: Optional[str] = None
    role: Optional[str] = None
    environment: Optional[str] = None
    os: Optional[str] = None
    description: Optional[str] = None
    criticality: Optional[str] = None
    tags: Optional[List[str]] = None


@dataclass
class KBUser(BaseDTO):
    """Represents an internal user/account in the environment."""

    username: str
    display_name: Optional[str] = None
    account_type: Optional[str] = None
    department: Optional[str] = None
    privilege_level: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None


@dataclass
class KBDeviceSchema(BaseDTO):
    """Represents a naming schema pattern for devices/hosts."""

    pattern: str
    pattern_style: str
    device_type: str
    example: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None


@dataclass
class KBUserSchema(BaseDTO):
    """Represents a naming schema pattern for user accounts."""

    pattern: str
    pattern_style: str
    user_type: str
    example: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None


@dataclass
class KBEnvRules(BaseDTO):
    """Represents environment-wide classification and risk rules."""

    version: Optional[str] = None
    environment_types: Optional[List[str]] = None
    network_classification: Optional[Dict[str, Any]] = None
    user_categories: Optional[Dict[str, Any]] = None
    general_rules: Optional[List[Dict[str, Any]]] = None


@dataclass
class KBClientInfra(BaseDTO):
    """
    Aggregated view of a client's infrastructure as loaded from client_env/*.
    """

    client_name: str
    subnets: List[KBSubnet] = field(default_factory=list)
    servers: List[KBServer] = field(default_factory=list)
    users: List[KBUser] = field(default_factory=list)
    device_schemas: List[KBDeviceSchema] = field(default_factory=list)
    user_schemas: List[KBUserSchema] = field(default_factory=list)
    env_rules: Optional[KBEnvRules] = None
    summary: Optional[str] = None


class KBClient(Protocol):
    """
    Interface for knowledge base clients that provide client infrastructure
    knowledge to the MCP server and orchestrator tools.
    """

    def list_clients(self) -> List[str]:
        """
        List available client environments.

        Returns:
            List of client identifiers (e.g., ``acme_corp_client``).
        """

        ...

    def get_client_infra(self, client_name: str) -> KBClientInfra:
        """
        Load and aggregate infrastructure knowledge for a specific client.

        Args:
            client_name: Client identifier (e.g., ``acme_corp_client`` or ``acme_corp``).

        Returns:
            KBClientInfra object with normalized data and an optional summary string.
        """

        ...


