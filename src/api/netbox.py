"""
NetBox (DCIM/IPAM) API for asset and network enrichment.

Defines DTOs and the ``NetBoxClient`` interface that orchestrator code and
MCP tools use. Vendor HTTP details live under ``src/integrations/netbox``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from ..core.dto import BaseDTO


@dataclass
class NetBoxRef(BaseDTO):
    """Compact nested object reference from NetBox."""

    id: Optional[int] = None
    name: Optional[str] = None
    display: Optional[str] = None
    slug: Optional[str] = None
    url: Optional[str] = None


@dataclass
class NetBoxIPAddress(BaseDTO):
    """Normalized IP address record."""

    id: int
    address: str
    status: Optional[str] = None
    dns_name: Optional[str] = None
    description: Optional[str] = None
    role: Optional[str] = None
    vrf: Optional[str] = None
    tenant: Optional[str] = None
    assigned_object_type: Optional[str] = None
    assigned_object: Optional[Dict[str, Any]] = None
    tags: List[str] = field(default_factory=list)
    display_url: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


@dataclass
class NetBoxDevice(BaseDTO):
    """Normalized device or virtual machine."""

    id: int
    name: str
    object_type: str  # "device" | "virtual_machine"
    status: Optional[str] = None
    role: Optional[str] = None
    site: Optional[str] = None
    tenant: Optional[str] = None
    platform: Optional[str] = None
    primary_ip: Optional[str] = None
    serial: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    display_url: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


@dataclass
class NetBoxPrefix(BaseDTO):
    """Normalized IPAM prefix."""

    id: int
    prefix: str
    status: Optional[str] = None
    description: Optional[str] = None
    site: Optional[str] = None
    role: Optional[str] = None
    vlan: Optional[str] = None
    vrf: Optional[str] = None
    tenant: Optional[str] = None
    is_pool: Optional[bool] = None
    tags: List[str] = field(default_factory=list)
    display_url: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


class NetBoxClient(Protocol):
    """Interface for NetBox DCIM/IPAM lookups used during investigations."""

    def ping(self) -> bool:
        """Return True when the NetBox API is reachable and authenticated."""
        ...

    def lookup_ip(self, ip: str, *, limit: int = 25) -> List[NetBoxIPAddress]:
        """Find IP address records matching ``ip`` (with or without prefix length)."""
        ...

    def lookup_host(self, name: str, *, limit: int = 25) -> List[NetBoxDevice]:
        """Search devices and virtual machines by name / hostname."""
        ...

    def lookup_prefix(self, query: str, *, limit: int = 25) -> List[NetBoxPrefix]:
        """
        Find prefixes.

        ``query`` may be a CIDR (``10.7.7.0/24``) or an IP whose containing
        prefixes should be returned (``contains`` filter).
        """
        ...

    def search(self, query: str, *, limit: int = 25) -> Dict[str, Any]:
        """
        Free-text search across devices, VMs, and IP addresses.

        Returns a dict with ``devices``, ``virtual_machines``, and ``ip_addresses``.
        """
        ...
