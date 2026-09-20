"""
NetBox client implementing the ``NetBoxClient`` protocol.

Normalizes NetBox REST payloads into compact DTOs for MCP / LLM use.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional

from ...api.netbox import NetBoxDevice, NetBoxIPAddress, NetBoxPrefix
from ...core.config import SamiConfig
from ...core.errors import IntegrationError
from ...core.logging import get_logger
from .netbox_http import NetBoxHttpClient

logger = get_logger("sami.integrations.netbox.client")

_CIDR_RE = re.compile(r"^.+/\d+$")


def _nested_name(obj: Any) -> Optional[str]:
    if not isinstance(obj, dict):
        return None
    for key in ("name", "display", "slug", "address", "prefix"):
        value = obj.get(key)
        if value:
            return str(value)
    return None


def _status_value(obj: Any) -> Optional[str]:
    if isinstance(obj, dict):
        return str(obj.get("value") or obj.get("label") or "") or None
    if obj is None:
        return None
    return str(obj)


def _tag_names(raw: Any) -> List[str]:
    if not isinstance(raw, list):
        return []
    names: List[str] = []
    for item in raw:
        if isinstance(item, dict) and item.get("name"):
            names.append(str(item["name"]))
        elif isinstance(item, str):
            names.append(item)
    return names


def _primary_ip(raw: Dict[str, Any]) -> Optional[str]:
    for key in ("primary_ip4", "primary_ip6", "primary_ip"):
        value = raw.get(key)
        if isinstance(value, dict) and value.get("address"):
            return str(value["address"])
        if isinstance(value, str) and value:
            return value
    return None


class NetBoxAPIClient:
    """NetBox-backed DCIM/IPAM client."""

    def __init__(self, http_client: NetBoxHttpClient) -> None:
        self._http = http_client

    @classmethod
    def from_config(cls, config: SamiConfig) -> "NetBoxAPIClient":
        if not config.netbox:
            raise IntegrationError("NetBox configuration is not set in SamiConfig")
        if not config.netbox.base_url or not config.netbox.api_token:
            raise IntegrationError("NetBox requires base_url and api_token")
        http = NetBoxHttpClient(
            base_url=config.netbox.base_url,
            api_token=config.netbox.api_token,
            timeout_seconds=config.netbox.timeout_seconds,
            verify_ssl=config.netbox.verify_ssl,
        )
        return cls(http_client=http)

    def ping(self) -> bool:
        try:
            status = self._http.status()
            return bool(status.get("netbox-version") or status.get("netbox-full-version"))
        except Exception as e:
            logger.warning("NetBox ping failed: %s", e)
            return False

    def lookup_ip(self, ip: str, *, limit: int = 25) -> List[NetBoxIPAddress]:
        value = (ip or "").strip()
        if not value:
            raise IntegrationError("ip is required")
        bare = value.split("/")[0]
        results = self._http.list_results(
            "ipam/ip-addresses/",
            params={"address": bare},
            limit=limit,
        )
        if not results:
            results = self._http.list_results(
                "ipam/ip-addresses/",
                params={"q": bare},
                limit=limit,
            )
        return [self._normalize_ip(item) for item in results]

    def lookup_host(self, name: str, *, limit: int = 25) -> List[NetBoxDevice]:
        query = (name or "").strip()
        if not query:
            raise IntegrationError("name is required")
        per_source = max(1, min(limit, 50))
        devices = [
            self._normalize_device(item, object_type="device")
            for item in self._http.list_results(
                "dcim/devices/",
                params={"q": query},
                limit=per_source,
            )
        ]
        vms = [
            self._normalize_device(item, object_type="virtual_machine")
            for item in self._http.list_results(
                "virtualization/virtual-machines/",
                params={"q": query},
                limit=per_source,
            )
        ]
        combined = devices + vms
        return combined[:limit]

    def lookup_prefix(self, query: str, *, limit: int = 25) -> List[NetBoxPrefix]:
        value = (query or "").strip()
        if not value:
            raise IntegrationError("query is required")

        params: Dict[str, Any]
        if _CIDR_RE.match(value):
            params = {"prefix": value}
        else:
            bare = value.split("/")[0]
            try:
                ipaddress.ip_address(bare)
                params = {"contains": bare}
            except ValueError:
                params = {"q": value}

        results = self._http.list_results("ipam/prefixes/", params=params, limit=limit)
        return [self._normalize_prefix(item) for item in results]

    def search(self, query: str, *, limit: int = 25) -> Dict[str, Any]:
        value = (query or "").strip()
        if not value:
            raise IntegrationError("query is required")
        per_source = max(1, min(limit, 50))
        devices = [
            self._normalize_device(item, object_type="device")
            for item in self._http.list_results(
                "dcim/devices/",
                params={"q": value},
                limit=per_source,
            )
        ]
        vms = [
            self._normalize_device(item, object_type="virtual_machine")
            for item in self._http.list_results(
                "virtualization/virtual-machines/",
                params={"q": value},
                limit=per_source,
            )
        ]
        ips = [
            self._normalize_ip(item)
            for item in self._http.list_results(
                "ipam/ip-addresses/",
                params={"q": value},
                limit=per_source,
            )
        ]
        return {
            "devices": devices[:limit],
            "virtual_machines": vms[:limit],
            "ip_addresses": ips[:limit],
        }

    def _normalize_ip(self, raw: Dict[str, Any]) -> NetBoxIPAddress:
        assigned = raw.get("assigned_object")
        assigned_summary: Optional[Dict[str, Any]] = None
        if isinstance(assigned, dict):
            assigned_summary = {
                "id": assigned.get("id"),
                "name": assigned.get("name") or assigned.get("display"),
                "device": _nested_name(assigned.get("device")),
                "virtual_machine": _nested_name(assigned.get("virtual_machine")),
            }
        return NetBoxIPAddress(
            id=int(raw.get("id") or 0),
            address=str(raw.get("address") or ""),
            status=_status_value(raw.get("status")),
            dns_name=raw.get("dns_name") or None,
            description=raw.get("description") or None,
            role=_nested_name(raw.get("role")) or _status_value(raw.get("role")),
            vrf=_nested_name(raw.get("vrf")),
            tenant=_nested_name(raw.get("tenant")),
            assigned_object_type=raw.get("assigned_object_type"),
            assigned_object=assigned_summary,
            tags=_tag_names(raw.get("tags")),
            display_url=raw.get("display_url"),
        )

    def _normalize_device(self, raw: Dict[str, Any], *, object_type: str) -> NetBoxDevice:
        return NetBoxDevice(
            id=int(raw.get("id") or 0),
            name=str(raw.get("name") or raw.get("display") or ""),
            object_type=object_type,
            status=_status_value(raw.get("status")),
            role=_nested_name(raw.get("role") or raw.get("device_role")),
            site=_nested_name(raw.get("site")),
            tenant=_nested_name(raw.get("tenant")),
            platform=_nested_name(raw.get("platform")),
            primary_ip=_primary_ip(raw),
            serial=(raw.get("serial") or None) if object_type == "device" else None,
            description=raw.get("description") or None,
            tags=_tag_names(raw.get("tags")),
            display_url=raw.get("display_url"),
        )

    def _normalize_prefix(self, raw: Dict[str, Any]) -> NetBoxPrefix:
        site = _nested_name(raw.get("site")) or _nested_name(raw.get("scope"))
        return NetBoxPrefix(
            id=int(raw.get("id") or 0),
            prefix=str(raw.get("prefix") or ""),
            status=_status_value(raw.get("status")),
            description=raw.get("description") or None,
            site=site,
            role=_nested_name(raw.get("role")),
            vlan=_nested_name(raw.get("vlan")),
            vrf=_nested_name(raw.get("vrf")),
            tenant=_nested_name(raw.get("tenant")),
            is_pool=bool(raw.get("is_pool")) if raw.get("is_pool") is not None else None,
            tags=_tag_names(raw.get("tags")),
            display_url=raw.get("display_url"),
        )
