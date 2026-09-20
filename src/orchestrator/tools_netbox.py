"""
LLM-callable tools for NetBox DCIM/IPAM enrichment.

Read-only lookups used during investigations to map IPs and hostnames to
documented assets, prefixes, and assignments.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, Optional

from ..api.netbox import NetBoxClient
from ..core.errors import IntegrationError


def _to_dict(obj: Any) -> Dict[str, Any]:
    data = asdict(obj)
    data.pop("raw", None)
    return data


def netbox_lookup_ip(
    ip: str,
    client: NetBoxClient = None,  # type: ignore
    limit: int = 25,
) -> Dict[str, Any]:
    """
    Look up an IP address in NetBox.

    Tool schema:
    - name: netbox_lookup_ip
    - description: Resolve an IP in NetBox IPAM (assignment, DNS name, device/VM).
    - parameters:
      - ip (str, required)
      - limit (int, optional)
    """
    if client is None:
        raise IntegrationError("NetBox client not provided")
    try:
        results = client.lookup_ip(ip, limit=limit)
        return {
            "success": True,
            "ip": ip,
            "count": len(results),
            "results": [_to_dict(item) for item in results],
        }
    except Exception as e:
        raise IntegrationError(f"NetBox IP lookup failed: {e}") from e


def netbox_lookup_host(
    name: str,
    client: NetBoxClient = None,  # type: ignore
    limit: int = 25,
) -> Dict[str, Any]:
    """
    Look up a device or virtual machine by name in NetBox.

    Tool schema:
    - name: netbox_lookup_host
    - description: Search NetBox devices and VMs by hostname/name.
    - parameters:
      - name (str, required)
      - limit (int, optional)
    """
    if client is None:
        raise IntegrationError("NetBox client not provided")
    try:
        results = client.lookup_host(name, limit=limit)
        return {
            "success": True,
            "name": name,
            "count": len(results),
            "results": [_to_dict(item) for item in results],
        }
    except Exception as e:
        raise IntegrationError(f"NetBox host lookup failed: {e}") from e


def netbox_lookup_prefix(
    query: str,
    client: NetBoxClient = None,  # type: ignore
    limit: int = 25,
) -> Dict[str, Any]:
    """
    Look up IPAM prefixes in NetBox.

    Tool schema:
    - name: netbox_lookup_prefix
    - description: Find prefixes by CIDR or the prefix containing an IP.
    - parameters:
      - query (str, required): CIDR or IP address
      - limit (int, optional)
    """
    if client is None:
        raise IntegrationError("NetBox client not provided")
    try:
        results = client.lookup_prefix(query, limit=limit)
        return {
            "success": True,
            "query": query,
            "count": len(results),
            "results": [_to_dict(item) for item in results],
        }
    except Exception as e:
        raise IntegrationError(f"NetBox prefix lookup failed: {e}") from e


def netbox_search(
    query: str,
    client: NetBoxClient = None,  # type: ignore
    limit: int = 25,
) -> Dict[str, Any]:
    """
    Free-text search across NetBox devices, VMs, and IP addresses.

    Tool schema:
    - name: netbox_search
    - description: Search NetBox assets by free-text query.
    - parameters:
      - query (str, required)
      - limit (int, optional)
    """
    if client is None:
        raise IntegrationError("NetBox client not provided")
    try:
        payload = client.search(query, limit=limit)
        devices = [_to_dict(item) for item in payload.get("devices") or []]
        vms = [_to_dict(item) for item in payload.get("virtual_machines") or []]
        ips = [_to_dict(item) for item in payload.get("ip_addresses") or []]
        return {
            "success": True,
            "query": query,
            "count": len(devices) + len(vms) + len(ips),
            "devices": devices,
            "virtual_machines": vms,
            "ip_addresses": ips,
        }
    except Exception as e:
        raise IntegrationError(f"NetBox search failed: {e}") from e
