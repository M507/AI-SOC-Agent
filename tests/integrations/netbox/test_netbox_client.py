"""Unit tests for the NetBox integration client."""

from __future__ import annotations

from src.core.config import NetBoxConfig, SamiConfig
from src.integrations.netbox.netbox_client import NetBoxAPIClient
from src.integrations.netbox.netbox_http import NetBoxHttpClient
from src.orchestrator import tools_netbox


class FakeHttp:
    def __init__(self):
        self.calls = []

    def status(self):
        return {"netbox-version": "4.7.0"}

    def list_results(self, path, *, params=None, limit=25):
        self.calls.append({"path": path, "params": params, "limit": limit})
        if path.startswith("ipam/ip-addresses"):
            return [
                {
                    "id": 1,
                    "address": "10.7.7.1/24",
                    "status": {"value": "active"},
                    "dns_name": "cs",
                    "description": "lab",
                    "assigned_object_type": "virtualization.vminterface",
                    "assigned_object": {
                        "id": 62,
                        "name": "eth0",
                        "virtual_machine": {"id": 62, "name": "CS"},
                    },
                    "tags": [{"name": "lab"}],
                    "display_url": "http://netbox/ipam/ip-addresses/1/",
                }
            ]
        if path.startswith("dcim/devices"):
            return [
                {
                    "id": 10,
                    "name": "edge-fw",
                    "status": {"value": "active"},
                    "role": {"name": "Firewall"},
                    "site": {"name": "Home"},
                    "primary_ip4": {"address": "10.10.10.1/24"},
                    "display_url": "http://netbox/dcim/devices/10/",
                }
            ]
        if path.startswith("virtualization/virtual-machines"):
            return [
                {
                    "id": 62,
                    "name": "CS",
                    "status": {"value": "active"},
                    "role": {"name": "Server"},
                    "site": {"name": "Home"},
                    "primary_ip4": {"address": "10.7.7.1/24"},
                }
            ]
        if path.startswith("ipam/prefixes"):
            return [
                {
                    "id": 11,
                    "prefix": "10.7.7.0/24",
                    "status": {"value": "active"},
                    "description": "C2_PG",
                    "scope": {"name": "Home"},
                }
            ]
        return []


def test_netbox_client_normalizes_lookups():
    http = FakeHttp()
    client = NetBoxAPIClient(http_client=http)  # type: ignore[arg-type]

    assert client.ping() is True

    ips = client.lookup_ip("10.7.7.1")
    assert len(ips) == 1
    assert ips[0].address == "10.7.7.1/24"
    assert ips[0].dns_name == "cs"
    assert ips[0].assigned_object["virtual_machine"] == "CS"

    hosts = client.lookup_host("CS")
    assert any(h.name == "CS" and h.object_type == "virtual_machine" for h in hosts)
    assert any(h.name == "edge-fw" and h.object_type == "device" for h in hosts)

    prefixes = client.lookup_prefix("10.7.7.50")
    assert prefixes[0].prefix == "10.7.7.0/24"
    assert prefixes[0].site == "Home"
    assert any(call["params"].get("contains") == "10.7.7.50" for call in http.calls)

    search = client.search("CS")
    assert search["devices"] and search["virtual_machines"] and search["ip_addresses"]


def test_netbox_tools_wrap_client():
    http = FakeHttp()
    client = NetBoxAPIClient(http_client=http)  # type: ignore[arg-type]
    result = tools_netbox.netbox_lookup_ip("10.7.7.1", client=client, limit=5)
    assert result["success"] is True
    assert result["count"] == 1
    assert result["results"][0]["dns_name"] == "cs"


def test_netbox_from_config_builds_http_client():
    config = SamiConfig(
        netbox=NetBoxConfig(
            base_url="http://10.10.10.79:8851",
            api_token="nbt_test",
            verify_ssl=False,
        )
    )
    client = NetBoxAPIClient.from_config(config)
    assert isinstance(client._http, NetBoxHttpClient)
    assert client._http.api_root == "http://10.10.10.79:8851/api/"
