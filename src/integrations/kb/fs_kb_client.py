"""
Filesystem-backed KB client.

This client reads client infrastructure knowledge from JSON files under
``client_env/*`` in the project root and exposes it via the KBClient API.
"""

from __future__ import annotations

import json
import os
from typing import List, Optional

from ...core.errors import IntegrationError
from ...api.kb import (
    KBClient,
    KBClientInfra,
    KBSubnet,
    KBServer,
    KBUser,
    KBDeviceSchema,
    KBUserSchema,
    KBEnvRules,
)


class FileSystemKBClient(KBClient):
    """
    Knowledge base client that reads from local JSON files.

    Folder layout (relative to project root):
    - client_env/
      - all_clients/               # generic templates (not treated as a client)
      - env_rules.json             # shared rules across all clients
      - <client_name>_client/
        - internal_subnets.json
        - internal_servers.json
        - internal_users.json
        - naming_schemas.json
    """

    def __init__(self, client_env_dir: Optional[str] = None) -> None:
        # Infer project root from this file path
        if client_env_dir is None:
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            client_env_dir = os.path.join(project_root, "client_env")

        self.client_env_dir = client_env_dir

    # ------------------------------------------------------------------
    # KBClient interface
    # ------------------------------------------------------------------
    def list_clients(self) -> List[str]:
        """List available client environment folders."""
        if not os.path.isdir(self.client_env_dir):
            return []

        clients: List[str] = []
        for entry in os.listdir(self.client_env_dir):
            full_path = os.path.join(self.client_env_dir, entry)
            if not os.path.isdir(full_path):
                continue
            if entry == "all_clients":
                continue
            # Conventionally treat folders ending with _client as full environments
            if entry.endswith("_client"):
                clients.append(entry)
        clients.sort()
        return clients

    def get_client_infra(self, client_name: str) -> KBClientInfra:
        """Load and aggregate infrastructure knowledge for a specific client."""
        # Allow passing bare client name without _client suffix
        if not client_name.endswith("_client"):
            candidate = f"{client_name}_client"
        else:
            candidate = client_name

        client_dir = os.path.join(self.client_env_dir, candidate)
        if not os.path.isdir(client_dir):
            raise IntegrationError(
                f"Client environment not found: {client_name} "
                f"(looked in {client_dir})"
            )

        subnets = self._load_subnets(client_dir)
        servers = self._load_servers(client_dir)
        users = self._load_users(client_dir)
        device_schemas, user_schemas = self._load_naming_schemas(client_dir)
        env_rules = self._load_env_rules()

        summary = self._build_summary(
            client_name=candidate,
            subnets=subnets,
            servers=servers,
            users=users,
            device_schemas=device_schemas,
            user_schemas=user_schemas,
        )

        return KBClientInfra(
            client_name=candidate,
            subnets=subnets,
            servers=servers,
            users=users,
            device_schemas=device_schemas,
            user_schemas=user_schemas,
            env_rules=env_rules,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Helpers for loading JSON and building DTOs
    # ------------------------------------------------------------------
    def _load_json(self, path: str) -> Optional[dict]:
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            raise IntegrationError(f"Failed to load JSON from {path}: {e}") from e

    def _load_subnets(self, client_dir: str) -> List[KBSubnet]:
        data = self._load_json(os.path.join(client_dir, "internal_subnets.json")) or {}
        raw_subnets = data.get("subnets", [])
        subnets: List[KBSubnet] = []
        for s in raw_subnets:
            subnets.append(
                KBSubnet(
                    name=s.get("name", ""),
                    cidr=s.get("cidr", ""),
                    network_type=s.get("network_type"),
                    access_method=s.get("access_method"),
                    description=s.get("description"),
                    tags=s.get("tags"),
                )
            )
        return subnets

    def _load_servers(self, client_dir: str) -> List[KBServer]:
        data = self._load_json(os.path.join(client_dir, "internal_servers.json")) or {}
        raw_servers = data.get("servers", [])
        servers: List[KBServer] = []
        for s in raw_servers:
            servers.append(
                KBServer(
                    hostname=s.get("hostname", ""),
                    ip_address=s.get("ip_address"),
                    role=s.get("role"),
                    environment=s.get("environment"),
                    os=s.get("os"),
                    description=s.get("description"),
                    criticality=s.get("criticality"),
                    tags=s.get("tags"),
                )
            )
        return servers

    def _load_users(self, client_dir: str) -> List[KBUser]:
        data = self._load_json(os.path.join(client_dir, "internal_users.json")) or {}
        raw_users = data.get("users", [])
        users: List[KBUser] = []
        for u in raw_users:
            users.append(
                KBUser(
                    username=u.get("username", ""),
                    display_name=u.get("display_name"),
                    account_type=u.get("account_type"),
                    department=u.get("department"),
                    privilege_level=u.get("privilege_level"),
                    description=u.get("description"),
                    tags=u.get("tags"),
                )
            )
        return users

    def _load_naming_schemas(
        self, client_dir: str
    ) -> tuple[List[KBDeviceSchema], List[KBUserSchema]]:
        data = self._load_json(os.path.join(client_dir, "naming_schemas.json")) or {}
        raw_device_schemas = data.get("device_schemas", [])
        raw_user_schemas = data.get("user_schemas", [])

        device_schemas: List[KBDeviceSchema] = []
        for d in raw_device_schemas:
            # Skip entries missing required fields
            if not d.get("pattern") or not d.get("device_type"):
                continue
            device_schemas.append(
                KBDeviceSchema(
                    pattern=d.get("pattern", ""),
                    pattern_style=d.get("pattern_style", "regex"),
                    device_type=d.get("device_type", ""),
                    example=d.get("example"),
                    description=d.get("description"),
                    tags=d.get("tags"),
                )
            )

        user_schemas: List[KBUserSchema] = []
        for u in raw_user_schemas:
            if not u.get("pattern") or not u.get("user_type"):
                continue
            user_schemas.append(
                KBUserSchema(
                    pattern=u.get("pattern", ""),
                    pattern_style=u.get("pattern_style", "regex"),
                    user_type=u.get("user_type", ""),
                    example=u.get("example"),
                    description=u.get("description"),
                    tags=u.get("tags"),
                )
            )

        return device_schemas, user_schemas

    def _load_env_rules(self) -> Optional[KBEnvRules]:
        data = self._load_json(os.path.join(self.client_env_dir, "env_rules.json"))
        if not data:
            return None
        return KBEnvRules(
            version=data.get("version"),
            environment_types=data.get("environment_types"),
            network_classification=data.get("network_classification"),
            user_categories=data.get("user_categories"),
            general_rules=data.get("general_rules"),
        )

    # ------------------------------------------------------------------
    # Summary builder
    # ------------------------------------------------------------------
    def _build_summary(
        self,
        client_name: str,
        subnets: List[KBSubnet],
        servers: List[KBServer],
        users: List[KBUser],
        device_schemas: List[KBDeviceSchema],
        user_schemas: List[KBUserSchema],
    ) -> str:
        """Build a concise, human-readable summary of the client environment."""

        total_subnets = len(subnets)
        total_servers = len(servers)
        total_users = len(users)

        # Count by simple categories
        internal_subnets = [
            s for s in subnets if (s.network_type or "").lower() in {"internal", "lan"}
        ]
        vpn_subnets = [
            s for s in subnets
            if "vpn" in (s.tags or []) or "vpn" in (s.description or "").lower()
        ]
        guest_subnets = [
            s for s in subnets
            if (s.network_type or "").lower() == "guest"
            or "guest" in (s.tags or [])
        ]
        dmz_subnets = [
            s for s in subnets
            if (s.network_type or "").lower() == "dmz"
            or "dmz" in (s.tags or [])
        ]

        admin_users = [
            u for u in users
            if (u.account_type or "").lower() == "administrator"
            or (u.privilege_level or "").lower() in {"admin", "high"}
        ]
        contractor_users = [
            u for u in users if (u.account_type or "").lower() == "contractor"
        ]
        service_accounts = [
            u for u in users if (u.account_type or "").lower() in {"service", "service_account"}
        ]

        lines: List[str] = []
        lines.append(f"Client '{client_name}' infrastructure overview:")
        lines.append(
            f"- {total_subnets} subnets "
            f"({len(internal_subnets)} internal, "
            f"{len(vpn_subnets)} VPN, "
            f"{len(dmz_subnets)} DMZ, "
            f"{len(guest_subnets)} guest)"
        )
        lines.append(
            f"- {total_servers} servers (examples: "
            + ", ".join(s.hostname for s in servers[:3])
            + (", ..." if total_servers > 3 else ")")
        )
        lines.append(
            f"- {total_users} user accounts "
            f"({len(admin_users)} admin, "
            f"{len(service_accounts)} service, "
            f"{len(contractor_users)} contractor)"
        )

        if device_schemas:
            device_types = sorted({d.device_type for d in device_schemas})
            lines.append(
                "- Device naming schemas define types: " + ", ".join(device_types)
            )
        if user_schemas:
            user_types = sorted({u.user_type for u in user_schemas})
            lines.append(
                "- User naming schemas define categories: " + ", ".join(user_types)
            )

        return "\n".join(lines)


