#!/usr/bin/env python3
"""Walk the setup wizard against an isolated instance and compare the saved config.

Reads the golden config for the values to type. Prints key paths on mismatch, never values.
"""

from __future__ import annotations

import argparse
import json
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, Dict, List


TEST_PASSWORD = "onboarding-test-password"
SKIPPED_SECTIONS = ("iris", "thehive", "edr", "cti_opencti")


class WizardClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        context = ssl._create_unverified_context()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(CookieJar()),
        )

    def request(self, method: str, path: str, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with self._opener.open(request, timeout=60) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise SystemExit(f"{method} {path} failed with HTTP {exc.code}") from exc
        return json.loads(raw) if raw else {}


def _fail(mismatches: List[str]) -> None:
    print("Config mismatch:")
    for path in mismatches:
        print(f"  {path}")
    raise SystemExit(1)


def _eq(mismatches: List[str], path: str, actual: Any, expected: Any) -> None:
    if actual != expected:
        mismatches.append(path)


def _section(data: Dict[str, Any], name: str) -> Dict[str, Any]:
    value = data.get(name)
    return value if isinstance(value, dict) else {}


def compare(saved: Dict[str, Any], golden: Dict[str, Any], example: Dict[str, Any]) -> None:
    mismatches: List[str] = []
    elastic = _section(saved, "elastic")
    golden_elastic = _section(golden, "elastic")
    clusters = elastic.get("clusters") if isinstance(elastic.get("clusters"), list) else []
    golden_clusters = golden_elastic.get("clusters") if isinstance(golden_elastic.get("clusters"), list) else []
    if not clusters or not golden_clusters:
        mismatches.append("elastic.clusters")
        _fail(mismatches)
    cluster = clusters[0]
    golden_cluster = golden_clusters[0]
    _eq(mismatches, "elastic.default_cluster_id", elastic.get("default_cluster_id"), golden_elastic.get("default_cluster_id"))
    _eq(mismatches, "elastic.default_skill_vector", elastic.get("default_skill_vector"), golden_elastic.get("default_skill_vector"))
    for key in ("id", "name", "base_url", "api_key", "username", "password", "timeout_seconds", "verify_ssl", "skill_vector", "kibana_url"):
        _eq(mismatches, f"elastic.clusters[0].{key}", cluster.get(key), golden_cluster.get(key))
    for key in ("base_url", "api_key", "username", "password", "timeout_seconds", "verify_ssl"):
        _eq(mismatches, f"elastic.{key}", elastic.get(key), golden_elastic.get(key))
    if elastic.get("verify_ssl") is not False or cluster.get("verify_ssl") is not False:
        mismatches.append("elastic.verify_ssl")

    cti = _section(saved, "cti")
    golden_cti = _section(golden, "cti")
    for key in ("cti_type", "base_url", "timeout_seconds", "verify_ssl"):
        _eq(mismatches, f"cti.{key}", cti.get(key), golden_cti.get(key))
    if cti.get("verify_ssl") is not False:
        mismatches.append("cti.verify_ssl")

    netbox = _section(saved, "netbox")
    golden_netbox = _section(golden, "netbox")
    for key in ("base_url", "api_token", "timeout_seconds", "verify_ssl"):
        _eq(mismatches, f"netbox.{key}", netbox.get(key), golden_netbox.get(key))
    if netbox.get("verify_ssl") is not False:
        mismatches.append("netbox.verify_ssl")

    eng = _section(saved, "eng")
    golden_eng = _section(golden, "eng")
    example_eng = _section(example, "eng")
    _eq(mismatches, "eng.provider", eng.get("provider"), golden_eng.get("provider"))
    github = eng.get("github") if isinstance(eng.get("github"), dict) else {}
    golden_github = golden_eng.get("github") if isinstance(golden_eng.get("github"), dict) else {}
    for key in ("api_token", "repository", "fine_tuning_label", "visibility_label", "timeout_seconds", "verify_ssl"):
        _eq(mismatches, f"eng.github.{key}", github.get(key), golden_github.get(key))
    _eq(mismatches, "eng.trello", eng.get("trello"), example_eng.get("trello"))
    _eq(mismatches, "eng.clickup", eng.get("clickup"), example_eng.get("clickup"))

    llm = _section(saved, "llm")
    golden_llm = _section(golden, "llm")
    _eq(mismatches, "llm.provider", llm.get("provider"), golden_llm.get("provider"))
    own = llm.get("openwebui") if isinstance(llm.get("openwebui"), dict) else {}
    golden_own = golden_llm.get("openwebui") if isinstance(golden_llm.get("openwebui"), dict) else {}
    for key in ("api_key", "base_url", "model", "mcp_server_id"):
        _eq(mismatches, f"llm.openwebui.{key}", own.get(key), golden_own.get(key))

    mcp = _section(saved, "mcp")
    golden_mcp = _section(golden, "mcp")
    for key in ("enabled", "auto_start", "port", "tls", "public_url", "api_token"):
        _eq(mismatches, f"mcp.{key}", mcp.get(key), golden_mcp.get(key))
    if mcp.get("host") != "0.0.0.0":
        mismatches.append("mcp.host")

    web = _section(saved, "web")
    _eq(mismatches, "web.username", web.get("username"), _section(golden, "web").get("username"))
    password = str(web.get("password") or "")
    if not password.startswith("$argon2id$") or password == TEST_PASSWORD:
        mismatches.append("web.password")
    if len(str(web.get("session_secret") or "")) < 32:
        mismatches.append("web.session_secret")

    for name in SKIPPED_SECTIONS:
        if saved.get(name) != example.get(name):
            mismatches.append(f"{name} placeholder")

    if mismatches:
        _fail(mismatches)


def container_config() -> Dict[str, Any]:
    completed = subprocess.run(
        [
            "docker", "compose", "-p", "samigpt-onboarding",
            "-f", "onboarding/docker-compose.yml",
            "exec", "-T", "onboarding",
            "python", "-c",
            "print(open('/var/lib/samigpt/config.json', encoding='utf-8').read())",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise SystemExit("Could not read the onboarding config from the container")
    return json.loads(completed.stdout)


def drive(client: WizardClient, golden: Dict[str, Any]) -> None:
    status = client.request("GET", "/api/setup/status")
    if not status.get("setup_required"):
        raise SystemExit("Expected a fresh setup with no console password")

    web = _section(golden, "web")
    client.request("POST", "/api/setup/steps/welcome", {"action": "next", "values": {}})
    client.request(
        "POST",
        "/api/setup/steps/security",
        {
            "action": "save",
            "values": {
                "username": web.get("username") or "admin",
                "password": TEST_PASSWORD,
                "confirm_password": TEST_PASSWORD,
                "session_ttl_seconds": int(web.get("session_ttl_seconds") or 43200),
            },
        },
    )

    elastic = _section(golden, "elastic")
    clusters = elastic.get("clusters") if isinstance(elastic.get("clusters"), list) else []
    if not clusters:
        raise SystemExit("Golden config has no Elastic cluster")
    cluster = clusters[0]
    client.request(
        "POST",
        "/api/setup/steps/siem",
        {
            "action": "save",
            "values": {
                "id": cluster.get("id"),
                "name": cluster.get("name"),
                "base_url": cluster.get("base_url"),
                "api_key": cluster.get("api_key") or "",
                "username": cluster.get("username") or "",
                "password": cluster.get("password") or "",
                "kibana_url": cluster.get("kibana_url") or "",
            },
        },
    )
    client.request("POST", "/api/setup/steps/cases", {"action": "skip", "values": {}})
    client.request("POST", "/api/setup/steps/edr", {"action": "skip", "values": {}})

    cti = _section(golden, "cti")
    client.request(
        "POST",
        "/api/setup/steps/cti",
        {"action": "save", "values": {"base_url": cti.get("base_url") or "", "use_opencti": False}},
    )

    netbox = _section(golden, "netbox")
    flags = str((clusters[0] or {}).get("skill_vector") or "")
    kb_on = "/KB:Y" in flags or flags.endswith("KB:Y")
    client.request(
        "POST",
        "/api/setup/steps/knowledge",
        {
            "action": "save",
            "values": {
                "kb": kb_on,
                "base_url": netbox.get("base_url") or "",
                "api_token": netbox.get("api_token") or "",
            },
        },
    )

    eng = _section(golden, "eng")
    github = eng.get("github") if isinstance(eng.get("github"), dict) else {}
    client.request(
        "POST",
        "/api/setup/steps/eng",
        {
            "action": "save",
            "values": {
                "provider": eng.get("provider") or "github",
                "api_token": github.get("api_token") or "",
                "repository": github.get("repository") or "",
                "fine_tuning_label": github.get("fine_tuning_label") or "fine-tuning",
                "visibility_label": github.get("visibility_label") or "visibility",
            },
        },
    )

    llm = _section(golden, "llm")
    openwebui = llm.get("openwebui") if isinstance(llm.get("openwebui"), dict) else {}
    mcp = _section(golden, "mcp")
    client.request(
        "POST",
        "/api/setup/steps/ai",
        {
            "action": "save",
            "values": {
                "provider": llm.get("provider") or "openwebui",
                "base_url": openwebui.get("base_url") or "",
                "api_key": openwebui.get("api_key") or "",
                "model": openwebui.get("model") or "auto",
                "enabled": mcp.get("enabled", True),
                "auto_start": mcp.get("auto_start", True),
                "port": mcp.get("port") or 8082,
                "tls": bool(mcp.get("tls", False)),
                "public_url": mcp.get("public_url") or "",
                "mcp_api_token": mcp.get("api_token") or "",
                "default_skill_vector": elastic.get("default_skill_vector") or "",
            },
        },
    )
    client.request("POST", "/api/setup/complete", {})


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Drive the Onboarding setup wizard")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--golden", required=True)
    parser.add_argument("--example", required=True)
    args = parser.parse_args(argv)
    golden = json.loads(Path(args.golden).read_text(encoding="utf-8"))
    example = json.loads(Path(args.example).read_text(encoding="utf-8"))
    drive(WizardClient(args.base_url), golden)
    compare(container_config(), golden, example)
    print("Wizard config matches the golden integration settings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
