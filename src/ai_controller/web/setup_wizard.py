"""Server-driven setup wizard.

The schema is the only definition of steps, fields, and branch rules. The
page renders it. The onboarding test posts the same step endpoints.
"""

from __future__ import annotations

import copy
import json
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ...core.config_storage import (
    get_section,
    save_raw_config,
    update_raw_section,
)
from ...core.elastic_clusters import (
    ElasticClusterRegistry,
    save_registry,
    slugify_cluster_id,
)
from ...core.secrets import is_masked_secret, mask_secret
from ...core.skill_vector import SOLUTION_ORDER, SkillVector, canonicalize
from .auth import (
    WEAK_PASSWORD_VALUES,
    apply_credentials,
    get_auth,
    hash_password,
    is_password_hash,
)

TIP_REPO = "https://github.com/M507/tip"
OPENWEBUI_MCP_ID = "samigpt-mcp"
MCP_HOST = "0.0.0.0"

STEP_ORDER: Tuple[str, ...] = (
    "welcome",
    "security",
    "siem",
    "cases",
    "edr",
    "cti",
    "knowledge",
    "eng",
    "ai",
    "review",
    "done",
)

# Sections a skip restores from config.json.example.
SKIP_SECTIONS = {
    "siem": ("elastic",),
    "cases": ("iris", "thehive"),
    "edr": ("edr",),
    "cti": ("cti", "cti_opencti"),
    "knowledge": ("netbox",),
    "eng": ("eng",),
    "ai": ("llm", "mcp"),
}


def example_config() -> Dict[str, Any]:
    from ...core import config_storage

    path = Path(config_storage.STARTING_CONFIG_FILE)
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, dict) else {}


def example_section(name: str) -> Any:
    value = example_config().get(name)
    return copy.deepcopy(value) if value is not None else None


def _progress() -> Dict[str, Any]:
    stored = get_section("setup", {})
    choices = stored.get("choices") if isinstance(stored.get("choices"), dict) else {}
    skipped = stored.get("skipped") if isinstance(stored.get("skipped"), list) else []
    return {
        "completed": bool(stored.get("completed")),
        "skipped": [str(item) for item in skipped],
        "choices": dict(choices),
    }


def _write_progress(progress: Dict[str, Any]) -> None:
    current = get_section("setup", {})
    current["completed"] = bool(progress.get("completed"))
    current["skipped"] = list(progress.get("skipped") or [])
    current["choices"] = dict(progress.get("choices") or {})
    update_raw_section("setup", current)


def _mark(step_id: str, choice_patch: Dict[str, Any], skipped: bool) -> Dict[str, Any]:
    progress = _progress()
    choices = progress["choices"]
    choices.update(choice_patch)
    progress["choices"] = choices
    names = [item for item in progress["skipped"] if item != step_id]
    if skipped:
        names.append(step_id)
    progress["skipped"] = names
    _write_progress(progress)
    return progress


def is_placeholder(value: Any) -> bool:
    text = str(value or "").strip()
    if not text:
        return True
    lower = text.lower()
    if "example.com" in lower or lower.startswith("your-") or "replace_with" in lower:
        return True
    return False


def _blank_placeholder(value: Any) -> str:
    text = str(value or "").strip()
    if is_placeholder(text):
        return ""
    return text


def _keep_secret(incoming: Any, existing: Any) -> str:
    """Keep a real stored secret when the form sends a blank or a mask."""
    text = str(incoming or "").strip()
    if text and not is_masked_secret(text) and not is_placeholder(text):
        return text
    stored = str(existing or "").strip()
    if stored and not is_placeholder(stored):
        return stored
    return ""


def cluster_flags(choices: Dict[str, Any]) -> Dict[str, bool]:
    """Skill flags implied by wizard choices. Elastic cases stay under SIEM."""
    case = choices.get("case") or "skip"
    eng = choices.get("eng") or "skip"
    return {
        "IRIS": case == "iris",
        "TH": case == "thehive",
        "SIEM": choices.get("siem") == "elastic",
        "EDR": False,
        "CTI": choices.get("cti") == "local_tip" or bool(choices.get("opencti")),
        "KB": bool(choices.get("kb")),
        "NB": bool(choices.get("netbox")),
        "ENG": eng in {"github", "clickup", "trello"},
        "RB": True,
        "AG": False,
        "RU": True,
    }


def encode_flags(flags: Dict[str, bool]) -> str:
    vector = SkillVector()
    for code in SOLUTION_ORDER:
        vector.set_solution(code, bool(flags.get(code)))
    return vector.encode()


def derive_cluster_vector(choices: Optional[Dict[str, Any]] = None) -> str:
    return encode_flags(cluster_flags(choices if choices is not None else _progress()["choices"]))


def derive_default_vector(choices: Optional[Dict[str, Any]] = None) -> str:
    choices = choices if choices is not None else _progress()["choices"]
    explicit = str(choices.get("default_skill_vector") or "").strip()
    if explicit:
        return canonicalize(explicit, strict=True)
    return derive_cluster_vector(choices)


def _restore(name: str) -> None:
    section = example_section(name)
    if section is None:
        return
    update_raw_section(name, section)


def ensure_mcp_host() -> None:
    """The listener always binds every interface. Host is not a wizard field."""
    current = get_section("mcp", {})
    if not current:
        restored = example_section("mcp")
        current = restored if isinstance(restored, dict) else {}
    current["host"] = MCP_HOST
    update_raw_section("mcp", current)


def refresh_skill_vectors() -> None:
    """Rewrite cluster and future-cluster vectors from the saved choices."""
    raw = get_section("elastic", {})
    clusters = raw.get("clusters") if isinstance(raw.get("clusters"), list) else []
    if not clusters:
        return
    choices = _progress()["choices"]
    if choices.get("siem") != "elastic":
        return
    derived = derive_cluster_vector(choices)
    default_vector = derive_default_vector(choices)
    locks = choices.get("cluster_skill_locks") if isinstance(choices.get("cluster_skill_locks"), dict) else {}
    normalized: List[Dict[str, Any]] = []
    for cluster in clusters:
        if not isinstance(cluster, dict):
            continue
        item = dict(cluster)
        locked = str(locks.get(item.get("id")) or "").strip()
        item["skill_vector"] = canonicalize(locked, strict=True) if locked else derived
        item["verify_ssl"] = False
        item["kibana_url"] = str(item.get("kibana_url") or "")
        normalized.append(item)
    registry = ElasticClusterRegistry(
        default_cluster_id=str(raw.get("default_cluster_id") or normalized[0].get("id") or ""),
        default_skill_vector=default_vector,
        clusters=[],
    )
    from ...core.elastic_clusters import _normalize_cluster

    registry.clusters = [_normalize_cluster(item) for item in normalized]
    save_registry(registry)


def _next_step(step_id: str) -> str:
    index = STEP_ORDER.index(step_id)
    if index + 1 < len(STEP_ORDER):
        return STEP_ORDER[index + 1]
    return step_id


def _error(errors: Dict[str, str]) -> Dict[str, Any]:
    return {"success": False, "errors": errors}


def _ok(step_id: str) -> Dict[str, Any]:
    return {"success": True, "step": step_id, "next_step": _next_step(step_id)}


def apply_step(step_id: str, action: str, values: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Validate and persist one wizard step. ``action`` is save, skip, or next."""
    if step_id not in STEP_ORDER:
        return _error({"step": "Unknown setup step."})
    action = (action or "save").strip().lower()
    values = dict(values or {})
    if action not in {"save", "skip", "next"}:
        return _error({"action": "Use save, skip, or next."})
    handler = _HANDLERS.get(step_id)
    if handler is None:
        return _error({"step": "This step cannot be saved."})
    if action == "skip" and step_id in {"welcome", "security", "review", "done"}:
        return _error({"action": "This step cannot be skipped."})
    result = handler(action, values)
    if result.get("success") and step_id not in {"welcome", "done"}:
        if _progress()["choices"].get("siem") == "elastic":
            refresh_skill_vectors()
        if step_id in {"ai", "review"}:
            ensure_mcp_host()
    return result


def _save_welcome(action: str, _values: Dict[str, Any]) -> Dict[str, Any]:
    _mark("welcome", {}, skipped=False)
    return _ok("welcome")


def _save_security(action: str, values: Dict[str, Any]) -> Dict[str, Any]:
    raw = get_section("web", {})
    username = str(values.get("username") or raw.get("username") or "admin").strip()
    password = str(values.get("password") or "")
    confirm = str(values.get("confirm_password") or "")
    errors: Dict[str, str] = {}
    if not username:
        errors["username"] = "Username is required."
    already = is_password_hash(str(raw.get("password") or ""))
    if password or confirm or not already:
        if password != confirm:
            errors["confirm_password"] = "Confirmation does not match the password."
        if password.strip().lower() in WEAK_PASSWORD_VALUES or not password.strip():
            errors["password"] = "Choose a password that is not a well-known default."
    ttl_raw = values.get("session_ttl_seconds", raw.get("session_ttl_seconds") or 43200)
    try:
        ttl = int(ttl_raw)
    except (TypeError, ValueError):
        ttl = 0
    if ttl < 300:
        errors["session_ttl_seconds"] = "Session length must be at least 300 seconds."
    if errors:
        return _error(errors)

    stored_hash = str(raw.get("password") or "")
    if password:
        stored_hash = hash_password(password)
    elif not is_password_hash(stored_hash):
        return _error({"password": "Password is required."})

    auth = get_auth()
    secret = (raw.get("session_secret") or auth.config.session_secret or "").strip()
    if secret in {"", "changeme"} or len(secret) < 32:
        secret = secrets.token_urlsafe(48)
    persisted = dict(raw)
    persisted["username"] = username
    persisted["password"] = stored_hash
    persisted["session_secret"] = secret
    persisted["session_ttl_seconds"] = ttl
    update_raw_section("web", persisted)
    from .auth import WebAuthConfig

    auth.config = WebAuthConfig(
        username=username,
        password=stored_hash,
        session_secret=secret,
        session_ttl_seconds=max(ttl, 300),
        cookie_secure=auth.config.cookie_secure,
    )
    apply_credentials(username, stored_hash)
    _mark("security", {"security": "set"}, skipped=False)
    result = _ok("security")
    result["session"] = True
    result["username"] = username
    return result


def _cluster_from_values(values: Dict[str, Any], existing: Optional[Dict[str, Any]], skill_vector: str) -> Dict[str, Any]:
    name = str(values.get("name") or (existing or {}).get("name") or "").strip()
    base_url = str(values.get("base_url") or "").strip().rstrip("/")
    cluster_id = str(values.get("id") or (existing or {}).get("id") or "").strip() or slugify_cluster_id(name or base_url)
    api_key = _keep_secret(values.get("api_key"), (existing or {}).get("api_key"))
    username = _keep_secret(values.get("username"), (existing or {}).get("username"))
    password = _keep_secret(values.get("password"), (existing or {}).get("password"))
    kibana = str(values.get("kibana_url") or "").strip().rstrip("/")
    timeout = (existing or {}).get("timeout_seconds") or 30
    return {
        "id": cluster_id,
        "name": name or cluster_id,
        "base_url": base_url,
        "api_key": api_key,
        "username": username if username else "",
        "password": password if password else "",
        "timeout_seconds": int(timeout),
        "verify_ssl": False,
        "skill_vector": skill_vector,
        "kibana_url": kibana,
    }


def _validate_cluster(cluster: Dict[str, Any], prefix: str = "") -> Dict[str, str]:
    errors: Dict[str, str] = {}
    key = f"{prefix}base_url" if prefix else "base_url"
    if not cluster.get("base_url"):
        errors[key] = "Elastic URL is required."
    auth_key = f"{prefix}api_key" if prefix else "api_key"
    if not cluster.get("api_key") and not (cluster.get("username") and cluster.get("password")):
        errors[auth_key] = "Provide an API key, or a username and password."
    return errors


def _existing_primary() -> Optional[Dict[str, Any]]:
    clusters = get_section("elastic", {}).get("clusters")
    if isinstance(clusters, list):
        for cluster in clusters:
            if isinstance(cluster, dict) and not is_placeholder(cluster.get("base_url")):
                return cluster
    return None


def _save_siem(action: str, values: Dict[str, Any]) -> Dict[str, Any]:
    if action == "skip":
        _restore("elastic")
        _mark("siem", {"siem": "skip", "cluster_skill_locks": {}}, skipped=True)
        return _ok("siem")
    existing = _existing_primary()
    derived = derive_cluster_vector({**_progress()["choices"], "siem": "elastic"})
    primary = _cluster_from_values(values, existing, derived)
    errors = _validate_cluster(primary)
    extras: List[Dict[str, Any]] = []
    extra_url = str(values.get("extra_base_url") or "").strip()
    locks: Dict[str, str] = {}
    if extra_url:
        extra_values = {
            "id": values.get("extra_id"),
            "name": values.get("extra_name"),
            "base_url": extra_url,
            "api_key": values.get("extra_api_key"),
            "username": values.get("extra_username"),
            "password": values.get("extra_password"),
            "kibana_url": values.get("extra_kibana_url"),
        }
        extra = _cluster_from_values(extra_values, None, derived)
        errors.update(_validate_cluster(extra, prefix="extra_"))
        custom = str(values.get("extra_skill_vector") or "").strip()
        if custom:
            try:
                locks[extra["id"]] = canonicalize(custom, strict=True)
                extra["skill_vector"] = locks[extra["id"]]
            except ValueError as exc:
                errors["extra_skill_vector"] = str(exc)
        extras.append(extra)
    if errors:
        return _error(errors)
    explicit_default = str(_progress()["choices"].get("default_skill_vector") or "").strip()
    default_vector = canonicalize(explicit_default, strict=True) if explicit_default else derived
    from ...core.elastic_clusters import _normalize_cluster

    registry = ElasticClusterRegistry(
        default_cluster_id=primary["id"],
        default_skill_vector=default_vector,
        clusters=[_normalize_cluster(item) for item in [primary, *extras]],
    )
    save_registry(registry)
    _mark(
        "siem",
        {"siem": "elastic", "cluster_skill_locks": locks},
        skipped=False,
    )
    return _ok("siem")


def _save_cases(action: str, values: Dict[str, Any]) -> Dict[str, Any]:
    if action == "skip":
        _restore("iris")
        _restore("thehive")
        _mark("cases", {"case": "skip"}, skipped=True)
        return _ok("cases")
    mode = str(values.get("mode") or "elastic").strip().lower()
    if mode not in {"elastic", "iris", "thehive"}:
        return _error({"mode": "Choose Elastic cases, IRIS, or TheHive."})
    if mode == "elastic":
        _restore("iris")
        _restore("thehive")
        _mark("cases", {"case": "elastic"}, skipped=False)
        return _ok("cases")
    url = str(values.get("base_url") or "").strip().rstrip("/")
    current = get_section("iris" if mode == "iris" else "thehive", {})
    api_key = _keep_secret(values.get("api_key"), current.get("api_key"))
    errors: Dict[str, str] = {}
    if not url:
        errors["base_url"] = "URL is required."
    if not api_key:
        errors["api_key"] = "API key is required."
    if errors:
        return _error(errors)
    if mode == "iris":
        update_raw_section(
            "iris",
            {"base_url": url, "api_key": api_key, "timeout_seconds": 30, "verify_ssl": True},
        )
        _restore("thehive")
    else:
        update_raw_section(
            "thehive",
            {"base_url": url, "api_key": api_key, "timeout_seconds": 30},
        )
        _restore("iris")
    _mark("cases", {"case": mode}, skipped=False)
    return _ok("cases")


def _save_edr(action: str, _values: Dict[str, Any]) -> Dict[str, Any]:
    # Velociraptor is not a connected client. Every path keeps the example section.
    _restore("edr")
    _mark("edr", {"edr": "skip"}, skipped=True)
    return _ok("edr")


def _save_cti(action: str, values: Dict[str, Any]) -> Dict[str, Any]:
    use_opencti = str(values.get("use_opencti") or "").lower() in {"1", "true", "yes", "on"}
    if action == "skip":
        _restore("cti")
        _restore("cti_opencti")
        _mark("cti", {"cti": "skip", "opencti": False}, skipped=True)
        return _ok("cti")
    url = str(values.get("base_url") or "").strip().rstrip("/")
    errors: Dict[str, str] = {}
    if not url:
        errors["base_url"] = "TIP URL is required, or skip this step."
    opencti_url = str(values.get("opencti_base_url") or "").strip().rstrip("/")
    current_open = get_section("cti_opencti", {})
    opencti_key = _keep_secret(values.get("opencti_api_key"), current_open.get("api_key"))
    if use_opencti:
        if not opencti_url:
            errors["opencti_base_url"] = "OpenCTI URL is required."
        if not opencti_key:
            errors["opencti_api_key"] = "OpenCTI API key is required."
    if errors:
        return _error(errors)
    example = example_section("cti") if isinstance(example_section("cti"), dict) else {}
    section = dict(example)
    section["cti_type"] = "local_tip"
    section["base_url"] = url
    section["timeout_seconds"] = int(section.get("timeout_seconds") or 30)
    section["verify_ssl"] = False
    section.pop("api_key", None)
    update_raw_section("cti", section)
    if use_opencti:
        block = example_section("cti_opencti")
        open_section = dict(block) if isinstance(block, dict) else {}
        open_section["cti_type"] = "opencti"
        open_section["base_url"] = opencti_url
        open_section["api_key"] = opencti_key
        open_section["timeout_seconds"] = int(open_section.get("timeout_seconds") or 30)
        open_section["verify_ssl"] = False
        update_raw_section("cti_opencti", open_section)
    else:
        _restore("cti_opencti")
    _mark("cti", {"cti": "local_tip", "opencti": use_opencti}, skipped=False)
    return _ok("cti")


def _save_knowledge(action: str, values: Dict[str, Any]) -> Dict[str, Any]:
    if action == "skip":
        _restore("netbox")
        _mark("knowledge", {"kb": False, "netbox": False}, skipped=True)
        return _ok("knowledge")
    kb = str(values.get("kb") or "").lower() in {"1", "true", "yes", "on"}
    url = str(values.get("base_url") or "").strip().rstrip("/")
    current = get_section("netbox", {})
    token = _keep_secret(values.get("api_token"), current.get("api_token"))
    if not url and not token:
        _restore("netbox")
        _mark("knowledge", {"kb": kb, "netbox": False}, skipped=False)
        return _ok("knowledge")
    errors: Dict[str, str] = {}
    if not url:
        errors["base_url"] = "NetBox URL is required."
    if not token:
        errors["api_token"] = "NetBox token is required."
    if errors:
        return _error(errors)
    example = example_section("netbox")
    section = dict(example) if isinstance(example, dict) else {}
    section["base_url"] = url
    section["api_token"] = token
    section["timeout_seconds"] = int(section.get("timeout_seconds") or 30)
    section["verify_ssl"] = False
    update_raw_section("netbox", section)
    _mark("knowledge", {"kb": kb, "netbox": True}, skipped=False)
    return _ok("knowledge")


def _save_eng(action: str, values: Dict[str, Any]) -> Dict[str, Any]:
    if action == "skip":
        _restore("eng")
        _mark("eng", {"eng": "skip"}, skipped=True)
        return _ok("eng")
    provider = str(values.get("provider") or "github").strip().lower()
    if provider not in {"github", "clickup", "trello"}:
        return _error({"provider": "Choose GitHub Issues, ClickUp, or Trello."})
    example = example_section("eng")
    section = dict(example) if isinstance(example, dict) else {}
    errors: Dict[str, str] = {}
    if provider == "github":
        current = section.get("github") if isinstance(section.get("github"), dict) else {}
        stored = get_section("eng", {}).get("github") if isinstance(get_section("eng", {}).get("github"), dict) else {}
        token = _keep_secret(values.get("api_token"), stored.get("api_token"))
        repository = str(values.get("repository") or "").strip()
        if not token:
            errors["api_token"] = "GitHub token is required."
        if repository.count("/") != 1 and "github.com/" not in repository.lower():
            errors["repository"] = "Repository must be owner/repo."
        if errors:
            return _error(errors)
        github = dict(current)
        github["api_token"] = token
        github["repository"] = repository
        github["fine_tuning_label"] = str(values.get("fine_tuning_label") or "fine-tuning").strip() or "fine-tuning"
        github["visibility_label"] = str(values.get("visibility_label") or "visibility").strip() or "visibility"
        github["timeout_seconds"] = int(github.get("timeout_seconds") or 30)
        github["verify_ssl"] = True
        section["github"] = github
        for name in ("trello", "clickup"):
            if name in (example or {}):
                section[name] = copy.deepcopy(example[name])
    elif provider == "clickup":
        stored = get_section("eng", {}).get("clickup") if isinstance(get_section("eng", {}).get("clickup"), dict) else {}
        token = _keep_secret(values.get("api_token"), stored.get("api_token"))
        fine_id = str(values.get("fine_tuning_list_id") or "").strip()
        eng_id = str(values.get("engineering_list_id") or "").strip()
        if not token:
            errors["api_token"] = "ClickUp token is required."
        if not fine_id:
            errors["fine_tuning_list_id"] = "Fine-tuning list id is required."
        if not eng_id:
            errors["engineering_list_id"] = "Engineering list id is required."
        if errors:
            return _error(errors)
        block = dict(section.get("clickup") or {})
        block.update(
            {
                "api_token": token,
                "fine_tuning_list_id": fine_id,
                "engineering_list_id": eng_id,
                "timeout_seconds": int(block.get("timeout_seconds") or 30),
                "verify_ssl": True,
            }
        )
        section["clickup"] = block
        for name in ("trello", "github"):
            if isinstance(example, dict) and name in example:
                section[name] = copy.deepcopy(example[name])
    else:
        stored = get_section("eng", {}).get("trello") if isinstance(get_section("eng", {}).get("trello"), dict) else {}
        api_key = _keep_secret(values.get("api_key"), stored.get("api_key"))
        api_token = _keep_secret(values.get("api_token"), stored.get("api_token"))
        fine_board = str(values.get("fine_tuning_board_id") or "").strip()
        eng_board = str(values.get("engineering_board_id") or "").strip()
        if not api_key:
            errors["api_key"] = "Trello API key is required."
        if not api_token:
            errors["api_token"] = "Trello token is required."
        if not fine_board:
            errors["fine_tuning_board_id"] = "Fine-tuning board id is required."
        if not eng_board:
            errors["engineering_board_id"] = "Engineering board id is required."
        if errors:
            return _error(errors)
        block = dict(section.get("trello") or {})
        block.update(
            {
                "api_key": api_key,
                "api_token": api_token,
                "fine_tuning_board_id": fine_board,
                "engineering_board_id": eng_board,
                "timeout_seconds": int(block.get("timeout_seconds") or 30),
                "verify_ssl": True,
            }
        )
        section["trello"] = block
        for name in ("clickup", "github"):
            if isinstance(example, dict) and name in example:
                section[name] = copy.deepcopy(example[name])
    section["provider"] = provider
    update_raw_section("eng", section)
    _mark("eng", {"eng": provider}, skipped=False)
    return _ok("eng")


def _save_ai(action: str, values: Dict[str, Any]) -> Dict[str, Any]:
    if action == "skip":
        _restore("llm")
        _restore("mcp")
        ensure_mcp_host()
        _mark("ai", {"ai": "skip"}, skipped=True)
        return _ok("ai")
    provider = str(values.get("provider") or "openwebui").strip().lower()
    if provider not in {"cursor_agent", "openai", "openrouter", "openwebui", "custom"}:
        return _error({"provider": "Choose a supported AI provider."})
    example = example_section("llm")
    llm = dict(example) if isinstance(example, dict) else {}
    llm["provider"] = provider
    block = dict(llm.get(provider) or {}) if isinstance(llm.get(provider), dict) else {}
    stored_llm = get_section("llm", {})
    stored_block = stored_llm.get(provider) if isinstance(stored_llm.get(provider), dict) else {}
    if provider != "cursor_agent":
        api_key = _keep_secret(values.get("api_key"), stored_block.get("api_key") or block.get("api_key"))
        base_url = str(values.get("base_url") or block.get("base_url") or "").strip().rstrip("/")
        model = str(values.get("model") or "").strip()
        if provider == "openwebui" and not model:
            model = "auto"
        errors: Dict[str, str] = {}
        if not api_key and provider != "custom":
            errors["api_key"] = "API token is required."
        if not base_url:
            errors["base_url"] = "API URL is required."
        if not model and provider != "custom":
            errors["model"] = "Choose a model, or type one."
        if errors:
            return _error(errors)
        block["api_key"] = api_key
        block["base_url"] = base_url
        block["model"] = model
        if provider == "openwebui":
            block["mcp_server_id"] = OPENWEBUI_MCP_ID
        llm[provider] = block
    else:
        block["binary_path"] = str(values.get("binary_path") or block.get("binary_path") or "")
        llm[provider] = block
    update_raw_section("llm", llm)

    mcp_example = example_section("mcp")
    mcp = dict(mcp_example) if isinstance(mcp_example, dict) else {}
    stored_mcp = get_section("mcp", {})
    token = _keep_secret(values.get("mcp_api_token"), stored_mcp.get("api_token"))
    if not token:
        token = secrets.token_urlsafe(32)
    try:
        port = int(values.get("port") or mcp.get("port") or 8082)
    except (TypeError, ValueError):
        return _error({"port": "MCP port must be a number."})
    if port < 1 or port > 65535:
        return _error({"port": "MCP port must be between 1 and 65535."})
    tls_raw = values.get("tls", False)
    tls = str(tls_raw).lower() in {"1", "true", "yes", "on"} if not isinstance(tls_raw, bool) else tls_raw
    enabled_raw = values.get("enabled", True)
    enabled = str(enabled_raw).lower() in {"1", "true", "yes", "on"} if not isinstance(enabled_raw, bool) else bool(enabled_raw)
    auto_raw = values.get("auto_start", True)
    auto_start = str(auto_raw).lower() in {"1", "true", "yes", "on"} if not isinstance(auto_raw, bool) else bool(auto_raw)
    public_url = str(values.get("public_url") or "").strip()
    mcp.update(
        {
            "enabled": enabled,
            "auto_start": auto_start,
            "host": MCP_HOST,
            "port": port,
            "tls": tls,
            "public_url": public_url,
            "api_token": token,
        }
    )
    update_raw_section("mcp", mcp)
    explicit_default = str(values.get("default_skill_vector") or "").strip()
    if explicit_default:
        try:
            explicit_default = canonicalize(explicit_default, strict=True)
        except ValueError as exc:
            return _error({"default_skill_vector": str(exc)})
    _mark("ai", {"ai": provider, "default_skill_vector": explicit_default}, skipped=False)
    return _ok("ai")


def _save_review(action: str, _values: Dict[str, Any]) -> Dict[str, Any]:
    progress = _progress()
    progress["completed"] = True
    _write_progress(progress)
    if progress["choices"].get("siem") == "elastic":
        refresh_skill_vectors()
    ensure_mcp_host()
    return _ok("review")


def _save_done(action: str, _values: Dict[str, Any]) -> Dict[str, Any]:
    return _ok("done")


_HANDLERS = {
    "welcome": _save_welcome,
    "security": _save_security,
    "siem": _save_siem,
    "cases": _save_cases,
    "edr": _save_edr,
    "cti": _save_cti,
    "knowledge": _save_knowledge,
    "eng": _save_eng,
    "ai": _save_ai,
    "review": _save_review,
    "done": _save_done,
}


def _field(name: str, label: str, kind: str = "text", **extra: Any) -> Dict[str, Any]:
    payload = {"name": name, "label": label, "type": kind}
    payload.update(extra)
    return payload


def _choice(value: str, label: str, **extra: Any) -> Dict[str, Any]:
    payload = {"value": value, "label": label}
    payload.update(extra)
    return payload


def build_schema() -> Dict[str, Any]:
    """Steps, fields, and notices for the current config. Secrets are masked."""
    progress = _progress()
    choices = progress["choices"]
    web = get_section("web", {})
    elastic = get_section("elastic", {})
    clusters = elastic.get("clusters") if isinstance(elastic.get("clusters"), list) else []
    primary = {}
    for item in clusters:
        if isinstance(item, dict) and not is_placeholder(item.get("base_url")):
            primary = item
            break
    cti = get_section("cti", {})
    netbox = get_section("netbox", {})
    eng = get_section("eng", {})
    github = eng.get("github") if isinstance(eng.get("github"), dict) else {}
    llm = get_section("llm", {})
    provider = str(choices.get("ai") or llm.get("provider") or "openwebui")
    provider_block = llm.get(provider) if isinstance(llm.get(provider), dict) else {}
    mcp = get_section("mcp", {})
    siem_on = choices.get("siem") == "elastic"
    flags = cluster_flags(choices if choices.get("siem") else {**choices, "siem": "elastic" if siem_on else choices.get("siem")})
    if choices.get("siem") != "elastic":
        flags = cluster_flags(choices)
    summary_vector = derive_cluster_vector(choices) if choices.get("siem") == "elastic" else ""

    steps: List[Dict[str, Any]] = [
        {
            "id": "welcome",
            "title": "Welcome",
            "why": "Connect the tools this SOC already uses. Anything you skip stays at its starting placeholder and is not treated as connected.",
            "skippable": False,
            "fields": [],
            "notices": [
                {"tone": "info", "text": "You will set the console password first. After that, each integration is optional."},
            ],
        },
        {
            "id": "security",
            "title": "Security",
            "why": "The console is HTTPS-only and rejects every request without a session. The password is stored as an Argon2id hash. A session secret is generated for you.",
            "skippable": False,
            "fields": [
                _field("username", "Username", value=str(web.get("username") or "admin"), required=True),
                _field("password", "Password", "password", required=not is_password_hash(str(web.get("password") or "")), autocomplete="new-password"),
                _field("confirm_password", "Confirm password", "password", required=not is_password_hash(str(web.get("password") or "")), autocomplete="new-password"),
                _field(
                    "session_ttl_seconds",
                    "Session length (seconds)",
                    "number",
                    value=int(web.get("session_ttl_seconds") or 43200),
                    advanced=True,
                    help="Default is 12 hours.",
                ),
            ],
            "notices": [
                {"tone": "info", "text": "A self-signed certificate is written under certs/ the first time the app starts. The browser warning is expected."},
                {
                    "tone": "info",
                    "text": "A session secret is already in place." if len(str(web.get("session_secret") or "")) >= 32 else "A session secret will be generated when you save this step.",
                },
            ],
        },
        {
            "id": "siem",
            "title": "SIEM",
            "why": "Elastic is the SIEM this product talks to. Alerts, searches, and Elastic Security cases use this cluster.",
            "skippable": True,
            "fields": [
                _field("name", "Cluster name", value=_blank_placeholder(primary.get("name")) or "Lab Elasticsearch"),
                _field("id", "Cluster id", value=_blank_placeholder(primary.get("id")), help="Sessions bind to this id."),
                _field("base_url", "Elasticsearch URL", value=_blank_placeholder(primary.get("base_url")), required=True, placeholder="https://host:9200"),
                _field("api_key", "API key", "password", value=_display_secret(primary.get("api_key")), help="Or use a username and password instead."),
                _field("username", "Username", value=_blank_placeholder(primary.get("username")), advanced=True),
                _field("password", "Password", "password", value=_display_secret(primary.get("password")), advanced=True),
                _field("kibana_url", "Kibana URL", value=_blank_placeholder(primary.get("kibana_url")), advanced=True, help="Leave blank to keep it empty. Cases map port 9200 to 5601 when needed."),
                _field("extra_name", "Second cluster name", advanced=True),
                _field("extra_id", "Second cluster id", advanced=True),
                _field("extra_base_url", "Second cluster URL", advanced=True),
                _field("extra_api_key", "Second cluster API key", "password", advanced=True),
                _field("extra_skill_vector", "Second cluster skill vector", advanced=True, help="Leave blank to use the same skills as the first cluster."),
            ],
            "notices": [
                {"tone": "info", "text": "Certificate checks for this cluster are left off, so HTTP and internal certificates work. You can turn them on later in Settings."},
            ],
        },
        {
            "id": "cases",
            "title": "Case management",
            "why": "Investigations need a place to keep the case. If Elastic is connected, its Security cases are used and no extra token is required.",
            "skippable": True,
            "fields": [
                _field(
                    "mode",
                    "Where cases go",
                    "choice",
                    value=str(choices.get("case") or ("elastic" if siem_on else "skip")),
                    options=[
                        _choice("elastic", "Elastic Security cases", help="Recommended when Elastic is the SIEM. No extra token.", requires_siem=True),
                        _choice("iris", "IRIS", beta=True, help="Beta. IRIS is preferred when both IRIS and TheHive are filled in."),
                        _choice("thehive", "TheHive", advanced=True, help="Already built. Used only when IRIS is not configured."),
                    ],
                ),
                _field("base_url", "URL", when={"mode": ["iris", "thehive"]}, placeholder="https://cases.example.com"),
                _field("api_key", "API key", "password", when={"mode": ["iris", "thehive"]}),
            ],
            "notices": [
                {"tone": "info", "text": "Elastic Security cases are already available for this cluster."} if siem_on else {"tone": "info", "text": "Connect Elastic on the SIEM step to use its case management without another token."},
            ],
        },
        {
            "id": "edr",
            "title": "EDR",
            "why": "Endpoint isolation and release already go through Elastic Defend on the SIEM cluster. Velociraptor is still beta and is not connected.",
            "skippable": True,
            "beta": True,
            "fields": [],
            "notices": [
                {"tone": "info", "text": "Elastic Defend isolation and release are already covered by the Elastic cluster. No separate EDR token is required."} if siem_on else {"tone": "info", "text": "Without Elastic, endpoint isolation is not available yet."},
                {"tone": "beta", "text": "Velociraptor is still beta. Skipping keeps the starting placeholder and does not turn the EDR skill on."},
            ],
        },
        {
            "id": "cti",
            "title": "Threat intel",
            "why": "Hash lookups use a custom local TIP. It includes VirusTotal, Hybrid Analysis, and the TIP's local database.",
            "skippable": True,
            "fields": [
                _field("base_url", "TIP URL", value=_blank_placeholder(cti.get("base_url")) if choices.get("cti") == "local_tip" else "", required=True, placeholder="http://tip-host:8084"),
                _field("use_opencti", "Also query OpenCTI", "checkbox", advanced=True, beta=True, help="Beta. Queried together with the local TIP."),
                _field("opencti_base_url", "OpenCTI URL", when={"use_opencti": True}, advanced=True),
                _field("opencti_api_key", "OpenCTI API key", "password", when={"use_opencti": True}, advanced=True),
            ],
            "notices": [
                {"tone": "info", "text": f"The TIP is custom. Download it from {TIP_REPO}."},
                {"tone": "info", "text": "Certificate checks for the TIP are left off."},
            ],
        },
        {
            "id": "knowledge",
            "title": "Knowledge and assets",
            "why": "The knowledge base is local notes for customers (client folders). NetBox is one asset inventory for the install. The NB skill turns it on for this cluster.",
            "skippable": True,
            "fields": [
                _field("kb", "Enable the knowledge base for this cluster", "checkbox", value=bool(choices.get("kb")), help="KB is shared client folders, not a token. Use it when investigations need a customer's subnets, servers, or users. It can differ per Elastic cluster."),
                _field("base_url", "NetBox URL", value=_blank_placeholder(netbox.get("base_url")) if choices.get("netbox") else "", placeholder="http://netbox-host:8851"),
                _field("api_token", "NetBox token", "password", value=_display_secret(netbox.get("api_token")) if choices.get("netbox") else ""),
            ],
            "notices": [
                {"tone": "info", "text": "NetBox credentials are one instance. Which cluster may look up assets is the NB skill on that cluster. Certificate checks for NetBox are left off."},
            ],
        },
        {
            "id": "eng",
            "title": "Engineering tickets",
            "why": "Fine-tune, visibility, and runbook notes are filed as tickets. GitHub creates issues in one repo. ClickUp and Trello are beta and work.",
            "skippable": True,
            "fields": [
                _field(
                    "provider",
                    "Where tickets go",
                    "choice",
                    value=str(choices.get("eng") or "github"),
                    options=[
                        _choice("github", "GitHub Issues", help="Asks for the owner/repo. Issues are split by the fine-tuning and visibility labels. Runbook notes use the label runbook."),
                        _choice("clickup", "ClickUp", beta=True),
                        _choice("trello", "Trello", beta=True),
                    ],
                ),
                _field("api_token", "Token", "password", when={"provider": ["github", "clickup", "trello"]}, value=_display_secret(github.get("api_token")) if choices.get("eng") == "github" else ""),
                _field("repository", "Issues repository", when={"provider": "github"}, value=_blank_placeholder(github.get("repository")), placeholder="owner/repo", help="owner/repo. New issues are created in this repository."),
                _field("fine_tuning_label", "Fine-tune label", when={"provider": "github"}, value=str(github.get("fine_tuning_label") or "fine-tuning"), advanced=True),
                _field("visibility_label", "Visibility label", when={"provider": "github"}, value=str(github.get("visibility_label") or "visibility"), advanced=True),
                _field("fine_tuning_list_id", "Fine-tune list id", when={"provider": "clickup"}),
                _field("engineering_list_id", "Engineering list id", when={"provider": "clickup"}),
                _field("api_key", "Trello API key", "password", when={"provider": "trello"}),
                _field("fine_tuning_board_id", "Fine-tune board id", when={"provider": "trello"}),
                _field("engineering_board_id", "Engineering board id", when={"provider": "trello"}),
            ],
            "notices": [
                {"tone": "info", "text": "Filing a new issue is enabled with the SIEM skills. The engineering skill turns on listing and commenting. GitHub Projects is not used."},
            ],
        },
        {
            "id": "ai",
            "title": "AI and MCP",
            "why": "The model answers investigations. MCP exposes the skills to that model. The listener always binds 0.0.0.0 so other hosts can reach it.",
            "skippable": True,
            "fields": [
                _field(
                    "provider",
                    "AI provider",
                    "choice",
                    value=provider if provider in {"cursor_agent", "openai", "openrouter", "openwebui", "custom"} else "openwebui",
                    options=[
                        _choice("openwebui", "Open WebUI"),
                        _choice("openai", "OpenAI"),
                        _choice("openrouter", "OpenRouter"),
                        _choice("custom", "OpenAI-compatible endpoint"),
                        _choice("cursor_agent", "Cursor agent on this host"),
                    ],
                ),
                _field("base_url", "API URL", when={"provider": ["openwebui", "openai", "openrouter", "custom"]}, value=_blank_placeholder(provider_block.get("base_url"))),
                _field("api_key", "API token", "password", when={"provider": ["openwebui", "openai", "openrouter", "custom"]}, value=_display_secret(provider_block.get("api_key"))),
                _field("model", "Model", "model", when={"provider": ["openwebui", "openai", "openrouter", "custom"]}, value=str(provider_block.get("model") or ("auto" if provider == "openwebui" else "")), help="Refresh loads the models this token can use. Open WebUI can stay on auto."),
                _field("binary_path", "Cursor binary path", when={"provider": "cursor_agent"}, advanced=True, help="Leave blank to use the binary on PATH."),
                _field("enabled", "Enable MCP", "checkbox", value=mcp.get("enabled", True) is not False),
                _field("auto_start", "Start MCP with the app", "checkbox", value=mcp.get("auto_start", True) is not False),
                _field("port", "MCP port", "number", value=int(mcp.get("port") or 8082)),
                _field("tls", "MCP TLS", "checkbox", value=bool(mcp.get("tls", False)), help="Leave off for an HTTP listener."),
                _field("public_url", "Public MCP URL", value=str(mcp.get("public_url") or ""), placeholder="http://host:8082/mcp", help="The URL the AI platform uses to reach this listener."),
                _field("mcp_api_token", "MCP bearer token", "password", value=_display_secret(mcp.get("api_token")), help="Leave blank to generate one. Open WebUI sends this as Authorization: Bearer."),
                _field("default_skill_vector", "Skills for future clusters", advanced=True, value=str(choices.get("default_skill_vector") or ""), help="Leave blank to copy this cluster's skills onto new clusters."),
            ],
            "notices": [
                {"tone": "info", "text": "MCP listens on 0.0.0.0. Host is not asked."},
                {"tone": "info", "text": f"Skills for this cluster: {summary_vector or 'set after a SIEM cluster is saved'}."},
                {"tone": "info", "text": "Register with Open WebUI is optional and calls that server. The test does not use it."},
            ],
            "actions": ["refresh_models", "register_openwebui"],
        },
        {
            "id": "review",
            "title": "Review",
            "why": "Confirm what will be saved. Skipped items stay at their starting placeholders.",
            "skippable": False,
            "fields": [],
            "notices": _review_notices(progress, summary_vector),
        },
        {
            "id": "done",
            "title": "You're set up",
            "why": "The console password works, and the choices above are in the config.",
            "skippable": False,
            "fields": [],
            "notices": [
                {"tone": "info", "text": "Open the dashboard and confirm the cluster and the MCP listener."},
                {"tone": "info", "text": "You can reopen Setup later to change any step."},
            ],
        },
    ]
    return {
        "success": True,
        "steps": steps,
        "order": list(STEP_ORDER),
        "completed": progress["completed"],
        "skipped": progress["skipped"],
        "choices": {key: value for key, value in choices.items() if key != "default_skill_vector" or not value},
        "skill_vector": summary_vector,
        "resume_step": _resume_step(progress),
        "tip_repo": TIP_REPO,
    }


def _review_notices(progress: Dict[str, Any], vector: str) -> List[Dict[str, str]]:
    skipped = set(progress["skipped"])
    lines = [
        {"tone": "info", "text": "The password is stored as a hash. The session secret was generated. The UI is HTTPS-only."},
        {"tone": "info", "text": "MCP listens on 0.0.0.0. The bearer token is masked after it is saved."},
    ]
    if vector:
        lines.append({"tone": "info", "text": f"Skill vector for this cluster: {vector}"})
    labels = {
        "siem": "SIEM",
        "cases": "extra case tools",
        "edr": "Velociraptor",
        "cti": "threat intel",
        "knowledge": "NetBox",
        "eng": "engineering tickets",
        "ai": "AI provider",
    }
    for step_id, label in labels.items():
        if step_id in skipped:
            lines.append({"tone": "info", "text": f"{label} skipped. The starting placeholder stays in the config."})
    return lines


def _resume_step(progress: Dict[str, Any]) -> str:
    if progress.get("completed"):
        return "done"
    seen = set(progress["skipped"]) | set(_seen_from_choices(progress["choices"]))
    if is_password_hash(str(get_section("web", {}).get("password") or "")):
        seen.add("security")
    if not seen:
        return "welcome"
    if "security" not in seen:
        return "security"
    for step_id in STEP_ORDER:
        if step_id in {"welcome", "review", "done"}:
            continue
        if step_id not in seen:
            return step_id
    return "review"


def _seen_from_choices(choices: Dict[str, Any]) -> List[str]:
    mapping = {
        "security": "security",
        "siem": "siem",
        "case": "cases",
        "edr": "edr",
        "cti": "cti",
        "kb": "knowledge",
        "netbox": "knowledge",
        "eng": "eng",
        "ai": "ai",
    }
    return [mapping[key] for key in choices if key in mapping]


def _display_secret(value: Any) -> str:
    text = str(value or "").strip()
    if is_placeholder(text):
        return ""
    return mask_secret(text)


def status_payload() -> Dict[str, Any]:
    progress = _progress()
    from .auth import setup_required

    return {
        "success": True,
        "setup_required": setup_required(),
        "completed": progress["completed"],
        "resume_step": _resume_step(progress),
    }


def replace_raw_config(data: Dict[str, Any]) -> None:
    """Test helper. Production steps use update_raw_section."""
    save_raw_config(data)
