"""
MCP Skill Vector (MSV) — CVSS-style enablement string.

Stored on each Elastic cluster (and as a default for new clusters):

    MSV:1/IRIS:Y/TH:Y/SIEM:Y/EDR:N/CTI:Y/KB:Y/NB:Y/ENG:N/RB:Y/AG:Y/RU:Y/SK:create_case=N

Solution metrics are Y or N. Optional SK overrides flip individual tools:
  SK:create_case=N   disable one skill even if its solution is on
  SK:isolate_endpoint=Y   enable one skill even if its solution is off

Case-management tools belong to both IRIS and TheHive. They are available
when either IRIS or TH is Y, unless an SK override says otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

VECTOR_PREFIX = "MSV:1"
# Also accept the older/alt prefix from the design notes.
_PREFIXES = ("MSV:1", "MCP:1")

SOLUTION_ORDER: Tuple[str, ...] = (
    "IRIS",
    "TH",
    "SIEM",
    "EDR",
    "CTI",
    "KB",
    "NB",
    "ENG",
    "RB",
    "AG",
    "RU",
)

SOLUTION_LABELS: Dict[str, str] = {
    "IRIS": "IRIS",
    "TH": "TheHive",
    "SIEM": "Elastic (ELK)",
    "EDR": "EDR",
    "CTI": "Threat intel",
    "KB": "Knowledge base",
    "NB": "NetBox",
    "ENG": "Engineering",
    "RB": "Runbooks",
    "AG": "Agent profiles",
    "RU": "Rules engine",
}

SOLUTION_SHORT: Dict[str, str] = {
    "IRIS": "IRIS",
    "TH": "TheHive",
    "SIEM": "ELK",
    "EDR": "EDR",
    "CTI": "CTI",
    "KB": "KB",
    "NB": "NetBox",
    "ENG": "Eng",
    "RB": "Runbooks",
    "AG": "Agents",
    "RU": "Rules",
}

_ACRONYMS = {"ip", "ioc", "dns", "kql", "kb", "ti", "edr", "ai"}
_LABEL_OVERRIDES = {
    "lookup_hash_ti": "Look up hash in threat intel",
    "search_kql_query": "Run a KQL search",
    "get_ioc_matches": "Get IOC matches",
    "kb_list_clients": "List knowledge-base clients",
    "kb_get_client_infra": "Get client infrastructure",
    "netbox_lookup_ip": "Look up IP in NetBox",
    "netbox_lookup_host": "Look up host in NetBox",
    "netbox_lookup_prefix": "Look up prefix in NetBox",
    "netbox_search": "Search NetBox assets",
    "get_all_uncertain_alerts_for_host": "Uncertain alerts for a host",
    "create_fine_tuning_recommendation": "File a fine-tune suggestion",
    "create_visibility_recommendation": "File a visibility-gap note",
    "search_lab_detection_rules": "Search Home Lab detection rules",
    "get_lab_detection_rule": "Get a Home Lab detection rule",
    "create_elastic_case": "Create Elastic Security case",
    "isolate_endpoint": "Isolate endpoint (Elastic Defend)",
    "release_endpoint_isolation": "Release endpoint isolation",
}

NETBOX_SKILLS: Tuple[str, ...] = (
    "netbox_lookup_ip",
    "netbox_lookup_host",
    "netbox_lookup_prefix",
    "netbox_search",
)


def human_skill_label(skill: str) -> str:
    if skill in _LABEL_OVERRIDES:
        return _LABEL_OVERRIDES[skill]
    parts = []
    for part in skill.split("_"):
        if part.lower() in _ACRONYMS:
            parts.append(part.upper())
        else:
            parts.append(part.capitalize())
    return " ".join(parts)


# Case tools are listed under both IRIS and TheHive in the UI.
# MCP still enables them if either solution is Y.
CASE_SKILLS: Tuple[str, ...] = (
    "create_case",
    "review_case",
    "list_cases",
    "search_cases",
    "add_case_comment",
    "attach_observable_to_case",
    "update_case_status",
    "assign_case",
    "get_case_timeline",
    "add_case_task",
    "list_case_tasks",
    "update_case_task_status",
    "add_case_asset",
    "list_case_assets",
    "add_case_evidence",
    "list_case_evidence",
    "update_case",
    "link_cases",
    "add_case_timeline_event",
    "list_case_timeline_events",
)

SIEM_SKILLS: Tuple[str, ...] = (
    "search_security_events",
    "get_file_report",
    "get_file_behavior_summary",
    "get_entities_related_to_file",
    "get_ip_address_report",
    "search_user_activity",
    "pivot_on_indicator",
    "search_kql_query",
    "get_recent_alerts",
    "get_network_events",
    "get_dns_events",
    "get_alerts_by_entity",
    "get_alerts_by_time_window",
    "get_all_uncertain_alerts_for_host",
    "get_email_events",
    "get_security_alerts",
    "get_security_alert_by_id",
    "get_siem_event_by_id",
    "close_alert",
    "update_alert_verdict",
    "tag_alert",
    "add_alert_note",
    "create_elastic_case",
    "isolate_endpoint",
    "release_endpoint_isolation",
    "lookup_entity",
    "get_ioc_matches",
    "get_threat_intel",
    "list_security_rules",
    "search_security_rules",
    "get_rule_detections",
    "list_rule_errors",
    "search_lab_detection_rules",
    "get_lab_detection_rule",
    "create_fine_tuning_recommendation",
    "create_visibility_recommendation",
)

SKILL_GROUPS: Tuple[Dict[str, object], ...] = (
    {
        "id": "IRIS",
        "name": "IRIS skills",
        "solutions": ("IRIS",),
        "help": "Case management tools when this cluster may talk to IRIS. TheHive uses the same tool names.",
        "skills": CASE_SKILLS,
    },
    {
        "id": "TH",
        "name": "TheHive skills",
        "solutions": ("TH",),
        "help": "Case management tools when this cluster may talk to TheHive. IRIS uses the same tool names.",
        "skills": CASE_SKILLS,
    },
    {
        "id": "SIEM",
        "name": "Elastic / ELK skills",
        "solutions": ("SIEM",),
        "help": "Search, alerts, detections, Elastic Defend isolation, and Home Lab rule suggestions against the Elastic cluster bound to this tab.",
        "skills": SIEM_SKILLS,
    },
    {
        "id": "EDR",
        "name": "EDR skills",
        "solutions": ("EDR",),
        "help": "Endpoint isolation, process kill, and forensic collection.",
        "skills": (
            "get_endpoint_summary",
            "get_detection_details",
            "isolate_endpoint",
            "release_endpoint_isolation",
            "kill_process_on_endpoint",
            "collect_forensic_artifacts",
        ),
    },
    {
        "id": "CTI",
        "name": "Threat intel skills",
        "solutions": ("CTI",),
        "help": "Hash lookups against configured CTI platforms.",
        "skills": ("lookup_hash_ti",),
    },
    {
        "id": "KB",
        "name": "Knowledge base skills",
        "solutions": ("KB",),
        "help": "Client infrastructure notes used during investigations.",
        "skills": ("kb_list_clients", "kb_get_client_infra"),
    },
    {
        "id": "NB",
        "name": "NetBox skills",
        "solutions": ("NB",),
        "help": "DCIM/IPAM lookups against NetBox for host, IP, and prefix enrichment.",
        "skills": NETBOX_SKILLS,
    },
    {
        "id": "ENG",
        "name": "Engineering skills",
        "solutions": ("ENG",),
        "help": "Trello / ClickUp / GitHub recommendation boards.",
        "skills": (
            "list_fine_tuning_recommendations",
            "list_visibility_recommendations",
            "add_comment_to_fine_tuning_recommendation",
            "add_comment_to_visibility_recommendation",
        ),
    },
    {
        "id": "RB",
        "name": "Runbook skills",
        "solutions": ("RB",),
        "help": "Saved investigation runbooks.",
        "skills": ("list_runbooks", "get_runbook", "execute_runbook"),
    },
    {
        "id": "AG",
        "name": "Agent profile skills",
        "solutions": ("AG",),
        "help": "SOC-tier agent personas and routing.",
        "skills": (
            "list_agent_profiles",
            "get_agent_profile",
            "route_case_to_agent",
            "execute_as_agent",
        ),
    },
    {
        "id": "RU",
        "name": "Rules engine skills",
        "solutions": ("RU",),
        "help": "Chained investigation workflows.",
        "skills": ("list_rules", "execute_rule"),
    },
)

SKILL_TO_SOLUTIONS: Dict[str, Tuple[str, ...]] = {}
KNOWN_SKILLS = set()
for _group in SKILL_GROUPS:
    sols = tuple(_group["solutions"])  # type: ignore[arg-type]
    for _skill in _group["skills"]:  # type: ignore[index]
        skill = str(_skill)
        KNOWN_SKILLS.add(skill)
        previous = SKILL_TO_SOLUTIONS.get(skill, ())
        SKILL_TO_SOLUTIONS[skill] = tuple(dict.fromkeys(previous + sols))

DEFAULT_SKILL_VECTOR = VECTOR_PREFIX + "/" + "/".join(f"{code}:Y" for code in SOLUTION_ORDER)


@dataclass
class SkillVector:
    solutions: Dict[str, bool] = field(default_factory=dict)
    skills: Dict[str, bool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for code in SOLUTION_ORDER:
            self.solutions.setdefault(code, True)

    def solution_on(self, code: str) -> bool:
        return bool(self.solutions.get(code, True))

    def parents_on(self, skill: str) -> bool:
        parents = SKILL_TO_SOLUTIONS.get(skill)
        if not parents:
            return True
        return any(self.solution_on(code) for code in parents)

    def allows(self, skill: str) -> bool:
        if skill in self.skills:
            return bool(self.skills[skill])
        return self.parents_on(skill)

    def set_solution(self, code: str, enabled: bool) -> None:
        if code not in SOLUTION_ORDER:
            raise ValueError(f"Unknown solution '{code}'")
        self.solutions[code] = bool(enabled)

    def set_skill(self, skill: str, enabled: Optional[bool]) -> None:
        if skill not in KNOWN_SKILLS:
            raise ValueError(f"Unknown skill '{skill}'")
        if enabled is None:
            self.skills.pop(skill, None)
            return
        parent = self.parents_on(skill)
        if bool(enabled) == parent:
            self.skills.pop(skill, None)
        else:
            self.skills[skill] = bool(enabled)

    def encode(self) -> str:
        parts = [VECTOR_PREFIX]
        for code in SOLUTION_ORDER:
            parts.append(f"{code}:{'Y' if self.solution_on(code) else 'N'}")
        overrides = []
        for skill in sorted(KNOWN_SKILLS):
            parent = self.parents_on(skill)
            if skill not in self.skills:
                continue
            enabled = bool(self.skills[skill])
            if enabled == parent:
                continue
            overrides.append(f"{skill}={'Y' if enabled else 'N'}")
        if overrides:
            parts.append("SK:" + ",".join(overrides))
        return "/".join(parts)


def default_vector() -> SkillVector:
    return SkillVector()


def parse_skill_vector(raw: Optional[str], *, strict: bool = True) -> SkillVector:
    """
    Parse an MSV string.

    Empty/missing values become the all-on default.
    `strict=True` raises ValueError on unknown metrics (API/UI save).
    `strict=False` ignores junk so a bad config cannot take MCP down.
    """
    text = (raw or "").strip()
    if not text:
        return default_vector()

    parts = [item.strip() for item in text.split("/") if item.strip()]
    if not parts:
        return default_vector()

    prefix = parts[0].upper()
    if prefix not in {item.upper() for item in _PREFIXES} and not prefix.startswith("MSV:") and not prefix.startswith("MCP:"):
        if strict:
            raise ValueError("Skill vector must start with MSV:1 (CVSS-style)")
        return default_vector()

    vector = default_vector()
    for part in parts[1:]:
        if part.upper().startswith("SK:"):
            body = part.split(":", 1)[1]
            for item in body.split(","):
                item = item.strip()
                if not item:
                    continue
                if "=" not in item:
                    if strict:
                        raise ValueError(f"Invalid skill override '{item}'")
                    continue
                name, flag = item.split("=", 1)
                name = name.strip()
                flag = flag.strip().upper()
                if name not in KNOWN_SKILLS:
                    if strict:
                        raise ValueError(f"Unknown skill '{name}'")
                    continue
                if flag not in {"Y", "N"}:
                    if strict:
                        raise ValueError(f"Skill '{name}' must be Y or N")
                    continue
                vector.skills[name] = flag == "Y"
            continue

        if ":" not in part:
            if strict:
                raise ValueError(f"Invalid vector metric '{part}'")
            continue
        key, value = part.split(":", 1)
        key = key.strip().upper()
        value = value.strip().upper()
        if key == "CASE":
            # Alias: CASE:N turns off both IRIS and TheHive.
            if value not in {"Y", "N"}:
                if strict:
                    raise ValueError("CASE must be Y or N")
                continue
            enabled = value == "Y"
            vector.solutions["IRIS"] = enabled
            vector.solutions["TH"] = enabled
            continue
        if key not in SOLUTION_ORDER:
            if key.lower() in KNOWN_SKILLS and value in {"Y", "N"}:
                vector.skills[key.lower()] = value == "Y"
                continue
            if strict:
                raise ValueError(f"Unknown solution '{key}'")
            continue
        if value not in {"Y", "N"}:
            if strict:
                raise ValueError(f"{key} must be Y or N")
            continue
        vector.solutions[key] = value == "Y"
    return vector


def canonicalize(raw: Optional[str], *, strict: bool = True, fallback: Optional[str] = None) -> str:
    try:
        return parse_skill_vector(raw, strict=strict).encode()
    except ValueError:
        if fallback is not None:
            return parse_skill_vector(fallback, strict=False).encode()
        raise


def is_skill_allowed(skill: str, raw_vector: Optional[str]) -> bool:
    vector = parse_skill_vector(raw_vector, strict=False)
    return vector.allows(skill)


def allowed_tool_names(names: Iterable[str], raw_vector: Optional[str]) -> List[str]:
    vector = parse_skill_vector(raw_vector, strict=False)
    allowed: List[str] = []
    for name in names:
        if name not in KNOWN_SKILLS or vector.allows(name):
            allowed.append(name)
    return allowed


def catalog_payload() -> Dict[str, object]:
    return {
        "prefix": VECTOR_PREFIX,
        "default_skill_vector": DEFAULT_SKILL_VECTOR,
        "example": DEFAULT_SKILL_VECTOR + "/SK:create_case=N",
        "help": (
            "CVSS-style MCP Skill Vector. Each group below is one solution "
            "(IRIS skills, Elastic / ELK skills, and so on). Solution metrics are Y or N. "
            "SK:skill=N disables one tool; SK:skill=Y re-enables a tool when its solution is off."
        ),
        "solutions": [
            {
                "id": code,
                "label": SOLUTION_LABELS[code],
                "short": SOLUTION_SHORT[code],
            }
            for code in SOLUTION_ORDER
        ],
        "groups": [
            {
                "id": group["id"],
                "name": group["name"],
                "help": group["help"],
                "solutions": list(group["solutions"]),
                "skills": [
                    {
                        "id": skill,
                        "label": human_skill_label(str(skill)),
                    }
                    for skill in group["skills"]  # type: ignore[union-attr]
                ],
            }
            for group in SKILL_GROUPS
        ],
    }


def summarize(raw: Optional[str]) -> Dict[str, object]:
    vector = parse_skill_vector(raw, strict=False)
    on = sum(1 for code in SOLUTION_ORDER if vector.solution_on(code))
    return {
        "skill_vector": vector.encode(),
        "solutions_on": on,
        "solutions_total": len(SOLUTION_ORDER),
        "skill_overrides": len(vector.skills),
        "solution_flags": {code: vector.solution_on(code) for code in SOLUTION_ORDER},
    }
