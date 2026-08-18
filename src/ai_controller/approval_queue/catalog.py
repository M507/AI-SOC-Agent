"""Action catalog: what the AI may request and what each payload must contain.

Adding a new action is: define an ActionSpec here, then implement a handler
in `actions/` and register it in `actions/HANDLERS`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class FieldSpec:
    name: str
    label: str
    required: bool = False
    description: str = ""


@dataclass(frozen=True)
class ActionSpec:
    action_type: str
    label: str
    description: str
    category: str
    risk: str
    fields: Tuple[FieldSpec, ...]
    execution: str
    integration: str
    gated_mcp_tool: Optional[str] = None
    asks_question: bool = False
    default_follow_ups: Tuple[str, ...] = ()
    notes: str = ""

    @property
    def required_fields(self) -> Tuple[str, ...]:
        return tuple(item.name for item in self.fields if item.required)

    def to_dict(self) -> Dict[str, object]:
        return {
            "action_type": self.action_type,
            "label": self.label,
            "description": self.description,
            "category": self.category,
            "risk": self.risk,
            "execution": self.execution,
            "integration": self.integration,
            "asks_question": self.asks_question,
            "gated_mcp_tool": self.gated_mcp_tool,
            "notes": self.notes,
            "fields": [
                {
                    "name": item.name,
                    "label": item.label,
                    "required": item.required,
                    "description": item.description,
                }
                for item in self.fields
            ],
        }


def _fields(*specs: FieldSpec) -> Tuple[FieldSpec, ...]:
    return specs


ACTION_CATALOG: Tuple[ActionSpec, ...] = (
    ActionSpec(
        action_type="close_alert",
        label="Close alert",
        description="Close a SIEM alert, typically as a false positive or benign true positive.",
        category="siem",
        risk="medium",
        execution="ready",
        integration="siem",
        gated_mcp_tool="close_alert",
        notes="Runs Elastic close_alert against the cluster bound to the request.",
        fields=_fields(
            FieldSpec("alert_id", "Alert ID", True, "SIEM alert identifier"),
            FieldSpec("reason", "Reason", False, "false_positive, benign_true_positive, true_positive"),
            FieldSpec("comment", "Comment", False, "Why the alert is being closed"),
        ),
    ),
    ActionSpec(
        action_type="identity_verify",
        label="Is this you?",
        description="Ask the analyst to confirm whether activity (login, admin action, travel) was them.",
        category="identity",
        risk="low",
        execution="ready",
        integration="siem",
        asks_question=True,
        default_follow_ups=("yes", "no"),
        notes="After Yes: acknowledge (close as benign). After No: escalate (Elastic Security case + true-positive tag).",
        fields=_fields(
            FieldSpec("alert_id", "Alert ID", False),
            FieldSpec("username", "User", True),
            FieldSpec("source_ip", "Source IP", False),
            FieldSpec("hostname", "Host", False),
            FieldSpec("timestamp", "When", False),
            FieldSpec("activity", "Activity", False, "e.g. VPN login, Okta MFA, RDP"),
        ),
    ),
    ActionSpec(
        action_type="isolate_endpoint",
        label="Isolate endpoint",
        description="Cut an endpoint off the network via Elastic Defend (Kibana) on the bound cluster.",
        category="edr",
        risk="critical",
        execution="ready",
        integration="siem",
        gated_mcp_tool="isolate_endpoint",
        notes="Runs Kibana `/api/endpoint/action/isolate` (Elastic Defend). Needs a Kibana API key with host isolation / response-action privileges. Optional cluster kibana_url if Kibana is not :5601.",
        fields=_fields(
            FieldSpec("endpoint_id", "Endpoint / agent ID", True),
            FieldSpec("hostname", "Hostname", False),
            FieldSpec("reason", "Reason", False),
        ),
    ),
    ActionSpec(
        action_type="release_isolation",
        label="Release isolation",
        description="Restore network connectivity via Elastic Defend (Kibana) on the bound cluster.",
        category="edr",
        risk="high",
        execution="ready",
        integration="siem",
        gated_mcp_tool="release_endpoint_isolation",
        notes="Runs Kibana `/api/endpoint/action/unisolate`. Inverse of isolate_endpoint.",
        fields=_fields(
            FieldSpec("endpoint_id", "Endpoint / agent ID", True),
            FieldSpec("hostname", "Hostname", False),
            FieldSpec("reason", "Reason", False),
        ),
    ),
    ActionSpec(
        action_type="kill_process",
        label="Kill process",
        description="Terminate a process on an endpoint.",
        category="edr",
        risk="critical",
        execution="ready_if_configured",
        integration="edr",
        gated_mcp_tool="kill_process_on_endpoint",
        notes="Requires EDR.",
        fields=_fields(
            FieldSpec("endpoint_id", "Endpoint ID", True),
            FieldSpec("pid", "PID", True),
            FieldSpec("process_name", "Process name", False),
        ),
    ),
    ActionSpec(
        action_type="collect_forensics",
        label="Collect forensics",
        description="Collect forensic artifacts from an endpoint.",
        category="edr",
        risk="high",
        execution="ready_if_configured",
        integration="edr",
        gated_mcp_tool="collect_forensic_artifacts",
        notes="Requires EDR.",
        fields=_fields(
            FieldSpec("endpoint_id", "Endpoint ID", True),
            FieldSpec("hostname", "Hostname", False),
            FieldSpec("artifact_types", "Artifact types", False),
        ),
    ),
    ActionSpec(
        action_type="fine_tune",
        label="Fine-tune detection",
        description="Informational suggestion to tune a Home Lab detection rule. No action is taken.",
        category="detections",
        risk="low",
        execution="informational",
        integration="none",
        gated_mcp_tool="create_fine_tuning_recommendation",
        notes="Looks up the rule in Home-Lab-Rules and stores a suggestion. No approve button; no engineering board.",
        fields=_fields(
            FieldSpec("title", "Title", True),
            FieldSpec("description", "Suggestion", True, "What to change and why"),
            FieldSpec("rule_id", "Rule ID", False),
            FieldSpec("rule_name", "Rule name", False),
            FieldSpec("alert_id", "Related alert", False),
        ),
    ),
    ActionSpec(
        action_type="visibility",
        label="Visibility gap",
        description="Informational note that telemetry or a detection may be missing. No action is taken.",
        category="detections",
        risk="low",
        execution="informational",
        integration="none",
        gated_mcp_tool="create_visibility_recommendation",
        notes="Searches the Home Lab rule catalog first. Filed only as info, with coverage evidence. No approve button.",
        fields=_fields(
            FieldSpec("title", "Title", True),
            FieldSpec("description", "Suggestion", True),
            FieldSpec("source", "Missing source", False, "e.g. DNS, PowerShell, cloud audit"),
        ),
    ),
    ActionSpec(
        action_type="create_case",
        label="Open case",
        description="Open a case in IRIS / TheHive for continued investigation.",
        category="case",
        risk="low",
        execution="ready_if_configured",
        integration="case",
        notes="Uses the configured case-management client.",
        fields=_fields(
            FieldSpec("title", "Title", True),
            FieldSpec("description", "Description", True),
            FieldSpec("priority", "Priority", False),
            FieldSpec("alert_id", "Related alert", False),
            FieldSpec("tags", "Tags", False),
        ),
    ),
    ActionSpec(
        action_type="close_case",
        label="Close case",
        description="Close an existing case after the investigation is complete.",
        category="case",
        risk="medium",
        execution="ready_if_configured",
        integration="case",
        notes="Sets case status to closed.",
        fields=_fields(
            FieldSpec("case_id", "Case ID", True),
            FieldSpec("comment", "Closing comment", False),
        ),
    ),
    ActionSpec(
        action_type="escalate",
        label="Escalate",
        description="Treat as a true positive: tag the alert and open an Elastic Security case.",
        category="siem",
        risk="medium",
        execution="ready",
        integration="siem",
        notes="Tags the SIEM alert as TP and opens a case in Elastic Security (not IRIS/TheHive), including the full alert.",
        fields=_fields(
            FieldSpec("alert_id", "Alert ID", False),
            FieldSpec("title", "Case title", False),
            FieldSpec("description", "Escalation notes", True),
            FieldSpec("priority", "Priority", False),
        ),
    ),
    ActionSpec(
        action_type="block_indicator",
        label="Block indicator",
        description="Block an IP, domain, URL, or hash at the perimeter or EDR.",
        category="network",
        risk="high",
        execution="stub",
        integration="none",
        notes="Needs a firewall / proxy / EDR block API.",
        fields=_fields(
            FieldSpec("indicator", "Indicator", True),
            FieldSpec("indicator_type", "Type", True, "ip, domain, url, hash"),
            FieldSpec("reason", "Reason", False),
        ),
    ),
    ActionSpec(
        action_type="disable_user",
        label="Disable user",
        description="Disable an identity in AD / IdP after confirmed account compromise.",
        category="iam",
        risk="critical",
        execution="stub",
        integration="none",
        notes="Needs an IAM / directory API (Okta, Entra, AD).",
        fields=_fields(
            FieldSpec("username", "Username", True),
            FieldSpec("directory", "Directory", False),
            FieldSpec("reason", "Reason", False),
        ),
    ),
    ActionSpec(
        action_type="reset_credentials",
        label="Reset credentials",
        description="Force a password / session reset for a user.",
        category="iam",
        risk="high",
        execution="stub",
        integration="none",
        notes="Needs an IAM API.",
        fields=_fields(
            FieldSpec("username", "Username", True),
            FieldSpec("reason", "Reason", False),
        ),
    ),
    ActionSpec(
        action_type="contain_email",
        label="Contain email",
        description="Quarantine or recall a malicious message across mailboxes.",
        category="email",
        risk="high",
        execution="stub",
        integration="none",
        notes="Needs a mail-gateway / M365 / Google Workspace API.",
        fields=_fields(
            FieldSpec("message_id", "Message ID", True),
            FieldSpec("sender", "Sender", False),
            FieldSpec("subject", "Subject", False),
            FieldSpec("reason", "Reason", False),
        ),
    ),
)

_BY_TYPE: Dict[str, ActionSpec] = {spec.action_type: spec for spec in ACTION_CATALOG}
_GATED_MCP: Dict[str, ActionSpec] = {
    spec.gated_mcp_tool: spec for spec in ACTION_CATALOG if spec.gated_mcp_tool
}


def list_action_specs() -> List[ActionSpec]:
    return list(ACTION_CATALOG)


def get_action_spec(action_type: str) -> Optional[ActionSpec]:
    return _BY_TYPE.get(action_type)


def spec_for_mcp_tool(tool_name: str) -> Optional[ActionSpec]:
    return _GATED_MCP.get(tool_name)


def gated_mcp_tools() -> Tuple[str, ...]:
    return tuple(_GATED_MCP.keys())
