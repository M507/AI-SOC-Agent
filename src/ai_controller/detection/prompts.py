"""Prompt text for asking about a finding and for drafting exceptions.

These instructions are only used by Detection as Code. They are not the
global SOC system prompt, so a draft cannot pick up tools or behavior
from chat. The template ids returned to the Findings page are the keys
in ASK_TEMPLATES. The draft JSON contract is DRAFT_SYSTEM. See
documentation/detection-as-code.md.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

MAX_PROMPT_CHARS = 6500

ASK_TEMPLATES: List[Dict[str, str]] = [
    {
        "id": "ask_about",
        "label": "Ask about this alert",
        "description": "What happened and why it fired.",
        "instruction": (
            "You are a detection engineer helping triage an Elastic Security alert. "
            "Explain what this alert means, why it likely fired, and what an analyst "
            "should look at next. Be concise and practical."
        ),
    },
    {
        "id": "is_fp",
        "label": "Is this a false positive?",
        "description": "False positive or true positive, with confidence.",
        "instruction": (
            "You are a detection engineer. Assess whether this Elastic Security alert "
            "is likely a false positive or a true positive. Give a clear verdict, "
            "confidence (low/medium/high), key evidence for and against, and what "
            "additional checks would confirm it."
        ),
    },
    {
        "id": "suggest_exception",
        "label": "Suggest an exception",
        "description": "A narrow exception, or an explanation of why not.",
        "instruction": (
            "You are a detection engineer tuning Elastic rules. If this alert looks like "
            "benign or expected activity, propose a narrow exception using the selected "
            "fields. Explain the risk of over-suppression and suggest a precise name. "
            "If it is not safe to except, say so."
        ),
    },
    {
        "id": "investigate",
        "label": "Investigation steps",
        "description": "Checks, pivots, and when to escalate or close.",
        "instruction": (
            "You are a SOC analyst. Provide a short investigation playbook for this "
            "alert: immediate checks, host, user, and process pivots, log sources to "
            "query, and criteria to escalate versus close."
        ),
    },
    {
        "id": "explain_rule",
        "label": "Explain the detection logic",
        "description": "What the rule is looking for.",
        "instruction": (
            "Explain the detection logic behind this Elastic rule in plain language. "
            "Cover what behavior it is looking for, common legitimate versus malicious "
            "causes, and typical tuning pitfalls."
        ),
    },
    {
        "id": "risk_severity",
        "label": "Assess risk and severity",
        "description": "Impact and whether the severity fits.",
        "instruction": (
            "Assess the real-world risk and urgency of this alert for a small SOC. "
            "Comment on severity versus likely impact, and whether the assigned "
            "severity seems right."
        ),
    },
    {
        "id": "ticket_summary",
        "label": "Summarize for a ticket",
        "description": "A short note that can be pasted into a ticket.",
        "instruction": (
            "Write a short ticket-ready summary of this alert: title, what happened, "
            "affected assets, selected evidence fields, recommended next action, and "
            "suggested status (investigate, monitor, or close as a false positive)."
        ),
    },
    {
        "id": "custom",
        "label": "Custom question",
        "description": "Your own question, with the alert context attached.",
        "instruction": "",
    },
]

DRAFT_SYSTEM = """You are a senior Elastic Security detection engineer drafting narrow rule exceptions.

Rules you must follow:
1. Prefer the analyst-selected fields. Do not invent field names that are not in the provided alert fields.
2. Prefer values that appear across multiple selected alerts when building a shared exception.
3. Prefer host, user, process, and path fields over volatile IPs and timestamps.
4. Keep exceptions as a tight AND of exact matches. Do not use "*" or empty strings.
5. If it is not safe to except, return an empty exceptions list and explain why.
6. Respond with JSON only. No markdown fences. No prose outside JSON.

Required JSON schema:
{
  "rationale": "short explanation",
  "safe_to_except": true,
  "exceptions": [
    {
      "name": "short exception name",
      "confidence": "low|medium|high",
      "entries": [
        {"field": "host.name", "value": "example"}
      ]
    }
  ],
  "notes": "optional caveats for the analyst"
}
"""


def list_ask_templates() -> List[Dict[str, str]]:
    return [
        {"id": item["id"], "label": item["label"], "description": item["description"]}
        for item in ASK_TEMPLATES
    ]


def _template(prompt_id: str) -> Dict[str, str]:
    for item in ASK_TEMPLATES:
        if item["id"] == prompt_id:
            return item
    raise ValueError(f"Unknown prompt template: {prompt_id}")


def _format_entries(entries: List[Dict[str, Any]]) -> str:
    lines = []
    for entry in entries or []:
        field = str(entry.get("field") or "").strip()
        value = str(entry.get("value") or "").strip()
        if not field:
            continue
        if len(value) > 400:
            value = value[:400] + "…"
        lines.append(f"- {field}: {value}")
    return "\n".join(lines) if lines else "(none selected)"


def build_ask_prompt(
    *,
    prompt_id: str,
    alert: Dict[str, Any],
    entries: Optional[List[Dict[str, Any]]] = None,
    custom_instruction: Optional[str] = None,
) -> str:
    """User prompt for one Ask completion. The system text is the template instruction."""
    template = _template(prompt_id)
    extra = (custom_instruction or "").strip()
    if prompt_id == "custom":
        if not extra:
            raise ValueError("Custom prompt text is required.")
        instruction = extra
    elif extra:
        instruction = f"{template['instruction']}\n\nAdditional analyst notes:\n{extra}"
    else:
        instruction = template["instruction"]
    parts = [
        instruction,
        "",
        "## Alert context",
        f"- Alert ID: {alert.get('id') or 'unknown'}",
        f"- Rule name: {alert.get('rule_name') or alert.get('title') or 'unknown'}",
        f"- Rule ID: {alert.get('rule_id') or 'unknown'}",
        f"- Severity: {alert.get('severity') or 'unknown'}",
        f"- Status: {alert.get('status') or 'unknown'}",
        f"- Timestamp: {alert.get('created_at') or 'unknown'}",
        f"- Host: {alert.get('host_name') or 'n/a'}",
        f"- User: {alert.get('user_name') or 'n/a'}",
        f"- Verdict: {alert.get('verdict') or 'n/a'}",
        "",
        "## Selected fields (analyst-checked)",
        _format_entries(entries or []),
        "",
        "Respond with clear sections and actionable recommendations.",
    ]
    prompt = "\n".join(parts).strip()
    if len(prompt) > MAX_PROMPT_CHARS:
        prompt = prompt[: MAX_PROMPT_CHARS - 1].rstrip() + "…"
    return prompt


def ask_system_prompt(prompt_id: str) -> str:
    if prompt_id == "custom":
        return (
            "You are a detection engineer. Answer the analyst's question about the "
            "Elastic Security alert in the user message. Use only the supplied context."
        )
    return _template(prompt_id)["instruction"]


def build_draft_prompt(
    *,
    rule_file: Dict[str, Any],
    alerts: List[Dict[str, Any]],
    feedback: Optional[str] = None,
    previous: Optional[Dict[str, Any]] = None,
) -> str:
    payload: Dict[str, Any] = {
        "task": (
            "Recommend exception item(s) to fine-tune this rule. "
            "Use selected_fields on each alert as the primary evidence."
        ),
        "rule_file": rule_file,
        "selected_alerts": alerts,
    }
    if previous:
        payload["previous_suggestions"] = previous
    if feedback:
        payload["analyst_feedback"] = feedback
    text = (
        "Draft fine-tune exceptions for this rule using the payload below.\n\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
    )
    if len(text) > 24000:
        text = text[:23999].rstrip() + "…"
    return text
