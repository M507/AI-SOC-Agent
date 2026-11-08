"""Prompt text for asking about an alert and for drafting exceptions.

These instructions are only used by Detection as Code. They are not the
global SOC system prompt, so a draft cannot pick up tools or behavior
from chat. The template ids returned to the Alerts page are the keys
in ASK_TEMPLATES. The draft JSON contract is DRAFT_SYSTEM. See
documentation/detection-as-code.md.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

MAX_PROMPT_CHARS = 6500
MAX_DRAFT_PROMPT_CHARS = 24000

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

DRAFT_SYSTEM = """You are a senior Elastic Security detection engineer drafting narrow, maintainable rule exceptions (Detection as Code).

Engineering bar:
- Evidence-based only: ground every exception in the supplied rule, suggestion, and alert fields. Never invent field names or values.
- Prefer precision: host, user, process, path, and code-signing style ANDs over volatile IPs and timestamps.
- Prefer exact matches. Do not use "*" or "?" unless unavoidable; if you must, the analyst must allow wildcards later.
- Prefer reusable, reviewable exception cards with clear names over one opaque catch-all.
- If it is not safe to except, return an empty exceptions list, set safe_to_except to false, and explain why in rationale and notes.

SIEM / teaching requirements:
- Explain what kind of SIEM signal this is (Elastic detection) and what behavior the rule watches.
- Paraphrase the actual rule logic you were given (query/EQL/threshold).
- Describe how the exception improves precision without blinding true positives.
- Give a short improvement_plan the analyst can skim before Implement.

When analyst_instructions are provided in the user payload, treat them as binding focus constraints from the human reviewer: prioritize what to except vs leave alone, while still obeying evidence-only / no-invent rules.

Output rules:
- Respond with JSON only. No markdown fences. No prose outside JSON.

Required JSON schema:
{
  "rationale": "2-5 sentences: what this SIEM signal is, how the rule fires today, why this is FP/BTP/noise, and how the exception improves precision without blinding true positives",
  "siem_context": {
    "platform": "elastic",
    "rule_type": "query|eql|threshold|machine_learning|other",
    "signal_summary": "what activity/behavior this detection watches",
    "data_sources": ["index or beat hints from the rule"]
  },
  "rule_understanding": "short paraphrase of the actual rule logic (query/EQL) you were given",
  "improvement_plan": [
    "concrete step the exception implements",
    "what remains detected after the change"
  ],
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
  "notes": "residual risk, monitoring tips, when to revisit"
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


def _rule_document(rule_file: Dict[str, Any]) -> Dict[str, Any]:
    """Keep the fields that matter for drafting; drop bulky unrelated keys when needed."""
    rule = rule_file.get("rule") if isinstance(rule_file.get("rule"), dict) else {}
    dac = rule_file.get("_dac") if isinstance(rule_file.get("_dac"), dict) else {}
    items = rule_file.get("exception_items") if isinstance(rule_file.get("exception_items"), list) else []
    return {
        "rule_id": dac.get("rule_id") or rule.get("rule_id") or rule.get("id"),
        "name": rule.get("name"),
        "description": rule.get("description"),
        "severity": rule.get("severity"),
        "risk_score": rule.get("risk_score"),
        "type": rule.get("type"),
        "language": rule.get("language"),
        "query": rule.get("query"),
        "filters": rule.get("filters"),
        "index": rule.get("index"),
        "data_view_id": rule.get("data_view_id"),
        "tags": rule.get("tags"),
        "enabled": rule.get("enabled"),
        "investigation_fields": rule.get("investigation_fields"),
        "existing_exception_count": len(items),
        "existing_exception_items": items[:20],
        "_dac_status": dac.get("status"),
    }


def _siem_environment(rule_file: Dict[str, Any], cluster_id: Optional[str]) -> Dict[str, Any]:
    rule = rule_file.get("rule") if isinstance(rule_file.get("rule"), dict) else {}
    return {
        "platform": "elastic",
        "cluster_id": cluster_id or None,
        "rule_language": rule.get("language"),
        "rule_type": rule.get("type"),
        "severity": rule.get("severity"),
        "risk_score": rule.get("risk_score"),
        "enabled": rule.get("enabled"),
        "index": rule.get("index"),
        "data_view_id": rule.get("data_view_id"),
    }


def _evidence_has_values(alerts: List[Dict[str, Any]]) -> bool:
    for alert in alerts or []:
        if not isinstance(alert, dict):
            continue
        for entry in alert.get("selected_fields") or []:
            if isinstance(entry, dict) and str(entry.get("field") or "").strip() and str(entry.get("value") or "").strip():
                return True
    return False


def build_draft_prompt(
    *,
    rule_file: Dict[str, Any],
    alerts: List[Dict[str, Any]],
    feedback: Optional[str] = None,
    previous: Optional[Dict[str, Any]] = None,
    suggestion: Optional[str] = None,
    suggestion_title: Optional[str] = None,
    cluster_id: Optional[str] = None,
    analyst_instructions: Optional[str] = None,
) -> str:
    """Assemble a sectioned user prompt for Draft / Revise / Send-to-Review.

    Includes the agent suggestion (when present), SIEM environment, the actual
    rule document, and alert evidence. Truncates only under MAX_DRAFT_PROMPT_CHARS,
    preferring to keep name/query/exceptions intact.
    """
    has_values = _evidence_has_values(alerts)
    instructions = (analyst_instructions or "").strip()
    task = (
        "Fine-tune this Elastic detection. Produce narrow exception item(s) plus the "
        "enriched rationale schema (siem_context, rule_understanding, improvement_plan). "
        "Use selected_fields on each alert as primary evidence when values are present."
    )
    if instructions:
        task += (
            " Treat analyst_instructions as binding focus constraints from the human "
            "reviewer (what to fine-tune vs leave alone), while still obeying "
            "evidence-only / no-invent rules."
        )
    if not has_values:
        task += (
            " No concrete alert field values were supplied — constrain yourself to the "
            "rule document and the agent/analyst suggestion. Do not invent alert values."
        )
    payload: Dict[str, Any] = {
        "task": task,
        "agent_suggestion": {
            "title": (suggestion_title or "").strip() or None,
            "text": (suggestion or "").strip() or None,
        },
        "siem_environment": _siem_environment(rule_file, cluster_id),
        "actual_rule": _rule_document(rule_file),
        "selected_alerts": alerts,
        "evidence_note": (
            "Alert field values are present."
            if has_values
            else "No alert field values — use only rule + suggestion; do not invent values."
        ),
    }
    if instructions:
        payload["analyst_instructions"] = instructions
    if previous:
        payload["previous_suggestions"] = previous
    if feedback:
        payload["analyst_feedback"] = feedback
        payload["validation_errors"] = feedback
    text = (
        "Draft fine-tune exceptions for this Elastic SIEM rule using the payload below.\n"
        "Show clearly how to improve the detection; ground the exceptions in the actual rule.\n\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
    )
    if len(text) > MAX_DRAFT_PROMPT_CHARS:
        # Prefer keeping query: shrink existing exceptions first, then truncate.
        slim = dict(payload)
        actual = dict(slim.get("actual_rule") or {})
        actual["existing_exception_items"] = (actual.get("existing_exception_items") or [])[:5]
        slim["actual_rule"] = actual
        text = (
            "Draft fine-tune exceptions for this Elastic SIEM rule using the payload below.\n"
            "Show clearly how to improve the detection; ground the exceptions in the actual rule.\n\n"
            + json.dumps(slim, ensure_ascii=False, indent=2)
        )
    if len(text) > MAX_DRAFT_PROMPT_CHARS:
        text = text[: MAX_DRAFT_PROMPT_CHARS - 1].rstrip() + "…"
    return text
