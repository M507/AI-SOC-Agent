"""Author case runbooks from runbook-gap Requests (Create runbook button).

Builds an Open WebUI / LLM prompt from the request + investigated alert, and
writes finished markdown under ``run_books/<soc>/cases/``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

from .models import ApprovalRequest
from .runbook_gaps import list_case_runbooks, runbooks_dir

_SLUG_RE = re.compile(r"[^a-z0-9_]+")
_PATH_RE = re.compile(
    r"^(?P<tier>soc[123])/cases/(?P<name>[a-z0-9][a-z0-9_]{1,80})$",
    re.I,
)


def normalize_case_runbook_path(
    suggested_path: Optional[str] = None,
    *,
    soc_tier: str = "soc1",
    rule_name: Optional[str] = None,
    alert_type: Optional[str] = None,
    title: Optional[str] = None,
) -> str:
    """Return a safe relative path like ``soc1/cases/impossible_travel_triage`` (no .md)."""
    raw = (suggested_path or "").strip().removesuffix(".md")
    match = _PATH_RE.match(raw) if raw else None
    if match:
        return f"{match.group('tier').lower()}/cases/{match.group('name').lower()}"

    tier = (soc_tier or "soc1").strip().lower() or "soc1"
    if tier not in {"soc1", "soc2", "soc3"}:
        tier = "soc1"

    seed = rule_name or alert_type or title or "case_playbook"
    slug = _SLUG_RE.sub("_", str(seed).lower()).strip("_") or "case_playbook"
    if not slug.endswith("_triage"):
        slug = f"{slug}_triage"
    slug = slug[:80]
    return f"{tier}/cases/{slug}"


def save_case_runbook(
    path: str,
    content: str,
    *,
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Write a case runbook markdown file under ``run_books/<soc>/cases/``."""
    text = (content or "").strip()
    if not text:
        return {"success": False, "error": "content is empty"}
    if not text.lstrip().startswith("#"):
        return {
            "success": False,
            "error": "content must be markdown starting with an H1 title (# ...)",
        }

    raw = (path or "").strip().removesuffix(".md")
    match = _PATH_RE.match(raw)
    if not match:
        return {
            "success": False,
            "error": f"path must look like soc1/cases/<slug>, got: {path!r}",
        }
    relative = f"{match.group('tier').lower()}/cases/{match.group('name').lower()}"

    root = runbooks_dir().resolve()
    target = (root / f"{relative}.md").resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return {"success": False, "error": "refusing path outside run_books/"}

    cases_dir = target.parent
    if cases_dir.name != "cases":
        return {"success": False, "error": "path must target a cases/ directory"}

    if target.exists() and not overwrite:
        return {
            "success": False,
            "error": f"runbook already exists: {relative}.md (pass overwrite=true to replace)",
            "path": relative,
            "absolute_path": str(target),
        }

    cases_dir.mkdir(parents=True, exist_ok=True)
    target.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    return {
        "success": True,
        "path": relative,
        "absolute_path": str(target),
        "bytes": target.stat().st_size,
        "overwrote": bool(overwrite),
        "message": f"Wrote case runbook {relative}.md",
    }


def _json_block(label: str, value: Any, *, limit: int = 12000) -> str:
    if value is None or value == "" or value == {} or value == []:
        return f"### {label}\n_(none)_\n"
    try:
        blob = json.dumps(value, indent=2, default=str)
    except TypeError:
        blob = str(value)
    if len(blob) > limit:
        blob = blob[:limit] + "\n… (truncated)"
    return f"### {label}\n```json\n{blob}\n```\n"


def build_create_runbook_prompt(request: ApprovalRequest) -> Dict[str, Any]:
    """Build the freeform prompt sent to Open WebUI for authoring a case runbook."""
    payload = dict(request.payload or {})
    soc_tier = str(payload.get("soc_tier") or "soc1").strip().lower() or "soc1"
    target_path = normalize_case_runbook_path(
        payload.get("suggested_path"),
        soc_tier=soc_tier,
        rule_name=payload.get("rule_name"),
        alert_type=payload.get("alert_type"),
        title=request.title or payload.get("title"),
    )
    existing = payload.get("existing_case_runbooks")
    if not isinstance(existing, list):
        existing = list_case_runbooks(soc_tier=soc_tier)

    example_paths = [rb.get("path") for rb in existing if isinstance(rb, dict) and rb.get("path")]
    if not example_paths:
        example_paths = [
            "soc1/cases/suspicious_login_triage",
            "soc1/cases/malware_initial_triage",
            "soc1/cases/widget_abuse_triage",
        ]
    primary_example = example_paths[0]

    session_name = (request.title or "Create case runbook").strip()
    if len(session_name) > 72:
        session_name = session_name[:69] + "…"
    if not session_name.lower().startswith("create"):
        session_name = f"Create runbook: {session_name}"

    alert = payload.get("alert")
    alert_id = payload.get("alert_id") or (alert.get("id") if isinstance(alert, dict) else None)

    prompt = f"""You are authoring a NEW SOC1 case-specific runbook for SamiGPT.

## Goal
Write a complete markdown playbook and save it with the MCP tool `save_case_runbook`.
Target path (relative, no .md suffix): `{target_path}`
Final file must land at `run_books/{target_path}.md` alongside the other case playbooks.

## Source request (runbook gap)
- **Request id:** `{request.id}`
- **Title:** {request.title}
- **Summary:** {request.summary or "(none)"}
- **Rationale:** {request.rationale or "(none)"}
- **Alert type:** {payload.get("alert_type") or "(unknown)"}
- **Rule name:** {payload.get("rule_name") or "(unknown)"}
- **Rule id:** {payload.get("rule_id") or "(unknown)"}
- **Related alert id:** {alert_id or "(unknown)"}
- **Why needed:** {payload.get("why_needed") or "(not provided)"}
- **Investigation summary:** {payload.get("investigation_summary") or "(not provided)"}
- **Example entities:** {payload.get("example_entities") or "(not provided)"}
- **Author brief / description:**
{payload.get("description") or payload.get("suggestion") or "(not provided)"}

{_json_block("Coverage check", payload.get("coverage_check"))}
{_json_block("Near matches (do not duplicate these)", payload.get("near_matches"))}
{_json_block("Existing case runbooks", existing, limit=6000)}
{_json_block("Last investigated alert (full details — use as the concrete example)", alert)}

## How to build the runbook (follow existing work)
1. Call `list_runbooks` with `soc_tier="{soc_tier}"` and `category="cases"`.
2. Call `get_runbook` on `{primary_example}` (and optionally one more similar case) to mirror structure, tone, and section naming.
3. Optionally call `get_runbook` on `soc1/triage/initial_alert_triage` for SOC1 fundamentals.
4. Draft a NEW playbook specialized for this alert type / rule. Do **not** copy-paste unrelated malware/login steps if they do not apply — adapt from the examples.
5. Required markdown structure (same as `run_books/runbook_guidelines.md` and existing `soc1/cases/*.md`):
   - `# SOC1: <Name> Runbook`
   - `## Objective`
   - `## Scope` (includes + excludes)
   - `## SOC Tier`
   - `## Inputs` — MUST include `${{ALERT_ID}}` as REQUIRED; use `${{VARIABLE}}` uppercase names
   - `## Outputs`
   - `## Tools` — wrap every tool name in backticks; group by SIEM / NetBox / CTI / EDR / Runbook as needed
   - `## Workflow Steps` — numbered; **step 1 MUST be Receive Alert (MANDATORY)** calling `get_security_alert_by_id`
   - Include mandatory history: closed/ack same-type alerts + **`get_alert_notes`** on matching past alerts
   - Prefer structured SIEM skills first; when free-form search is needed use the right query skill (`search_kql_query`, `search_lucene_query`, `search_eql_query`, `search_dsl_query`, `search_esql_query`)
   - `## Completion Criteria`
   - `## Escalation Criteria` (when applicable)
   - Optional `## Warning` / `## Notes`
6. SOC1 rules: start from alerts only; primary mission is FP/BTP closure via Requests (`close_alert`); do **not** teach `create_case` for SOC1 triage; if uncertain → full alert note + honest verdict, no case.
7. Ground the playbook in the investigated alert above (entities, rule, what worked / what was missing).
8. When the markdown is ready, call:
   `save_case_runbook` with `path="{target_path}"` and `content=<full markdown>`.
   Only use `overwrite=true` if the file already exists and replacement is clearly correct.
9. After a successful save, briefly confirm the path and stop. Do not file another `create_runbook_recommendation`.

Write the runbook now.
"""
    return {
        "prompt": prompt,
        "target_path": target_path,
        "session_name": session_name,
        "soc_tier": soc_tier,
        "alert_id": alert_id,
        "example_runbook": primary_example,
    }
