"""Enrich runbook-gap Requests with existing case-playbook coverage.

When SOC1 finishes triage without a matching ``soc*/cases/*`` playbook, the
agent files ``create_runbook_recommendation``. Enrichment lists existing case
runbooks and flags near-matches so analysts do not duplicate work.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...core.logging import get_logger

logger = get_logger("sami.runbook_gaps")

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_+.-]{2,}", re.I)
_STOPWORDS = {
    "the", "and", "for", "with", "from", "this", "that", "soc1", "soc2", "soc3",
    "case", "cases", "runbook", "playbook", "triage", "initial", "alert", "alerts",
    "investigation", "need", "needs", "missing", "gap", "please", "should",
}


def runbooks_dir() -> Path:
    override = os.environ.get("SAMI_RUNBOOKS_DIR", "").strip()
    if override:
        return Path(override)
    # src/ai_controller/approval_queue -> project root
    return Path(__file__).resolve().parents[3] / "run_books"


def _tokens(*parts: Optional[str]) -> List[str]:
    blob = " ".join(p for p in parts if p)
    found = []
    for match in _TOKEN_RE.finditer(blob.lower()):
        tok = match.group(0)
        if tok in _STOPWORDS or len(tok) < 3:
            continue
        if tok not in found:
            found.append(tok)
    return found


def list_case_runbooks(soc_tier: Optional[str] = "soc1") -> List[Dict[str, str]]:
    """Return compact metadata for case-specific playbooks under ``*/cases/*.md``."""
    root = runbooks_dir()
    if not root.is_dir():
        return []

    hits: List[Dict[str, str]] = []
    for path in sorted(root.rglob("cases/*.md")):
        rel = path.relative_to(root).as_posix()
        if soc_tier and f"/{soc_tier}/" not in f"/{rel}" and not rel.startswith(f"{soc_tier}/"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        title = ""
        for line in text.splitlines():
            if line.startswith("# "):
                title = line[2:].strip()
                break
        objective = ""
        if "## Objective" in text:
            after = text.split("## Objective", 1)[1]
            chunk = after.split("## ", 1)[0].strip()
            objective = " ".join(chunk.split())[:280]
        hits.append(
            {
                "path": rel[:-3] if rel.endswith(".md") else rel,
                "name": path.stem,
                "title": title or path.stem,
                "objective": objective,
            }
        )
    return hits


def _score_match(query_tokens: List[str], runbook: Dict[str, str]) -> int:
    hay = " ".join(
        [
            runbook.get("path", ""),
            runbook.get("name", ""),
            runbook.get("title", ""),
            runbook.get("objective", ""),
        ]
    ).lower()
    return sum(1 for tok in query_tokens if tok in hay)


def enrich_runbook_gap(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Attach coverage evidence for a runbook-gap recommendation."""
    enriched = dict(payload)
    soc_tier = str(enriched.get("soc_tier") or "soc1").strip().lower() or "soc1"
    existing = list_case_runbooks(soc_tier=soc_tier)
    enriched["existing_case_runbooks"] = existing

    query_tokens = _tokens(
        enriched.get("alert_type"),
        enriched.get("rule_name"),
        enriched.get("suggested_path"),
        enriched.get("title"),
        enriched.get("description"),
    )
    scored = []
    for rb in existing:
        score = _score_match(query_tokens, rb)
        if score > 0:
            scored.append({**rb, "score": score})
    scored.sort(key=lambda item: item["score"], reverse=True)
    near = scored[:5]
    enriched["near_matches"] = near

    if near and near[0]["score"] >= 2:
        status = "possible_match"
        note = (
            f"Possible existing playbook: `{near[0]['path']}`. "
            "Confirm it does not already cover this alert type before authoring a new one."
        )
    elif existing and not near:
        status = "likely_gap"
        note = (
            f"No near match among {len(existing)} case playbook(s) for {soc_tier}. "
            "A new case runbook is likely needed."
        )
    elif not existing:
        status = "likely_gap"
        note = f"No case playbooks found under run_books/{soc_tier}/cases/."
    else:
        status = "likely_gap"
        note = "Weak/no name overlap with existing case playbooks; treat as a gap unless an analyst disagrees."

    enriched["coverage_check"] = {
        "status": status,
        "soc_tier": soc_tier,
        "case_runbook_count": len(existing),
        "near_match_count": len(near),
        "note": note,
    }
    if not enriched.get("suggested_path") and enriched.get("rule_name"):
        slug = re.sub(r"[^a-z0-9]+", "_", str(enriched["rule_name"]).lower()).strip("_")
        if slug:
            enriched["suggested_path"] = f"{soc_tier}/cases/{slug}_triage"
    return enriched
