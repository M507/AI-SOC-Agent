# Requests view — action checklist

Analyst queue in the SamiGPT web UI (**Views → Requests**).

The AI files a request with the payload needed to run later. Irreversible MCP
tools (`close_alert`, isolate, kill process, collect forensics) are queued here
instead of executing immediately. Close, escalate, and Elastic Security cases
run against the **Elastic cluster bound to the request**.

**Fine-tune**, **Visibility gap**, and **Runbook gap** are **informational only**. They appear in
Requests so an analyst can read them. There is no Approve/Deny. Fine-tune / visibility
may also open a GitHub Issue when ENG is GitHub; runbook gaps use the `runbook` label when mirrored.

`update_alert_verdict` is **not** an approval item. It is the AI's working
assessment and runs immediately. Closing the alert still requires approval.

`create_elastic_case` is **not** gated. It opens a case in **Elastic Security
(Kibana Cases)**, not IRIS or TheHive. The case description always includes
the full SIEM alert (title, rule text, entities, triggering events, comments)
plus identity context when this came from **Is this you?**

Critical follow-ups after **Is this you?** (isolate, kill process, disable user)
are **not** auto-run. They become a second pending request.

## Status legend

| Status | Meaning |
|---|---|
| **Done** | Approve runs the action against a connected integration |
| **Ready if configured** | Handler exists; needs that integration client in `config.json` |
| **Informational** | Shown in Requests; no buttons; no side effects |
| **Needs API** | Payload is stored; no executor wired yet |

## Checklist

| Action | Payload stored | On approve | Status |
|---|---|---|---|
| **Close alert** | `alert_id`, reason, comment, cluster | Elastic `close_alert` | **Done** |
| **Is this you?** | `alert_id`, user, IP, host, time, activity, question | **Yes** → ACK (close as benign TP). **No** → escalate: TP tag + verdict + **Elastic Security case** with the full alert | **Done** (case uses Kibana Cases, not IRIS/TheHive) |
| **Fine-tune** | title, suggestion, `rule_id` / `rule_name`, pulled Home Lab rule (query, tags, exceptions) | **None** — no buttons | **Informational**. Rule is loaded from `/root/Home-Lab-Rules/rules/elastic_1/rules/` (override with `SAMI_LAB_RULES_DIR`). No engineering board. |
| **Visibility gap** | title, suggestion, missing source, `coverage_check` | **None** — no buttons | **Informational**. Catalog is searched first; the note includes whether a Home Lab rule already covers it. |
| **Runbook gap** | title, description, alert type / rule, suggested path, investigation summary, `coverage_check` (existing case playbooks) | **None** — no buttons | **Informational**. File **after** triage when no `soc*/cases` playbook matched. Does not block investigation. |
| **Open case (IRIS/TheHive)** | title, description, priority, alert | IRIS / TheHive `create_case` | **Ready if configured** (case management). Not used by **Is this you?** |
| **Close case** | `case_id`, comment | IRIS / TheHive case status → closed | **Ready if configured** (case management) |
| **Escalate** | `alert_id`, title, notes, priority, identity fields | TP tag + `true_positive` verdict + `create_elastic_case` (full alert body, alert attached when possible) | **Done**. Needs a Kibana API key with cases privileges (ES `:9200` key alone is not enough). Optional cluster `kibana_url` if Kibana is not `:5601` |
| **Isolate endpoint** | `endpoint_id` (Elastic Agent id), hostname, reason, cluster | Kibana Elastic Defend `POST /api/endpoint/action/isolate` | **Done**. Same bound cluster as cases. Needs a Kibana API key with host isolation / response-action privileges (ES `:9200` key alone is not enough). Optional cluster `kibana_url` if Kibana is not `:5601`. |
| **Release isolation** | `endpoint_id`, hostname, reason | Kibana `POST /api/endpoint/action/unisolate` | **Done**. Inverse of isolate. |
| **Kill process** | `endpoint_id`, PID | EDR kill | **Needs API** (EDR) |
| **Collect forensics** | `endpoint_id`, artifact types | EDR collect | **Needs API** (EDR) |
| **Block indicator** | indicator, type, reason | Firewall / proxy / EDR block | **Needs API** |
| **Disable user** | username, directory | IAM / directory disable | **Needs API** |
| **Reset credentials** | username | IAM password/session reset | **Needs API** |
| **Contain email** | message id, sender, subject | Mail-gateway quarantine/recall | **Needs API** |

## Home Lab rule lookup (token strategy)

Rules live on disk (~1.3k JSON files). The model must **not** load the catalog.

1. `search_lab_detection_rules` — 1–3 short keyword searches. Compact hits only (name, tags, data sources, indexes, ~360-char query excerpt). Default 8 hits, max 15.
2. `get_lab_detection_rule` — at most **one or two** full excerpts (query truncated, investigation `note` omitted).
3. `create_fine_tuning_recommendation` — server pulls the matching file and stores **rule + suggestion**. Informational.
4. `create_visibility_recommendation` — model searches first and should only file if coverage is still missing. The server **re-checks** on file and stores `coverage_check` (`likely_gap` / matching rules). Informational either way.
5. `create_runbook_recommendation` — **after** final verdict, if no case playbook matched. Server lists `soc*/cases` playbooks and stores near-matches. Informational.

Override path: env `SAMI_LAB_RULES_DIR`. Runbooks: env `SAMI_RUNBOOKS_DIR` (optional).

## Automatic (no approval)

| Action | What it does | Status |
|---|---|---|
| **AI verdict** (`update_alert_verdict`) | Writes the investigator's working assessment (`in-progress`, FP, BTP, TP, uncertain). Does not close the alert. | **Runs immediately** |
| **Elastic Security case** (`create_elastic_case`) | Opens a Kibana Security case on the bound cluster. Loads and attaches the SIEM alert. Used by **Is this you? → No** and by escalate. | **Runs immediately**. SIEM skill; tests in `tests/integrations/siem/elastic/test_elastic_cases.py` |
| **Search / get Home Lab rules** | Compact catalog search and one-rule excerpt. | **Runs immediately**. SIEM skill; local files, not Elastic. |

## How requests get filed

- MCP tool `create_approval_request` (preferred for identity checks and custom follow-ups). Default **No** follow-up is `escalate` → Elastic Security case.
- Calling a gated MCP tool (`close_alert`, `isolate_endpoint`, `kill_process_on_endpoint`, `collect_forensic_artifacts`, `release_endpoint_isolation`) — those enqueue and wait for approve.
- Calling `create_fine_tuning_recommendation`, `create_visibility_recommendation`, or `create_runbook_recommendation` — those file **informational** items (no approve).
- `POST /api/requests` (manual / tests)

`create_elastic_case` is a SIEM skill, not a gated Requests item. Calling it executes against Elastic immediately.

Action types and required fields live in `catalog.py`. Handlers live in `actions.py`. Rule catalog code lives in `lab_rules.py`.
