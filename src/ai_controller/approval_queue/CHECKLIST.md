# Requests view — action checklist

Analyst approval queue in the SamiGPT web UI (**Views → Requests**).

The AI files a request with the payload needed to run later. Irreversible MCP
tools (`close_alert`, isolate, kill process, fine-tune, …) are queued here
instead of executing immediately. Close / escalate run against the
**Elastic cluster bound to the request**.

`update_alert_verdict` is **not** an approval item. It is the AI's working
assessment and runs immediately. Closing the alert still requires approval.

Critical follow-ups after **Is this you?** (isolate, kill process, disable user)
are **not** auto-run. They become a second pending request.

## Status legend

| Status | Meaning |
|---|---|
| **Done** | Approve runs the action against a connected integration |
| **Ready if configured** | Handler exists; needs that integration client in `config.json` |
| **Queued locally** | Request is stored; push to an external board/API still pending |
| **Needs API** | Payload is stored; no executor wired yet |

## Checklist

| Action | Payload stored | On approve | Status |
|---|---|---|---|
| **Close alert** | `alert_id`, reason, comment, cluster | Elastic `close_alert` | **Done** |
| **Is this you?** | user, IP, host, time, question | **Yes** → ACK (close as benign TP). **No** → escalate (TP tag + case) | **Done** (follow-up close uses SIEM; case needs IRIS/TheHive) |
| **Fine-tune** | title, description, rule/alert | Engineering board if Trello/ClickUp/GitHub is configured | **Queued locally**; board push needs ENG |
| **Visibility gap** | title, description, missing source | Same as fine-tune | **Queued locally**; board push needs ENG |
| **Open case** | title, description, priority, alert | IRIS / TheHive `create_case` | **Ready if configured** (case management) |
| **Close case** | `case_id`, comment | Case status → closed | **Ready if configured** (case management) |
| **Escalate** | alert, notes, priority | TP tag + verdict + case | **Done** for SIEM steps; case needs IRIS/TheHive |
| **Isolate endpoint** | `endpoint_id`, hostname, reason | EDR isolate | **Needs API** (EDR / Elastic Defend) |
| **Release isolation** | `endpoint_id` | EDR release | **Needs API** (EDR) |
| **Kill process** | `endpoint_id`, PID | EDR kill | **Needs API** (EDR) |
| **Collect forensics** | `endpoint_id`, artifact types | EDR collect | **Needs API** (EDR) |
| **Block indicator** | indicator, type, reason | Firewall / proxy / EDR block | **Needs API** |
| **Disable user** | username, directory | IAM / directory disable | **Needs API** |
| **Reset credentials** | username | IAM password/session reset | **Needs API** |
| **Contain email** | message id, sender, subject | Mail-gateway quarantine/recall | **Needs API** |

## Automatic (no approval)

| Action | What it does | Status |
|---|---|---|
| **AI verdict** (`update_alert_verdict`) | Writes the investigator's working assessment (`in-progress`, FP, BTP, TP, uncertain). Does not close the alert. | **Runs immediately** |

## How requests get filed

- MCP tool `create_approval_request` (preferred for identity checks and custom follow-ups)
- Calling a gated MCP tool (`close_alert`, `isolate_endpoint`, `kill_process_on_endpoint`, `collect_forensic_artifacts`, `release_endpoint_isolation`, `create_fine_tuning_recommendation`, `create_visibility_recommendation`) — those enqueue instead of running
- `POST /api/requests` (manual / tests)

Action types and required fields live in `catalog.py`. Handlers live in `actions.py`.
