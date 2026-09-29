# Requests tab

Analyst queue in the SamiGPT web UI (**Views → Requests**). The agent files a request with the payload needed to run later. Approve (or Yes/No) is what applies the change. Deny archives the card and does not touch the SIEM, endpoint, or case.

Action types live in `src/ai_controller/approval_queue/catalog.py`. Handlers live in `src/ai_controller/approval_queue/actions.py`.

## How a request is filed

- Calling a gated MCP tool: `close_alert`, `add_alert_note`, `isolate_endpoint`, `release_endpoint_isolation`, `kill_process_on_endpoint`, `collect_forensic_artifacts`
- A `comment` on `update_alert_verdict` is filed as **Add alert note**. The verdict itself is written immediately
- `create_fine_tuning_recommendation`, `create_visibility_recommendation`, `create_runbook_recommendation` file informational notes (no Approve)
- `create_approval_request` for **Is this you?**, **Escalate**, and any type without a gated tool name
- `POST /api/requests` (manual / tests)

`create_elastic_case` is not a Requests item. Calling that skill opens a Kibana Security case immediately. The gated path that opens a Kibana case is **Escalate**.

## Tabs

| Tab | What it shows |
| --- | --- |
| SOC | SIEM, identity, EDR, case, IAM, email, network |
| Detection engineering | Fine-tune, visibility gap, runbook gap |
| Engineering | Items mirrored to a GitHub issue |
| All | Everything |

Open vs Archived: pending, informational, and waiting-on-integration stay Open. Denied, executed (Done), failed, and acknowledged (reviewed informational notes) are Archived.

## Actionable (Approve / Deny)

| Request | On Approve | Added | Closed / changed | Removed |
| --- | --- | --- | --- | --- |
| **Close alert** | Elastic `close_alert` on the bound cluster, after associated notes (see [Close also approves pending notes](#close-also-approves-pending-notes)) | Close comment on the Kibana close; `signal.ai.verdict` from the reason; associated note text on `signal.ai.comments.comment` | Alert workflow status → `closed` | Nothing. The alert document stays |
| **Add alert note** | Elastic `add_alert_note`. Also approved automatically when **Close alert** for the same alert is approved | One `{timestamp, comment, author: sami-gpt}` on `signal.ai.comments.comment` | Nothing | Nothing |
| **Isolate endpoint** | Kibana Elastic Defend `POST /api/endpoint/action/isolate` (EDR client if no SIEM isolate) | Isolation action on that host | Host is cut off the network | Nothing |
| **Release isolation** | Kibana `POST /api/endpoint/action/unisolate` | Unisolate action | Network access restored | Nothing |
| **Kill process** | EDR `kill_process_on_endpoint` if an EDR client exists | Nothing in SIEM | That PID is terminated | If no EDR: status **Waiting on integration**, nothing runs |
| **Collect forensics** | EDR `collect_forensic_artifacts` (default `processes`, `network`, `filesystem`) | Collected artifacts on the EDR side | Nothing closed | If no EDR: waiting, nothing runs |
| **Open case** | IRIS / TheHive `create_case` | A new case (title, description, priority, tags, optional alert id) | Nothing in Elastic | If no case client: waiting. This is **not** a Kibana Security case |
| **Close case** | IRIS / TheHive status → `closed` | Optional closing comment on the case | That case is closed | Case is not deleted. If no case client: waiting |
| **Escalate** | Tag + verdict + Kibana case | Tag `TP` on the alert; Kibana Security case with the full alert attached | Alert verdict → `true_positive` (comment from the escalation notes) | Alert is **not** closed. Not IRIS/TheHive. Needs a Kibana API key with cases privileges |
| **Block indicator** | Stub | Payload only | Nothing | No firewall / proxy / EDR block yet. Status **Waiting on integration** |
| **Disable user** | Stub | Payload only | Nothing | No AD / IdP disable yet |
| **Reset credentials** | Stub | Payload only | Nothing | No password / session reset yet |
| **Contain email** | Stub | Payload only | Nothing | No quarantine / recall yet |

Waiting-on-integration items stay Open. Approve only accepts `pending`; there is no retry button once a request is already waiting.

## Close also approves pending notes

Approving **Close alert** also approves every pending **Add alert note** for that same alert. You do not need to approve the note cards separately. The Requests card says how many notes will go with the close.

This applies to:

- Approve on a **Close alert** card
- Bulk Approve that includes a close
- **Is this you? → Yes** (that answer runs the same close path)

**Order:** associated notes are written first (`signal.ai.comments.comment`), then the alert is closed.

**Which notes count as associated**

- Same alert: `payload.alert_id` (or `alertId`) and the id on the enriched alert snapshot (`payload.alert.id` / `alert_id`)
- Same Elastic cluster when both the close and the note have a `cluster_id`. A note with no cluster inherits the close’s cluster and, if needed, the matched `alert_id`
- Notes for a different alert, or a different cluster when both ids are set, are left pending
- Already denied / executed / waiting notes are not touched

**Deny:** denying the close leaves those notes pending. They are not written.

A `comment` on `update_alert_verdict` is itself filed as a pending **Add alert note**. If the agent then files **Close alert** for that alert, approving the close writes that comment too.

## Is this you? (Yes / No)

No generic Approve. The analyst answers the identity question.

SOC1 may file this with `create_approval_request` (`action_type=identity_verify`) when a Yes/No on identity/expected use would actually decide the alert (login, VPN, RDP, admin, travel). It is **optional**. Uncertain alone is not a reason to file it. The card asks a yes/no `question`. Leave `follow_ups` empty so the defaults below apply.

| Answer | What runs | Added | Closed / changed |
| --- | --- | --- | --- |
| **Yes** | Close alert as benign true positive (and any pending **Add alert note** for that alert) | Close comment; associated notes | Alert closed; verdict benign true positive |
| **No** | Escalate | TP tag; Kibana Security case | Verdict `true_positive`. Alert stays open |

Isolate, kill process, disable user, and reset credentials after a Yes/No are **not** auto-run. They become a second pending request.

## Informational (no Approve)

Fine-tune, visibility gap, and runbook gap are review notes. **Done** only archives the card (GitHub issue stays open if linked). **Ignore** archives the card and closes the linked GitHub issue when ENG is GitHub.

| Request | On file | On Done | On Ignore | On Create runbook |
| --- | --- | --- | --- | --- |
| **Fine-tune detection** | Stores the suggestion plus the Home Lab rule snapshot. May open a GitHub issue | Archives locally | Archives locally; closes GitHub issue if linked | — |
| **Visibility gap** | Stores the gap note plus a catalog `coverage_check` | Same | Same | — |
| **Runbook gap** | Stores that a `soc*/cases` playbook is missing, plus near-matches | Archives locally | Same as above | Starts an Open WebUI session to write `run_books/soc1/cases/*.md`, then marks Done |

None of these change an Elastic rule, sensor, or alert.

## Not a Requests item

| Skill | What it does |
| --- | --- |
| `update_alert_verdict` | Writes the working assessment immediately (`in-progress`, FP, BTP, TP, uncertain). Does not close the alert. Optional `comment` is filed as **Add alert note** |
| `create_elastic_case` | Opens a Kibana Security case immediately on the bound cluster |
| `tag_alert` | Writes FP / TP / NMI on the alert immediately |
