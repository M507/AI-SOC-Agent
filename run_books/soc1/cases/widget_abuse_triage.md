# SOC1: Widget Abuse Alert Triage Runbook

## Objective

Perform fast, alert-only triage of **Widget Abuse** detections (and similarly named widget/plugin misuse rules). **SOC1 MUST ALWAYS BEGIN FROM SECURITY ALERTS (`${ALERT_ID}`), NEVER FROM EXISTING CASES.** Use NetBox to verify whether the host’s documented role explains the widget activity, then pivot on the primary entities (host + user) to see related alerts and events. Close clear FP/BTP via Requests; otherwise leave a full alert note and a final verdict — **do not create a case**.

**Concrete example entities:** host `lab-1`, user `bob`.

## Scope

This runbook covers:
*   Widget Abuse / widget-misuse alert triage starting from `${ALERT_ID}`.
*   Same-type closed/ack history review including **`get_alert_notes`**.
*   NetBox role/purpose check for the affected host (and related IPs when present).
*   Lightweight entity pivot on host and user (and top related indicators).
*   FP/BTP close requests or documented TP/uncertain handoff on the alert.

This runbook explicitly **excludes**:
*   Creating IRIS/TheHive cases (`create_case` and all case-write tools).
*   Deep widget/plugin forensics or reverse engineering.
*   Account lockdown, endpoint isolation, or other containment (gated response workflows only).
*   Full attack-chain reconstruction (human / later-tier follow-up).

## SOC Tier

**Tier:** SOC1 (Tier 1)  
**Escalation Target:** Human / later-tier review via alert note + final verdict (`true_positive` or `uncertain`). Do **not** create a case.

## Inputs

*   `${ALERT_ID}`: **REQUIRED** — SIEM alert id. SOC1 MUST ALWAYS START FROM `${ALERT_ID}`.
*   `${HOSTNAME}`: Primary host from the alert (example: `lab-1`). Extract if not provided.
*   `${USER_ID}`: Primary user from the alert (example: `bob`). Extract if not provided.
*   *(Optional) `${SOURCE_IP}` / `${WIDGET_NAME}` / `${PROCESS_NAME}`: Additional keys when present in event data.*
*   *(Optional) `${TIME_FRAME_HOURS}`: Lookback for pivots (default: 24–48 for SOC1 efficiency; history review ≥ 168 hours).*

## Outputs

*   `${ASSESSMENT}`: FP | BTP | TP | Uncertain (must match final `update_alert_verdict`).
*   `${ACTION_TAKEN}`: What was done on the alert (close requested vs documented handoff).
*   `${ALERT_COMPLETE_DETAILS}`: Full alert payload and extracted fields.
*   `${KEY_ENTITIES}`: Host, user, and other material keys (e.g. `lab-1`, `bob`).
*   `${RULE_ID}`, `${RULE_NAME}`: Detection rule / alert type.
*   `${NETBOX_CONTEXT}`: Role, tags, description, site/tenant for the host/IP.
*   `${HISTORICAL_DECISIONS}`: Same-type / same-key closed+ack history with verdicts and note takeaways.
*   `${PIVOT_SUMMARY}`: Related alerts/events from host + user (and top indicator) pivots.
*   `${IOC_MATCH_RESULTS}`: Lightweight IOC check results.
*   `${FINAL_VERDICT}`: Final value passed to `update_alert_verdict` (required; never leave `in-progress`).

## Tools

*   **SIEM – alert management:** `get_security_alert_by_id`, `get_alert_notes`, `update_alert_verdict`, `add_alert_note`, `close_alert`, `get_recent_alerts`
*   **SIEM – past decisions (MANDATORY):** `get_rule_detections`, `get_security_alerts`, `get_alerts_by_entity`
*   **SIEM – entity pivot / enrichment:** `lookup_entity`, `pivot_on_indicator`, `search_user_activity`, `search_security_events`, `search_kql_query`, `search_lucene_query`, `search_eql_query`, `search_dsl_query`, `search_esql_query`, `get_alerts_by_time_window`, `get_ioc_matches`, `get_ip_address_report`, `get_network_events`
*   **NetBox:** `netbox_lookup_host`, `netbox_lookup_ip`, `netbox_lookup_prefix`, `netbox_search`
*   **Engineering (when applicable):** `list_fine_tuning_recommendations`, `create_fine_tuning_recommendation`, `add_comment_to_fine_tuning_recommendation`, `create_visibility_recommendation`
*   **Forbidden in this runbook:** `create_case`, `search_cases`, `list_cases`, `review_case`, `add_case_comment`, `attach_observable_to_case`, `update_case_status`, `add_case_task`, and other case-write tools

## Workflow Steps

1.  **Receive Alert (MANDATORY):**
    *   **SOC1 MUST ALWAYS START FROM `${ALERT_ID}`** — never from an existing case.
    *   Obtain `${ALERT_ID}` from the SIEM alert queue / `get_recent_alerts`.
    *   **MUST use `get_security_alert_by_id` with `alert_id=${ALERT_ID}` as the FIRST action.**
    *   Store ALL alert details in `${ALERT_COMPLETE_DETAILS}` (alert id, rule name/id, severity, timestamps, event data, host, user, widget/process names, IPs, ports, command lines, metadata).
    *   If a final verdict already exists, stop (already investigated).
    *   Extract `${HOSTNAME}` (e.g. `lab-1`), `${USER_ID}` (e.g. `bob`), optional `${SOURCE_IP}` / `${WIDGET_NAME}` / `${PROCESS_NAME}` into `${KEY_ENTITIES}` (keep to 3–5 material keys).
    *   Extract `${RULE_ID}` and `${RULE_NAME}` (Widget Abuse / matching rule).

2.  **Past Decisions Review (MANDATORY — before NetBox / pivot / close):**
    *   **Same alert type — closed:** `get_rule_detections` with `rule_id`/`rule_name`, `alert_state="closed"`, `hours_back` ≥ 168; and/or `get_security_alerts` with `status_filter="closed"`.
    *   **Same alert type — acknowledged:** Repeat with `acknowledged` / `akn` / `ack`.
    *   **Same main values:** For `${HOSTNAME}` and `${USER_ID}` (and top IP/widget if present), call `get_alerts_by_entity` with multi-day lookback; prefer overlaps that also match `${RULE_NAME}` / `${RULE_ID}`. For host-centric alerts, also filter `get_security_alerts` by `hostname=${HOSTNAME}` + rule + closed/ack.
    *   **Read verdicts and notes (MANDATORY):** For the strongest matches (e.g. 3–8), open with `get_security_alert_by_id` and batch `get_alert_notes` (`alert_ids`). Notes are **not** on alert `_source`. Also `get_alert_notes` on the current `${ALERT_ID}` when present.
    *   Summarize into `${HISTORICAL_DECISIONS}`: overlapping keys, prior verdicts, closed vs ack counts, note takeaways, lean (supports FP/BTP | warns against close | conflicting | none found).
    *   **Do not proceed to NetBox or closure until `${HISTORICAL_DECISIONS}` is populated** (or explicitly “no history found”), including an explicit notes check.

3.  **Lock Alert (MANDATORY verdict #1):**
    *   Call `update_alert_verdict` with `verdict="in-progress"` and a short locking comment.
    *   Do not continue until this succeeds.

4.  **NetBox Role Check (PRIMARY for Widget Abuse):**
    *   For `${HOSTNAME}` (example `lab-1`): use `netbox_lookup_host`. If only an IP is known, use `netbox_lookup_ip` / `netbox_lookup_prefix`; fall back to `netbox_search` when needed.
    *   Capture **role, tags, description, site/tenant** into `${NETBOX_CONTEXT}`.
    *   Decision framing for widget abuse:
        *   Role/tags/description indicate a **lab, demo, widget-dev, or UI-test** host where widget installs/automation are expected → lean FP/BTP **if** history agrees and no IOC hits.
        *   Role is production / user workstation / high-value / missing NetBox record, or description contradicts widget misuse → do **not** auto-close; enrich and document.
        *   Example: `lab-1` documented as a lab/dev host with widget testing → role may explain activity for user `bob`; still verify history + pivots.

5.  **Entity Pivot (after NetBox):**
    *   **Host pivot:** `lookup_entity` with `entity_value=${HOSTNAME}`, `entity_type="hostname"`. Then `pivot_on_indicator` with `indicator=${HOSTNAME}` (limit ~24–48h). Use `get_alerts_by_entity` for the host.
    *   **User pivot:** `lookup_entity` with `entity_value=${USER_ID}`, `entity_type="user"`. Use `search_user_activity` with `username=${USER_ID}` (limit ~50). Then `pivot_on_indicator` / `get_alerts_by_entity` for the user (example: `bob`).
    *   **Optional related keys:** If `${SOURCE_IP}` or `${WIDGET_NAME}` is material, light pivot/`get_ioc_matches` / `get_ip_address_report` (keep to top 1–2 extras). Prefer structured tools before free-form `search_*_query`.
    *   **Time-window correlation:** `get_alerts_by_time_window` around the alert timestamp if host/user pivots show clustered activity.
    *   Store a concise `${PIVOT_SUMMARY}`: other widget-abuse or related alerts on `lab-1` / `bob`, unusual process/network peers, blast radius (single host vs many).
    *   **IOC check:** `get_ioc_matches` on top 2–3 entities → `${IOC_MATCH_RESULTS}`.

6.  **Assess (no case):**
    *   Combine `${HISTORICAL_DECISIONS}`, `${NETBOX_CONTEXT}`, `${PIVOT_SUMMARY}`, `${IOC_MATCH_RESULTS}`.
    *   **Close as FP/BTP** when: same rule + same host/user history consistently FP/BTP with consistent notes **and/or** NetBox role explains widget activity, **and** no IOC hits, **and** pivots show no unexplained suspicious spread.
    *   **Do not close** when: history missing/conflicting/TP/uncertain or notes show real risk, **or** NetBox missing/contradicts, **or** IOC hits / multi-host spread / unexplained pivots remain.
    *   Set `${ASSESSMENT}` accordingly.

7.  **FP/BTP Closure (no case) — MANDATORY final verdict:**
    *   `add_alert_note` citing history (verdicts + note takeaways), NetBox role match, pivot summary (host `lab-1` / user `bob` as applicable), and IOC results.
    *   **MANDATORY:** `update_alert_verdict` → `false_positive` or `benign_true_positive` (set `${FINAL_VERDICT}`).
    *   `close_alert` with appropriate reason + comment. Close is **queued for Requests** — do not claim the alert is already closed.
    *   If the rule is noisy for known lab/widget roles, create/update a fine-tuning recommendation (`list_fine_tuning_recommendations` → comment or `create_fine_tuning_recommendation` with tags like `["false-positive", "fine-tuning", "soc1-triage", "widget-abuse"]`).
    *   Set `${ACTION_TAKEN}` = "AI verdict recorded; close requested (pending analyst approval)." End.

8.  **TP / Uncertain Handoff (still no case) — MANDATORY final verdict:**
    *   Prefer a short additional targeted search only if pivots left a gap; keep light.
    *   Choose **final** verdict: `true_positive` or `uncertain` only — never end on `in-progress`.
    *   `add_alert_note` MUST include:
        1. Alert id, rule name/id, severity, key entities (`lab-1`, `bob`, …)
        2. `${NETBOX_CONTEXT}` match or mismatch
        3. `${HISTORICAL_DECISIONS}` including `get_alert_notes` takeaways
        4. `${PIVOT_SUMMARY}` and `${IOC_MATCH_RESULTS}`
        5. Why not closed and what a human should check next (widget legitimacy, user intent, lateral activity)
    *   **MANDATORY:** `update_alert_verdict` with that final assessment (`${FINAL_VERDICT}`).
    *   If visibility gaps blocked triage (missing NetBox, weak widget telemetry), optionally `create_visibility_recommendation`.
    *   **Do not create a case.** Set `${ACTION_TAKEN}` = "Alert documented with final verdict; no case created." End.

## Completion Criteria

The Widget Abuse alert has been successfully triaged by SOC1 when:
*   **MANDATORY:** Workflow started from `${ALERT_ID}`; `get_security_alert_by_id` was the first action.
*   **MANDATORY:** `${HISTORICAL_DECISIONS}` built before close/TP — closed + ack same-type search, key overlap (host/user), and **`get_alert_notes`** on matches (or explicit no history / empty notes).
*   NetBox role check completed for the primary host/IP (`${NETBOX_CONTEXT}`).
*   Entity pivots completed for host and user (`${PIVOT_SUMMARY}`).
*   `update_alert_verdict` called for lock (`in-progress`) and a **final** value (`false_positive` | `benign_true_positive` | `true_positive` | `uncertain`).
*   `${FINAL_VERDICT}` is set and is **not** `in-progress`.
*   Either a `close_alert` request was filed **or** a complete non-close alert note was written.
*   **No case was created.**

## Escalation Criteria

Hand off via **alert note + final verdict** (not a new case) when:
*   Past decisions/notes do not support FP/BTP or conflict.
*   NetBox role is missing or contradicts widget abuse on the host (e.g. production host, not a lab like `lab-1`).
*   Pivots show related suspicious activity for the user (e.g. `bob`) or additional hosts.
*   IOC matches or clear true-positive indicators exist.
*   Uncertainty remains after history + NetBox + light pivots.

## Notes

*   **MANDATORY: SOC1 MUST ALWAYS START FROM `${ALERT_ID}`** — never begin from existing cases.
*   **Past decisions come first**, then **NetBox role**, then **entity pivot** — that order is intentional for Widget Abuse noise (labs/dev hosts).
*   Alert notes are **not** on `_source`; always use `get_alert_notes`.
*   Example grounding: host `lab-1` + user `bob` — verify NetBox says `lab-1` is expected to run/test widgets before closing; pivots confirm whether `bob`’s activity is isolated or part of a wider pattern.
*   Verdicts are always required — finishing without a final `update_alert_verdict` is a process failure.
*   SOC1 never creates cases in this runbook.
