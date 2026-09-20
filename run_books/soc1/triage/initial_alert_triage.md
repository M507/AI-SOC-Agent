# SOC1: Initial Alert Triage Runbook

## Objective

Standardized SOC1 triage for SIEM alerts: start from the alert queue, **before assessing** read past closed/ack decisions for the same alert type and matching key values (IPs, hosts, users, …) including comments, use NetBox role context, **always set an alert verdict**, close clear FP/BTP without creating cases, and leave clear alert notes when not closing.

## Scope

**Included**
- Triage alerts from `get_recent_alerts`
- Full alert/event extraction via `get_security_alert_by_id`
- Same-type **and same-key** historical review (closed + acknowledged), including prior verdicts and comments
- NetBox identity/role verification
- Lightweight SIEM/IOC enrichment (3–5 entities)
- Alert verdicts (**MANDATORY** via `update_alert_verdict`), notes, and `close_alert` requests

**Excluded**
- Creating cases (`create_case` and all case-write tools)
- Deep investigation / attack-chain reconstruction
- Containment and response actions

## SOC Tier

- **Tier:** SOC1
- **Handoff:** If not closing, document on the alert for a human / later review. Do **not** create a case.

## Inputs

**Required**
- `${ALERT_ID}` selected from `get_recent_alerts` (alerts without a verdict)

**Must not**
- Start from `${CASE_ID}`

## Tools

**SIEM – alert management**
- `get_recent_alerts`, `get_security_alert_by_id`, `get_siem_event_by_id`
- `update_alert_verdict`, `add_alert_note`, `close_alert`

**SIEM – past decisions (MANDATORY before assessment)**
- `get_rule_detections` — same rule; `alert_state=closed|acknowledged`; `hours_back` ≥ 168
- `get_security_alerts` — `rule_name`/`rule_id` + `status_filter=closed|acknowledged` (+ `hostname` when useful)
- `get_alerts_by_entity` — same IPs / hosts / users / hashes / domains
- `get_security_alert_by_id` — **open matching past alerts and read their verdicts + comments/notes**

**SIEM – investigation**
- `search_security_events`
- Query languages (pick the right one): `search_kql_query` (KQL), `search_lucene_query` (Lucene), `search_eql_query` (EQL sequences), `search_dsl_query` (JSON DSL), `search_esql_query` (ES|QL)
- `get_network_events`, `get_dns_events`, `get_email_events`
- `get_alerts_by_time_window`
- `lookup_entity`, `get_ioc_matches`, `get_file_report`, `get_ip_address_report`

**NetBox**
- `netbox_lookup_ip`, `netbox_lookup_host`, `netbox_lookup_prefix`, `netbox_search`

**CTI / Engineering**
- `lookup_hash_ti`
- `list_fine_tuning_recommendations`, `create_fine_tuning_recommendation`, related comment tools
- visibility recommendation tools as needed

**Forbidden in this runbook**
- `create_case`, `search_cases`, `list_cases`, `review_case`, `add_case_comment`, `attach_observable_to_case`, `update_case_status`, `add_case_task`, and other case-write tools

## Outputs / variables

1. `${ASSESSMENT}` — FP | BTP | TP | Uncertain (**must match final `update_alert_verdict`**)
2. `${ACTION_TAKEN}` — what was done on the alert
3. `${ALERT_COMPLETE_DETAILS}`
4. `${KEY_ENTITIES}`
5. `${RULE_ID}`, `${RULE_NAME}` — detection rule / alert type
6. `${NETBOX_CONTEXT}`
7. `${HISTORICAL_DECISIONS}` — past closed/ack alerts for same type + matching keys, with verdicts and comment takeaways (**required before assessment**)
8. `${HISTORICAL_SAME_TYPE}` — optional alias/summary of rule-level history
9. `${IOC_MATCH_RESULTS}`
10. `${INITIAL_SIEM_CONTEXT}` (optional enrichment summary)
11. `${FINAL_VERDICT}` — the final value passed to `update_alert_verdict` (required)

---

## Verdict rule (MANDATORY)

**SOC1 must call `update_alert_verdict` on every alert it touches.**

1. After Step 2 → lock with `in-progress`.
2. Before ending the runbook → set a **final** verdict: `false_positive`, `benign_true_positive`, `true_positive`, or `uncertain`.
3. Never end a run leaving the alert only on `in-progress`.
4. If triage cannot continue, still set `uncertain` with a comment explaining the blocker.

## Workflow Steps

### 1. Receive alert (MANDATORY)

1. Call `get_recent_alerts` and select an alert without a verdict.
2. Set `${ALERT_ID}`.
3. If only a case id is provided, stop and require an alert id.

### 2. Retrieve alert details (MANDATORY first action on the alert)

1. Call `get_security_alert_by_id` with `${ALERT_ID}`.
2. If a verdict already exists, stop (already investigated).
3. Store full details in `${ALERT_COMPLETE_DETAILS}`.
4. Derive `${KEY_ENTITIES}` from event messages (3–5 most critical **relevant** keys for this alert type — IPs, hosts, users, hashes, domains, ports, processes as applicable).
5. Extract `${RULE_ID}` and `${RULE_NAME}` from the alert (alert type).

### 3. Past decisions review (MANDATORY — before NetBox / IOC / close decisions)

**Goal:** learn how L1/analysts already judged the **same alert type** with the **same main values**, including their comments.

1. **Same alert type — closed:**
   - `get_rule_detections` with `rule_id`/`rule_name`, `alert_state="closed"`, `hours_back=168` (or wider), `limit=50`
   - Optionally `get_security_alerts` with same rule + `status_filter="closed"`
2. **Same alert type — acknowledged:**
   - Repeat with `alert_state="acknowledged"` / `status_filter="acknowledged"` (`akn`/`ack` ok)
3. **Same main values:**
   - For each top key in `${KEY_ENTITIES}` (especially IPs and hosts), call `get_alerts_by_entity` with `hours_back` ≥ 168
   - Prefer/keep results that also share `${RULE_NAME}` / `${RULE_ID}` when identifiable
   - If hostname is central, also `get_security_alerts` with `hostname` + rule + closed/ack filters
4. **Read past verdicts and comments:**
   - Select the strongest matches (same rule **and** overlapping IPs/hosts/users/hashes/etc.)
   - For each (up to a small set, e.g. 3–8), call `get_security_alert_by_id`
   - Extract prior `verdict`, status (closed/ack), and **all comments/notes**
5. Summarize into `${HISTORICAL_DECISIONS}`:
   - Matching keys (which IPs/hosts/… overlapped)
   - Prior verdicts (FP/BTP/TP/uncertain) and closed vs ack counts
   - Short excerpts / takeaways from comments (why it was closed or acked)
   - Lean: supports FP/BTP close | warns against close | conflicting
6. **Do not proceed to NetBox/IOC/closure until `${HISTORICAL_DECISIONS}` is populated** (or explicitly recorded as “no history found”).

### 4. Lock alert (MANDATORY verdict #1)

1. Call `update_alert_verdict` with `verdict="in-progress"` and a short locking comment (may note that historical review is in progress / completed).
2. Do not proceed further until this call succeeds.

### 5. Quick assessment (no case)

#### 5.1 NetBox role / infra

1. For each primary host/IP: `netbox_lookup_host` / `netbox_lookup_ip` / `netbox_lookup_prefix` / `netbox_search` as needed.
2. Capture role, tags, description, site/tenant into `${NETBOX_CONTEXT}`.
3. Ask: does this alert match the system’s documented job? (e.g. movies VM + torrent ports; scanner host + scan traffic)

#### 5.2 IOC check

1. `get_ioc_matches` on top 2–3 entities → `${IOC_MATCH_RESULTS}`.

#### 5.3 Decision

**Close as FP/BTP (go to Step 6)** if:
- `${HISTORICAL_DECISIONS}` shows same rule + same key values repeatedly closed/acked as FP/BTP with consistent comments **and/or** NetBox role explains the behavior, **and**
- No IOC hits, **and**
- No unexplained suspicious patterns

**Do not close (go to Step 7)** if:
- History is missing/conflicting/TP/uncertain, **or** comments describe real risk, **or**
- NetBox missing/contradicts, **or**
- IOC hits / suspicious patterns remain

### 6. FP/BTP closure request (no case) — MANDATORY final verdict

1. `add_alert_note` citing `${HISTORICAL_DECISIONS}` (prior verdicts + comment takeaways) + NetBox + IOC results.
2. **MANDATORY:** `update_alert_verdict` → `false_positive` or `benign_true_positive` (set `${FINAL_VERDICT}`).
3. `close_alert` (queued for Requests). Do not claim the alert is already closed.
4. Optionally update/create a fine-tuning recommendation for noisy rules.
5. Set `${ASSESSMENT}` and `${ACTION_TAKEN}`; **end**.

### 7. Enrichment when not closing (still no case) — MANDATORY final verdict

1. Targeted SIEM searches / entity enrichment as needed (keep light).
2. Re-check history if new entities suggest additional past decisions to read.
3. Choose **final** working verdict: `uncertain` or `true_positive` only (do **not** leave `in-progress` when ending).
4. `add_alert_note` MUST include:
   - Rule name/id, key entities
   - `${HISTORICAL_DECISIONS}` (prior verdicts + comments summary)
   - NetBox match/mismatch
   - IOC/enrichment highlights
   - Why it was not closed and what a human should check next
5. **MANDATORY:** `update_alert_verdict` with that final assessment (set `${FINAL_VERDICT}`).
6. **Do not create a case.** Set `${ACTION_TAKEN}` = "Alert documented with final verdict; no case created." and **end**.

## Completion Criteria

- Workflow started from `${ALERT_ID}` with `get_security_alert_by_id` first.
- `${HISTORICAL_DECISIONS}` was built **before** close/TP decisions: closed + ack same-type search, key-value overlap, and `get_security_alert_by_id` on matches to read verdicts/comments (or explicit “no history”).
- `update_alert_verdict` was called for lock (`in-progress`) and **final** (`false_positive` | `benign_true_positive` | `true_positive` | `uncertain`).
- `${FINAL_VERDICT}` is set and is **not** `in-progress`.
- `${NETBOX_CONTEXT}` evaluated for primary hosts/IPs when present.
- Either a close request was filed **or** a clear non-close alert note was written.
- **No case was created.**

## Escalation Criteria

Escalate via **alert note + final verdict** (not a new case) when:
- Past decisions/comments do not support FP/BTP or conflict
- Behavior contradicts NetBox role
- IOC matches or clear TP indicators exist
- Uncertainty remains after history + NetBox + light enrichment

## Notes

- **Past decisions come first** — same alert type, same relevant keys, read comments, then decide.
- NetBox is the only infra knowledge base (role/purpose).
- **Verdicts are always required** — finishing without `update_alert_verdict` to a final value is a runbook failure.
- SOC1 never creates cases in this runbook.
