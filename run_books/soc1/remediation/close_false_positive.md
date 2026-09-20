# SOC1: Close False Positive Runbook

Close an alert that SOC1 has confirmed as a false positive or benign true positive. **Alert-only — do not create cases.** A final `update_alert_verdict` is **mandatory** before filing `close_alert`.

## Scope

* Document FP/BTP findings on the alert.
* Set the AI verdict immediately.
* Queue official close via `close_alert` (Requests approval).
* Optionally file/update a fine-tuning recommendation.

## SOC Tier

**Tier:** SOC1 (Tier 1)  
**Authority:** SOC1 can recommend FP/BTP closure (analyst approves the close)

## Inputs

* `${ALERT_ID}`: **REQUIRED**
* `${CLOSURE_REASON}`: `false_positive` | `benign_true_positive` | Duplicate-as-FP explanation
* `${CLOSURE_DETAILS}`: Detailed explanation (NetBox + same-type history when available)

## Outputs

* `${FINAL_VERDICT}`: Must be `false_positive` or `benign_true_positive`
* `${CLOSURE_STATUS}`: Close request status
* `${DOCUMENTATION_STATUS}`: Note/documentation status

## Tools

* **SIEM:** `get_security_alert_by_id`, `update_alert_verdict`, `add_alert_note`, `close_alert`
* **Engineering:** `list_fine_tuning_recommendations`, `create_fine_tuning_recommendation`, `add_comment_to_fine_tuning_recommendation`

## Workflow Steps

1. **Receive input:** `${ALERT_ID}`, `${CLOSURE_REASON}`, `${CLOSURE_DETAILS}`.

2. **Confirm alert:** `get_security_alert_by_id` — ensure this is the alert being closed.

3. **Document on the alert:**
   * `add_alert_note` with SOC1 closure details (`${CLOSURE_DETAILS}`).
   * Set `${DOCUMENTATION_STATUS}` = "Documented".

4. **MANDATORY — set final verdict:**
   * Call `update_alert_verdict` with `false_positive` or `benign_true_positive` and a comment summarizing why.
   * Set `${FINAL_VERDICT}` to that value.
   * **Do not skip this step.** Verdict is required even if close will be queued next.

5. **Fine-tuning (if False Positive):**
   * Search existing recommendations; comment or create as appropriate.

6. **Queue close:**
   * `close_alert` with `alert_id=${ALERT_ID}`, `reason=${CLOSURE_REASON}`, `comment=...`.
   * Do not claim the alert is already closed.
   * Set `${CLOSURE_STATUS}` = "Close requested (pending analyst approval)".

## Completion Criteria

* `update_alert_verdict` was called with a final FP/BTP value (`${FINAL_VERDICT}` set).
* Alert note documents the reason.
* `close_alert` was filed for Requests.
* No case was created.

## Notes

* **Verdicts are always required** for SOC1 — including this closure path.
* If uncertain, do **not** use this runbook; set `uncertain` / `true_positive` on the alert instead and stop.
