# SOC1: Close False Positive Runbook

Close a case that has been identified as a false positive or benign true positive during SOC1 triage. **Note:** SOC1's primary role is closing false positives. This runbook ensures proper documentation and closure procedures. SOC1 should also close the associated alert using `close_alert`.

## Scope

This runbook covers:
*   Documenting false positive/benign true positive findings.
*   Closing the case with appropriate status.
*   Ensuring proper documentation for future reference.

## SOC Tier

**Tier:** SOC1 (Tier 1)  
**Authority:** SOC1 can close false positives and benign true positives

## Inputs

*   `${ALERT_ID}`: **REQUIRED** - The alert ID associated with the case. SOC1 should have the alert ID from initial triage.
*   `${CASE_ID}`: The case ID to close (if case was created).
*   `${CLOSURE_REASON}`: The reason for closure (e.g., "False Positive", "Benign True Positive", "Duplicate").
*   `${CLOSURE_DETAILS}`: Detailed explanation of why this is a false positive/benign true positive.
*   *(Optional) `${SIMILAR_CASE_ID}`: If closing as duplicate, the similar case ID.*

## Outputs

*   `${CLOSURE_STATUS}`: Status of the closure operation.
*   `${DOCUMENTATION_STATUS}`: Status of documentation.

## Tools

*   **Case Management Tools:** `review_case`, `add_case_comment`, `update_case_status`
*   **Engineering Tools:** `list_fine_tuning_recommendations`, `create_fine_tuning_recommendation`, `add_comment_to_fine_tuning_recommendation`

## Workflow Steps

1.  **Receive Input:** Obtain `${CASE_ID}`, `${CLOSURE_REASON}`, `${CLOSURE_DETAILS}`, and optionally `${SIMILAR_CASE_ID}`.

2.  **Review Case Details:**
    *   Use `review_case` with `case_id=${CASE_ID}` to get current case status.
    *   Verify case is appropriate for closure (not already closed, not escalated to SOC2/SOC3).

3.  **Document Closure Reason:**
    *   Prepare closure comment: `CLOSURE_COMMENT = "SOC1 Closure: ${CLOSURE_REASON}. Details: ${CLOSURE_DETAILS}. ${if SIMILAR_CASE_ID: 'Duplicate of case: ' + SIMILAR_CASE_ID + '.'} Closed by: SOC1 Analyst."`
    *   Use `add_case_comment` with `case_id=${CASE_ID}` and `content=${CLOSURE_COMMENT}`.
    *   Set `${DOCUMENTATION_STATUS}` = "Documented".

4.  **Create or Update Fine-Tuning Recommendation (if False Positive):**
    *   If `${CLOSURE_REASON}` is "False Positive":
        *   Extract alert/rule pattern from `${CLOSURE_DETAILS}` (e.g., alert type, rule name, detection pattern).
        *   Use `list_fine_tuning_recommendations` with `include_closed=false` to search for existing tasks matching the alert/rule pattern.
        *   Check if any existing task matches the pattern (compare task names/descriptions with alert type or rule name).
        *   **If matching task found:**
            *   Extract `task_id` from the matching task.
            *   Prepare comment: `FINE_TUNING_COMMENT = "Additional false positive observed. Case ID: ${CASE_ID}. Closure reason: ${CLOSURE_DETAILS}. Total false positives for this pattern: [count if available]."`
            *   Use `add_comment_to_fine_tuning_recommendation` with `task_id=${task_id}` and `comment_text=${FINE_TUNING_COMMENT}`.
        *   **If no matching task found:**
            *   Prepare task title: `TASK_TITLE = "Reduce false positives for [Alert Type / Rule Name]"` (extract from case/alert context).
            *   Prepare task description: `TASK_DESCRIPTION = "Case ${CASE_ID} was closed as false positive. Details: ${CLOSURE_DETAILS}. Consider adjusting rule threshold, adding whitelist, or refining detection logic to reduce false positive rate."`
            *   Use `create_fine_tuning_recommendation` with `title=${TASK_TITLE}`, `description=${TASK_DESCRIPTION}`, and `tags=["false-positive", "fine-tuning"]`.
    *   *(Note: Skip this step if closure reason is "Benign True Positive" or "Duplicate".)*

5.  **Close Alert and Case:**
    *   **Close the alert**: Use `close_alert` with `alert_id=${ALERT_ID}`, `reason=${CLOSURE_REASON}`, and `comment=${CLOSURE_COMMENT}`.
    *   **If case exists**: Use `update_case_status` with `case_id=${CASE_ID}` and `status="closed"`.
    *   Set `${CLOSURE_STATUS}` = "Alert and case closed successfully".

6.  **Completion:**
    *   Verify case status is "closed".
    *   Confirm documentation is complete.
    *   Verify fine-tuning recommendation was created or updated (if applicable).

## Completion Criteria

The case has been successfully closed:
*   Closure reason has been documented in case comments.
*   Case status has been updated to "closed".
*   All closure details are recorded for future reference.

## Closure Reasons

Valid closure reasons for SOC1:
*   **False Positive**: Alert triggered incorrectly (e.g., misconfiguration, test activity, known benign software).
*   **Benign True Positive**: Activity is legitimate and expected (e.g., scheduled maintenance, approved tool, authorized activity).
*   **Duplicate**: Case is a duplicate of an existing case.

## Notes

*   **SOC1's primary role is closing false positives** - this is the most important function.
*   Only close cases/alerts that have been properly triaged and confirmed as false positive/benign with high confidence.
*   **If uncertain about legitimacy, leave as open case with ALL alert details** rather than closing.
*   When in doubt, leave as open case and escalate to SOC2 rather than closing.
*   Ensure detailed documentation for future reference and pattern identification.
*   Always close both the alert (using `close_alert`) and the case (if case was created).

