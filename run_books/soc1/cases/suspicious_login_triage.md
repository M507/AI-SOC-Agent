# SOC1: Suspicious Login Alert Triage Runbook

Guide the initial triage of common suspicious login alerts (e.g., Impossible Travel, Login from Untrusted Location, Multiple Failed Logins) for SOC1 analysts. **SOC1 MUST ALWAYS BEGIN FROM SECURITY ALERTS (`${ALERT_ID}`), NEVER FROM EXISTING CASES.** This runbook focuses on gathering basic context to determine if escalation to SOC2 is needed, if the alert can be closed as a false positive, or if it should be left as an open case with comprehensive alert details if uncertain.

## Scope

This runbook covers:
*   Initial investigation steps to gather context about a suspicious login event.
*   Basic user history and source IP reputation checks.
*   Simple pattern identification.
*   Decision-making for escalation to SOC2 or closure.

This runbook explicitly **excludes**:
*   Deep user behavior analysis (SOC2 responsibility).
*   Account lockdown actions (SOC3 responsibility).
*   Advanced correlation with other security events (SOC2 responsibility).
*   Historical pattern deep-dive analysis (SOC2 responsibility).

## SOC Tier

**Tier:** SOC1 (Tier 1)  
**Escalation Target:** SOC2 for suspicious cases, SOC3 for account lockdown if high confidence

## Inputs

*   `${ALERT_ID}`: **REQUIRED** - The identifier for the security alert from the SIEM alert queue. SOC1 MUST ALWAYS START FROM `${ALERT_ID}`, never from `${CASE_ID}`.
*   *(Optional) `${USER_ID}`: The user ID associated with the suspicious login (extracted from alert if not provided).*
*   *(Optional) `${SOURCE_IP}`: The source IP address (extracted from alert if not provided).*
*   *(Optional) `${ALERT_DETAILS}`: Specific details from the alert (e.g., alert name, timestamp).*

## Outputs

*   `${ASSESSMENT}`: The outcome of the triage (e.g., "False Positive", "Benign True Positive", "True Positive/Suspicious").
*   `${ACTION_TAKEN}`: The action performed (e.g., "Closed", "Escalated to SOC2").
*   `${ESCALATION_RECOMMENDATION}`: Recommendation for escalation if suspicious.

## Tools

*   **Case Management Tools:** `review_case`, `add_case_comment`, `attach_observable_to_case`, `search_cases`, `add_case_task`
*   **SIEM Tools:** `get_security_alert_by_id`, `lookup_entity`, `search_security_events`, `search_user_activity`, `get_ip_address_report`, `pivot_on_indicator`, `get_ioc_matches`, `get_alerts_by_entity`, `get_alerts_by_time_window`
*   **Engineering Tools:** `list_fine_tuning_recommendations`, `create_fine_tuning_recommendation`, `add_comment_to_fine_tuning_recommendation`, `create_visibility_recommendation`

## Workflow Steps

1.  **Receive Alert (MANDATORY):** 
    *   **SOC1 MUST ALWAYS START FROM `${ALERT_ID}`** - this is the entry point for all SOC1 workflows.
    *   Obtain the `${ALERT_ID}` from the SIEM alert queue.
    *   **MUST use `get_security_alert_by_id` with `alert_id=${ALERT_ID}` as the FIRST action.**
    *   Extract and store ALL alert details in `${ALERT_COMPLETE_DETAILS}`:
        *   Alert ID, alert name/type, severity, detection rule name
        *   All timestamps
        *   Complete event data
        *   Host information, user information
        *   Source IP, destination IP, ports
        *   Any other alert metadata
    *   Obtain other optional inputs.

2.  **Extract Key Entities:**
    *   Review alert information from `get_security_alert_by_id` to extract the primary `${USER_ID}`, `${SOURCE_IP}`, and relevant `${HOSTNAME}`(s).
    *   If not provided upfront, extract from alert details.
    *   Handle cases where these might be missing.

3.  **User Context (SIEM):**
    *   Use `lookup_entity` with `entity_value=${USER_ID}` and `entity_type="user"`.
    *   Use `search_user_activity` with `username=${USER_ID}` and `limit=50` to get recent activity (limit to last 50 events for efficiency).
    *   Record summary of user's recent activity, first/last seen, related alerts (`USER_SIEM_SUMMARY`).

4.  **Source IP Enrichment:**
    *   Use `get_ip_address_report` with `ip=${SOURCE_IP}` to get reputation and context.
    *   Use `lookup_entity` with `entity_value=${SOURCE_IP}` and `entity_type="ip"` to get SIEM context.
    *   Use `pivot_on_indicator` with `indicator=${SOURCE_IP}` to find related events (limit to last 24 hours).
    *   Use `get_ioc_matches` with `ioc_type="ip"` to check if it's a known IOC.
    *   Store results as `IP_REPORT`, `IP_SIEM_SUMMARY`, `IP_RELATED_EVENTS`, `IP_IOC_MATCH`.

5.  **Hostname Context (SIEM):**
    *   If `${HOSTNAME}` was extracted:
        *   Use `lookup_entity` with `entity_value=${HOSTNAME}` and `entity_type="hostname"`.
        *   Record summary (`HOSTNAME_SIEM_SUMMARY`).

6.  **Recent Login Activity (SIEM):**
    *   Use `search_security_events` with a query focusing on login events for the user in the last 24-48 hours (limit scope for efficiency):
        *   Query should search for authentication/login events involving `${USER_ID}` (e.g., `username="${USER_ID}" AND event_type IN ("login", "authentication")` or similar query syntax for your SIEM).
    *   Look for basic patterns: logins from other unusual IPs, successful logins after failures, frequency of logins from `${SOURCE_IP}` vs. others (`LOGIN_ACTIVITY_SUMMARY`).
    *   **Alert Correlation:** Use `get_alerts_by_entity` with `entity_value=${USER_ID}` and `entity_type="user"` to find related alerts for this user. Use `get_alerts_by_entity` with `entity_value=${SOURCE_IP}` and `entity_type="ip"` to find related alerts for this IP. Use `get_alerts_by_time_window` to find alerts occurring around the same time as the suspicious login.

7.  **Check Related Cases:**
    *   Use `search_cases` with `text` parameter containing `${USER_ID}`, `${SOURCE_IP}`, and `${HOSTNAME}` (if available).
    *   Filter by `status="open"` to find open cases.
    *   Obtain `${RELATED_CASES}`.

8.  **Attach Observables to Case:**
    *   Attach the source IP as an observable: Use `attach_observable_to_case` with `case_id=${CASE_ID}`, `observable_type="ip"`, `observable_value=${SOURCE_IP}`, and description.
    *   If hostname is available, attach it: Use `attach_observable_to_case` with `case_id=${CASE_ID}`, `observable_type="hostname"`, `observable_value=${HOSTNAME}`.

9.  **Create Case (If Needed) & Synthesize & Document:**
    *   **Only create a case if:** Assessment determined that case creation is needed (uncertain, suspicious, or requires tracking).
    *   If creating case, use `create_case` with comprehensive description including ALL alert details from `${ALERT_COMPLETE_DETAILS}`.
    *   Store `${CASE_ID}` for subsequent steps.
    *   Combine findings: User context (`USER_SIEM_SUMMARY`), Source IP context (`IP_REPORT`, `IP_SIEM_SUMMARY`, `IP_RELATED_EVENTS`, `IP_IOC_MATCH`), Hostname context (`HOSTNAME_SIEM_SUMMARY`), Login patterns (`LOGIN_ACTIVITY_SUMMARY`), Related cases (`${RELATED_CASES}`).
    *   Assess the severity and store in `${ASSESSMENT}` (FP, BTP, TP/Suspicious, Uncertain).
    *   **MANDATORY: Include ALL alert details from `${ALERT_COMPLETE_DETAILS}` in documentation.**
    *   Prepare comment text: `COMMENT_TEXT = "SOC1 Suspicious Login Triage for Alert ${ALERT_ID} (User: ${USER_ID} from ${SOURCE_IP}, Host: ${HOSTNAME}): **Complete Alert Details:** [include ALL from `${ALERT_COMPLETE_DETAILS}` - alert ID, detection rule name, timestamps, host/user info, event data, etc.]. User SIEM Summary: ${USER_SIEM_SUMMARY}. Source IP Report: ${IP_REPORT}. Source IP SIEM: ${IP_SIEM_SUMMARY}. Source IP IOC Match: ${IP_IOC_MATCH}. Hostname SIEM: ${HOSTNAME_SIEM_SUMMARY}. Recent Login Pattern: ${LOGIN_ACTIVITY_SUMMARY}. Related Open Cases: ${RELATED_CASES}. Assessment: [FP/BTP/TP/Uncertain]. Recommendation: [Close as FP/Known Activity | Escalate to SOC2 for further investigation | Leave as open case if uncertain]"`

    ```{warning}
    Account lockdown actions are SOC3 responsibility. If high confidence of compromise is identified, escalate to SOC3 with clear recommendation for account lockdown.
    ```

    *   If case exists, use `add_case_comment` with `case_id=${CASE_ID}` and `content=${COMMENT_TEXT}`.
    *   If no case yet and creating one, include this comment in the case description.

10. **Analyze Results and Create Recommendations (MANDATORY):**
    *   **CRITICAL: After making the assessment, the AI MUST analyze the results and determine if recommendations should be created.**
    *   **This step ensures continuous improvement of detection rules and visibility.**
    *   **For FP/BTP (High Confidence) assessments:**
        *   **Analyze if a fine-tuning recommendation should be created:**
            *   Extract detection rule name from `${ALERT_COMPLETE_DETAILS}` (if available).
            *   Extract alert type/pattern from alert details (e.g., "Impossible Travel", "Login from Untrusted Location").
            *   Use `list_fine_tuning_recommendations` with `include_closed=false` to search for existing recommendations matching the alert type or rule name.
            *   **If matching recommendation found:**
                *   Extract `task_id` from the matching task.
                *   Prepare comment: `FINE_TUNING_COMMENT = "Additional false positive observed. Alert ID: ${ALERT_ID}. Case ID: ${CASE_ID} (if created). Assessment: ${ASSESSMENT}. User: ${USER_ID}. Source IP: ${SOURCE_IP}. Details: [user context, IP context, login patterns]. Consider this additional data point for rule improvement."`
                *   Use `add_comment_to_fine_tuning_recommendation` with `task_id=${task_id}` and `comment_text=${FINE_TUNING_COMMENT}`.
            *   **If no matching recommendation found:**
                *   Prepare task title: `TASK_TITLE = "Reduce false positives for Suspicious Login Detection - [Alert Type] - [Detection Rule Name if available]"`
                *   Prepare task description: `TASK_DESCRIPTION = "Alert ${ALERT_ID} was assessed as ${ASSESSMENT} during SOC1 suspicious login triage. Detection Rule: [rule name if available]. Alert Type: [alert type]. User: ${USER_ID}. Source IP: ${SOURCE_IP}. User Context: ${USER_SIEM_SUMMARY}. IP Context: ${IP_REPORT}. Recommendations for improvement: Consider adjusting rule threshold, adding whitelist entries for known legitimate IPs/users, refining detection logic based on user patterns, or adding KB-based checks to reduce false positive rate."`
                *   Use `create_fine_tuning_recommendation` with `title=${TASK_TITLE}`, `description=${TASK_DESCRIPTION}`, and `tags=["false-positive", "fine-tuning", "soc1-triage", "suspicious-login"]`.
    *   **For TP/Suspicious or Uncertain assessments:**
        *   **Analyze if a visibility recommendation should be created:**
            *   **Check for visibility gaps:**
                *   If user activity data was incomplete or unavailable
                *   If IP reputation/enrichment data was limited
                *   If KB data was incomplete for user/IP patterns
                *   If detection rule lacks context needed for proper assessment
                *   If historical login patterns were not available
            *   **If visibility gaps identified:**
                *   Prepare task title: `VISIBILITY_TITLE = "Improve visibility for suspicious login detection - [specific gap identified]"`
                *   Prepare task description: `VISIBILITY_DESCRIPTION = "During SOC1 suspicious login triage of Alert ${ALERT_ID} (Case ${CASE_ID} if created), visibility gaps were identified: [list specific gaps]. Impact: [how this gap affected triage]. Recommendations: [specific recommendations - e.g., 'Enhance user activity logging', 'Improve IP reputation data', 'Add KB data for user patterns']."`
                *   Use `create_visibility_recommendation` with `title=${VISIBILITY_TITLE}`, `description=${VISIBILITY_DESCRIPTION}`, and `tags=["visibility", "soc1-triage", "suspicious-login"]`.
    *   **Document recommendation creation in case comments or alert notes:**
        *   If a fine-tuning recommendation was created/updated, mention it in the alert note or case comment.
        *   If a visibility recommendation was created, mention it in the alert note or case comment.

11. **Action Based on Assessment:**
    *   **If FP/BTP (High Confidence):**
        *   Use `close_alert` with `alert_id=${ALERT_ID}`, `reason="false_positive"` or `reason="benign_true_positive"`, and detailed comment.
        *   If case was created, use `update_case_status` with `case_id=${CASE_ID}` and `status="closed"`.
        *   Set `${ACTION_TAKEN}` = "Closed as FP/BTP during SOC1 triage."
        *   End runbook execution.
    *   **If TP/Suspicious OR If Uncertain:**
        *   **MUST create case if not already created, with ALL alert details from `${ALERT_COMPLETE_DETAILS}`.**
        *   Use `update_case_status` with `case_id=${CASE_ID}` and `status="in_progress"` (if suspicious) or `status="open"` (if uncertain).
        *   **Create Task for SOC2:**
            *   Use `add_case_task` with:
                *   `case_id=${CASE_ID}`
                *   `title="Suspicious Login Deep Investigation - User: ${USER_ID}"`
                *   `description="Perform comprehensive deep investigation of suspicious login activity for alert ${ALERT_ID}. **All alert details documented in case comments.** User: ${USER_ID}. Source IP: ${SOURCE_IP}. Hostname: ${HOSTNAME}. User SIEM Summary: ${USER_SIEM_SUMMARY}. Source IP Report: ${IP_REPORT}. Source IP IOC Match: ${IP_IOC_MATCH}. Recent Login Pattern: ${LOGIN_ACTIVITY_SUMMARY}. Related Cases: ${RELATED_CASES}. SOC1 Assessment: [Suspicious/True Positive/Uncertain] - requires SOC2 deep investigation including user behavior analysis, historical pattern analysis, and correlation with other security events."`
                *   `assignee="SOC2"` (or leave empty for SOC2 team assignment)
                *   `priority="high"` (or "critical" if IOC match found or high confidence of compromise)
                *   `status="pending"`
        *   **If High Confidence of Compromise:**
            *   Create additional task for SOC3:
                *   Use `add_case_task` with:
                    *   `case_id=${CASE_ID}`
                    *   `title="Account Security Assessment - User: ${USER_ID}"`
                    *   `description="Assess need for account lockdown and security actions. Alert ID: ${ALERT_ID}. User: ${USER_ID}. Source IP: ${SOURCE_IP}. Confidence Level: High. Indicators: [list key compromise indicators]. This task should be picked up by SOC3 if SOC2 confirms account compromise. SOC3 should evaluate account lockdown, password reset, and other security remediation actions."`
                    *   `assignee="SOC3"` (or leave empty for SOC3 team assignment)
                    *   `priority="high"` (or "critical" if immediate action needed)
                    *   `status="pending"`
        *   Set `${ACTION_TAKEN}` = "Escalated to SOC2 for deep investigation. Task created for SOC2. [If high confidence: Task also created for SOC3.] All alert details documented."
        *   Set `${ESCALATION_RECOMMENDATION}` = "Escalate to SOC2 for suspicious login investigation. Alert ID: ${ALERT_ID}. User: ${USER_ID}, Source IP: ${SOURCE_IP}. Indicators: [list key suspicious indicators]. [If high confidence: Also escalate to SOC3 for account security assessment.]"
        *   **Note:** SOC2 will perform deep investigation using `suspicious_login_investigation.md` runbook. If account compromise is confirmed, SOC3 will handle account lockdown.

## Completion Criteria

The suspicious login alert has been successfully triaged by SOC1:
*   **MANDATORY: Workflow started from `${ALERT_ID}` (never from existing case).**
*   **MANDATORY: `get_security_alert_by_id` called as FIRST step to gather ALL alert details.**
*   User context has been gathered.
*   Source IP has been enriched.
*   Recent login activity has been analyzed.
*   Related cases have been identified.
*   **If case created: ALL alert details included (alert ID, event data, context, detection rule name, timestamps, host/user info).**
*   Observables have been attached to the case (if case created).
*   An assessment has been made (FP, BTP, TP/Suspicious, Uncertain).
*   **MANDATORY: Results analyzed and recommendations created/updated when appropriate:**
    *   **For FP/BTP assessments:** Fine-tuning recommendation created or updated (if applicable) to track false positive patterns and improve detection rules.
    *   **For TP/Suspicious/Uncertain assessments:** Visibility recommendation created (if gaps identified) to improve detection capabilities and triage efficiency.
*   Appropriate action (closure, escalation to SOC2, or leave as open case with comprehensive details) has been taken.
*   **If escalated or left open: Task created for SOC2 with detailed investigation requirements and reference to alert details. If high confidence of compromise: Additional task created for SOC3 account security assessment.**
*   All findings and alert details have been documented in the case or alert closure.

## Escalation Criteria

**Escalate to SOC2 if:**
*   Suspicious patterns are identified (unusual IP, impossible travel, etc.).
*   IOC matches are found for the source IP.
*   Multiple failed logins followed by success.
*   User account shows signs of compromise.
*   Related suspicious cases exist.

**Escalate to SOC3 if:**
*   High confidence of account compromise.
*   Account lockdown is recommended (SOC3 will execute).

## Notes

*   **MANDATORY: SOC1 MUST ALWAYS START FROM `${ALERT_ID}`** - never begin from existing cases.
*   Focus on quick triage - do not perform deep behavioral analysis.
*   **If uncertain about legitimacy: Leave as open case with ALL alert details documented** rather than closing as false positive.
*   When in doubt, create case with comprehensive alert details and escalate to SOC2.
*   Account lockdown requires SOC3 authorization and execution.
*   Every open case MUST include comprehensive alert details (alert ID, event data, context, detection rule name, timestamps, host/user info) for SOC2 investigation.
*   **MANDATORY: Recommendation Analysis and Creation:** After making the assessment, the AI MUST analyze results and create recommendations when appropriate:
    *   **For FP/BTP assessments:** Check if a fine-tuning recommendation should be created or updated. If a similar recommendation exists, add a comment to it. If not, create a new fine-tuning recommendation with specific improvement suggestions.
    *   **For TP/Suspicious/Uncertain assessments:** Check for visibility gaps (missing user activity data, incomplete IP context, detection rule lacks context). If gaps are identified, create a visibility recommendation with specific improvement suggestions.
    *   This ensures continuous improvement of detection rules and visibility capabilities.

