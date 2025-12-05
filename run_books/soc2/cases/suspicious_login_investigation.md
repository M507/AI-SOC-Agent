# SOC2: Suspicious Login Deep Investigation Runbook

Perform comprehensive deep-dive investigation of a suspicious login case that has been escalated from SOC1. **SOC2 MUST ALWAYS BEGIN FROM CASES (`${CASE_ID}`), NEVER FROM RAW ALERT QUEUE.** This runbook provides thorough analysis including user behavior analysis, historical pattern analysis, account compromise assessment, and containment recommendations. SOC2 should read all case details, complete pending tasks, and fetch additional events from SIEM as needed.

## Scope

This runbook covers:
*   Deep user behavior analysis and historical patterns.
*   Multi-device and multi-location correlation.
*   Account compromise assessment.
*   Credential theft indicators.
*   Containment recommendations.

This runbook explicitly **excludes**:
*   Account lockdown execution (SOC3 responsibility).
*   Password reset coordination (SOC3 responsibility).

## SOC Tier

**Tier:** SOC2 (Tier 2)  
**Escalation Target:** SOC3 for account response actions if compromise confirmed

## Inputs

*   `${CASE_ID}`: **REQUIRED** - The case ID from the case management system. SOC2 MUST ALWAYS START FROM `${CASE_ID}`, never from raw `${ALERT_ID}`.
*   *(Optional) `${USER_ID}`: The user ID associated with the suspicious login (extracted from case details).*
*   *(Optional) `${SOURCE_IP}`: The source IP address (extracted from case details).*
*   *(Optional) `${TIME_FRAME_DAYS}`: Lookback period in days for historical analysis (default: 30 days).*

## Outputs

*   `${INVESTIGATION_RESULTS}`: Comprehensive investigation including:
    - User behavior analysis
    - Historical pattern analysis
    - Account compromise assessment
    - Containment recommendations
*   `${ACCOUNT_COMPROMISE_ASSESSMENT}`: Assessment of whether account is compromised.
*   `${CONTAINMENT_RECOMMENDATION}`: Recommendation for SOC3 account response actions.

## Tools

*   **Case Management Tools:** `review_case`, `add_case_comment`, `attach_observable_to_case`, `search_cases`, `list_case_tasks`, `update_case_task_status`
*   **Knowledge Base Tools:** `kb_list_clients`, `kb_get_client_infra`
*   **SIEM Tools:** `get_security_alert_by_id`, `lookup_entity`, `search_security_events`, `search_user_activity`, `get_ip_address_report`, `pivot_on_indicator`, `get_ioc_matches`, `get_threat_intel`

## Workflow Steps

1.  **Receive Case (MANDATORY):** 
    *   **SOC2 MUST ALWAYS START FROM `${CASE_ID}`** - this is the entry point for all SOC2 workflows.
    *   Obtain the `${CASE_ID}` from the case management system.
    *   **MUST use `review_case` with `case_id=${CASE_ID}` as the FIRST action.**
    *   **Read ALL case details:**
        *   Case title, description, status, priority, tags
        *   ALL case comments and notes (review from oldest to newest)
        *   ALL observables (IPs, domains, users, etc.)
        *   ALL assets (endpoints, servers, users)
        *   ALL evidence files
        *   Extract alert details from case description/comments (SOC1 should have documented all alert details)
    *   Extract `${USER_ID}`, `${SOURCE_IP}`, and `${HOSTNAME}` from case observables or description.
    *   Obtain other optional inputs.
    *   **Review case timeline**: Use `list_case_timeline_events` to understand case history and previous actions.
    *   **Task Management (Review & Complete Pending Tasks):** 
        *   Use `list_case_tasks` with `case_id=${CASE_ID}` to find ALL existing tasks created by SOC1/SOC2/SOC3.
        *   **Identify pending tasks**: Review tasks with `status="pending"` and complete them before starting new analysis.
        *   **Review completed tasks**: Do **not** repeat work already covered by completed tasks; instead, read their comments and build on them.
        *   If no SOC2 investigation tasks exist for this suspicious login, create a structured set of tasks using `add_case_task`, for example:
            *   `SOC2 – User Behavior Analysis for ${USER_ID}`
            *   `SOC2 – Historical Login Pattern Analysis for ${USER_ID}`
            *   `SOC2 – Source IP Deep Analysis for ${SOURCE_IP}`
            *   `SOC2 – Multi-Device & Location Correlation for ${USER_ID}`
            *   `SOC2 – Account Compromise Assessment for ${USER_ID}`
            *   `SOC2 – Campaign & Related Case Analysis for ${USER_ID}`
            *   `SOC2 – Containment Recommendations for ${USER_ID}`
        *   Each task description should briefly explain **why** this step is needed and **what** questions it answers so future analysts (including SOC3) can reuse the logic.
        *   For any of these tasks that are about to be executed, use `update_case_task_status` with `status="in_progress"` **before** performing the corresponding runbook step.
    *   **Knowledge Base Context:**
        *   Use `kb_list_clients` to list available client environments.
        *   If client name is known from case context, use `kb_get_client_infra` with `client_name=<CLIENT_NAME>` to get infrastructure knowledge.
        *   If client name is unknown, check case observables/comments for client identifiers, or query knowledge base for "all" clients if needed.
        *   Use knowledge base to understand:
            *   Whether `${HOSTNAME}` is a known/expected host in the infrastructure
            *   Whether `${SOURCE_IP}` belongs to a known network segment
            *   Whether `${USER_ID}` is a known user account
            *   Network topology and expected traffic patterns
            *   Device naming schemas and whether entities match expected patterns

2.  **Comprehensive User Behavior Analysis:**
    *   **Task linkage:** Work under the `SOC2 – User Behavior Analysis for ${USER_ID}` task. Ensure it is `in_progress` while this step runs and set to `completed` once analysis and documentation are done.
    *   Use `lookup_entity` with `entity_value=${USER_ID}` and `entity_type="user"` for complete user profile.
    *   Use `search_user_activity` with `username=${USER_ID}` and `limit=500` to get extensive activity history.
    *   Analyze user activity patterns:
        *   Normal login patterns (time, location, devices)
        *   Recent changes in behavior
        *   Privilege escalation events
        *   Unusual access patterns
    *   Store comprehensive user analysis (`${USER_BEHAVIOR_ANALYSIS}`).

3.  **Historical Pattern Analysis (Fetch Additional Events from SIEM):**
    *   **Task linkage:** Work under the `SOC2 – Historical Login Pattern Analysis for ${USER_ID}` task, updating its status as above and referencing it in comments.
    *   **SOC2 must fetch additional events beyond what SOC1 gathered:**
        *   Use `search_security_events` with extended time range (`${TIME_FRAME_DAYS}` days, default 30) to analyze:
            *   Login history and patterns
            *   Geographic locations
            *   Device types and user agents
            *   Failed login attempts
            *   Successful logins from unusual locations
        *   Use `search_user_activity` with extended limit and time range.
        *   Use `search_kql_query` for complex queries if needed.
        *   **Pivot on entities**: Use `pivot_on_indicator` on user, IP, hostname to find related activity.
    *   Identify baseline behavior and deviations (`${HISTORICAL_ANALYSIS}`).
    *   **Document what additional events were fetched and what new insights were discovered.**

4.  **Source IP Deep Analysis:**
    *   **Task linkage:** Work under the `SOC2 – Source IP Deep Analysis for ${SOURCE_IP}` task.
    *   Use `get_ip_address_report` with `ip=${SOURCE_IP}` for comprehensive reputation.
    *   Use `lookup_entity` with `entity_value=${SOURCE_IP}` and `entity_type="ip"` for SIEM context.
    *   Use `pivot_on_indicator` with `indicator=${SOURCE_IP}` to find all related events across extended time period.
    *   Use `get_ioc_matches` with `ioc_type="ip"` to check IOC status.
    *   Use `get_threat_intel` with query about the IP address.
    *   Store comprehensive IP analysis (`${IP_DEEP_ANALYSIS}`).

5.  **Multi-Device and Multi-Location Correlation:**
    *   **Task linkage:** Work under the `SOC2 – Multi-Device & Location Correlation for ${USER_ID}` task.
    *   Analyze login events to identify:
        *   Simultaneous logins from different locations (impossible travel)
        *   Logins from multiple devices
        *   Unusual device types or user agents
        *   VPN or proxy usage patterns
    *   Correlate with other security events for the user.
    *   Store correlation results (`${CORRELATION_ANALYSIS}`).

6.  **Account Compromise Assessment:**
    *   **Task linkage:** Work under the `SOC2 – Account Compromise Assessment for ${USER_ID}` task.
    *   Evaluate indicators of compromise:
        *   Credential theft indicators
        *   Unauthorized access patterns
        *   Privilege escalation
        *   Data access anomalies
        *   Lateral movement indicators
    *   Assess confidence level (Low, Medium, High) of account compromise.
    *   Store assessment in `${ACCOUNT_COMPROMISE_ASSESSMENT}`.

7.  **Related Cases and Campaign Analysis:**
    *   **Task linkage:** Work under the `SOC2 – Campaign & Related Case Analysis for ${USER_ID}` task.
    *   Use `search_cases` with comprehensive search terms (user, IP, related IOCs).
    *   Identify related attacks or campaigns.
    *   Correlate with threat intelligence.
    *   Store campaign analysis (`${CAMPAIGN_ANALYSIS}`).

8.  **Containment Recommendations:**
    *   **Task linkage:** Work under the `SOC2 – Containment Recommendations for ${USER_ID}` task, which should summarize recommended SOC3 actions and their rationale.
    *   Based on investigation, prepare recommendations:
        *   **If High Confidence of Compromise:**
            *   Immediate account lockdown (SOC3)
            *   Password reset (SOC3)
            *   MFA enforcement (SOC3)
            *   Session termination
        *   **If Medium Confidence:**
            *   Enhanced monitoring
            *   User notification
            *   Password reset recommendation
        *   **If Low Confidence:**
            *   Continue monitoring
            *   User education
    *   Store recommendations in `${CONTAINMENT_RECOMMENDATION}`.

9.  **Synthesize & Document (Update Case with Findings):**
    *   Combine all findings: `${USER_BEHAVIOR_ANALYSIS}`, `${HISTORICAL_ANALYSIS}`, `${IP_DEEP_ANALYSIS}`, `${CORRELATION_ANALYSIS}`, `${ACCOUNT_COMPROMISE_ASSESSMENT}`, `${CAMPAIGN_ANALYSIS}`, `${CONTAINMENT_RECOMMENDATION}`.
    *   Include knowledge base findings (infrastructure context, host validation, network topology insights) in the analysis.
    *   **Document what was reviewed from case**: Reference original alert details from SOC1, previous comments, completed tasks.
    *   **Document what additional analysis was performed**: What additional events were fetched from SIEM, what pivots were performed, what new insights were discovered.
    *   Prepare comprehensive comment: `COMMENT_TEXT = "SOC2 Deep Suspicious Login Investigation for Case ${CASE_ID} (User: ${USER_ID} from ${SOURCE_IP}): **Case Context Reviewed:** [summary of case details, alert info from SOC1, previous comments]. **Additional SIEM Analysis:** [what additional events were fetched, pivots performed, time windows expanded]. User Behavior Analysis: [...]. Historical Pattern Analysis: [...]. Source IP Deep Analysis: [...]. Multi-Device/Location Correlation: [...]. Infrastructure Context (KB): [...]. Account Compromise Assessment: ${ACCOUNT_COMPROMISE_ASSESSMENT} (Confidence: [Low/Medium/High]). Campaign Analysis: [...]. Containment Recommendations: ${CONTAINMENT_RECOMMENDATION}. **Next Steps:** [Escalate to SOC3 for account response if High confidence | Enhanced monitoring if Medium/Low confidence]"`
    *   Use `add_case_comment` with `case_id=${CASE_ID}` and `content=${COMMENT_TEXT}`.
    *   **Update case observables**: Attach any new IOCs or entities discovered during investigation.
    *   **Update case status/priority** if findings warrant it.
    *   **Task Management:** 
        *   For each SOC2 investigation task created for this run (user behavior, historical patterns, IP analysis, correlation, assessment, campaigns, containment), use `update_case_task_status` with `status="completed"` once the corresponding step is finished and documented.
        *   Ensure all pending tasks from SOC1 have been addressed.

10. **Action Based on Assessment:**
    *   **If High Confidence of Compromise:**
        *   Use `update_case_status` with `case_id=${CASE_ID}` and `status="in_progress"`.
        *   Set `${ACTION_TAKEN}` = "Escalated to SOC3 for account response actions."
        *   **Note:** SOC3 will execute account lockdown and password reset.
    *   **If Medium/Low Confidence:**
        *   Document findings and recommendations.
        *   Set `${ACTION_TAKEN}` = "Investigation complete. Enhanced monitoring recommended."

## Completion Criteria

The suspicious login investigation has been successfully completed by SOC2:
*   **MANDATORY: Workflow started from `${CASE_ID}` (never from raw alert).**
*   **MANDATORY: `review_case` called as FIRST step to read ALL case details (comments, tasks, observables, evidence).**
*   **MANDATORY: All pending tasks reviewed and completed.**
*   Comprehensive user behavior analysis performed.
*   Historical pattern analysis completed with extended time windows.
*   **Additional events fetched from SIEM beyond what SOC1 gathered.**
*   **Pivots performed on users, IPs, hostnames, and timelines to find related activity.**
*   Source IP deep analysis performed.
*   Multi-device/location correlation completed.
*   Account compromise assessment made.
*   Campaign analysis performed.
*   Containment recommendations prepared.
*   **Case updated with findings**: New comments, observables, status/priority updates.
*   Comprehensive documentation completed including what additional analysis was performed.
*   Appropriate escalation to SOC3 (if needed) performed.

## Escalation Criteria to SOC3

Escalate to SOC3 if:
*   High confidence of account compromise.
*   Credential theft confirmed.
*   Unauthorized access confirmed.
*   Account response actions needed (lockdown, password reset, MFA enforcement).

## Notes

*   **MANDATORY: SOC2 MUST ALWAYS START FROM `${CASE_ID}`** - never begin from raw `${ALERT_ID}` in the alert queue.
*   **MANDATORY: Read ALL case details first** - review case comments, tasks, observables, evidence, and previous actions before starting new analysis.
*   **MANDATORY: Complete pending tasks** - identify and complete any pending tasks from SOC1 or previous SOC2 work before starting new analysis.
*   This is a comprehensive deep investigation runbook for SOC2.
*   Perform thorough analysis including historical patterns with extended time windows.
*   **Fetch additional events from SIEM** - use broader time windows and more comprehensive queries than SOC1.
*   **Perform pivots** - pivot on users, IPs, hostnames, and timelines to find related activity.
*   **Update case with findings** - document what additional analysis was performed and what new insights were discovered.
*   Document all findings comprehensively.
*   Account response actions require SOC3 authorization and execution.

