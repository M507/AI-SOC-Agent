# SOC2: Multi-IOC Correlation Runbook

Correlate multiple Indicators of Compromise (IOCs) to identify attack patterns, campaigns, and relationships between security events. **SOC2 MUST ALWAYS BEGIN FROM CASES (`${CASE_ID}`), NEVER FROM RAW ALERT QUEUE.** This runbook helps SOC2 analysts understand the broader threat landscape and attack chains. SOC2 should read all case details, complete pending tasks, and fetch additional events from SIEM as needed.

## Scope

This runbook covers:
*   Correlation of multiple IOCs (IPs, domains, hashes, URLs).
*   Attack pattern identification.
*   Campaign identification.
*   Threat actor attribution.
*   Relationship mapping between entities.

## SOC Tier

**Tier:** SOC2 (Tier 2)

## Inputs

*   `${IOC_LIST}`: List of IOCs to correlate (IPs, domains, hashes, URLs, etc.).
*   `${CASE_ID}`: The relevant case ID for documentation.
*   *(Optional) `${TIME_FRAME_HOURS}`: Lookback period for correlation (default: 168 hours / 7 days).*

## Outputs

*   `${CORRELATION_RESULTS}`: Correlation analysis including:
    - Relationships between IOCs
    - Attack patterns identified
    - Campaign associations
    - Threat actor attribution
    - Related cases and events

## Tools

*   **SIEM Tools:** `pivot_on_indicator`, `lookup_entity`, `search_security_events`, `get_ioc_matches`, `get_threat_intel`, `get_network_events`, `get_dns_events`, `get_email_events`, `get_alerts_by_entity`, `get_alerts_by_time_window`
*   **Case Management Tools:** `review_case`, `search_cases`, `add_case_comment`, `list_case_tasks`, `update_case_task_status`
*   **Knowledge Base Tools:** `kb_list_clients`, `kb_get_client_infra`

## Workflow Steps

1.  **Receive Case (MANDATORY):** 
    *   **SOC2 MUST ALWAYS START FROM `${CASE_ID}`** - this is the entry point for all SOC2 workflows.
    *   Obtain the `${CASE_ID}` from the case management system.
    *   **MUST use `review_case` with `case_id=${CASE_ID}` as the FIRST action.**
    *   **Read ALL case details:**
        *   Case title, description, status, priority, tags
        *   ALL case comments and notes
        *   ALL observables (extract `${IOC_LIST}` from observables)
        *   ALL assets, evidence files
    *   Obtain optionally `${TIME_FRAME_HOURS}`.
    *   **Review case timeline**: Use `list_case_timeline_events` to understand case history.
    *   **Task Management (Review & Complete Pending Tasks):** 
        *   Use `list_case_tasks` with `case_id=${CASE_ID}` to find ALL tasks assigned to SOC2 (e.g., "Multi-IOC Correlation", "Correlation Analysis") as well as any prior correlation work by other tiers.
        *   **Identify pending tasks**: Review tasks with `status="pending"` and complete them before starting new analysis.
        *   If a completed multi-IOC correlation task already exists that covers `${IOC_LIST}` and the same time window, avoid re-running this runbook; instead, reference the existing task and its comments.
        *   If no suitable task exists, create a new task via `add_case_task`, for example `SOC2 – Multi-IOC Correlation for ${IOC_LIST}`, with a description explaining why correlation is needed and what hypotheses are being tested.
        *   Mark the chosen correlation task `status="in_progress"` using `update_case_task_status` before starting the correlation.
    *   **Knowledge Base Context:**
        *   Use `kb_list_clients` to list available client environments.
        *   If client name is known from case context, use `kb_get_client_infra` with `client_name=<CLIENT_NAME>` to get infrastructure knowledge.
        *   If client name is unknown, check case observables/comments for client identifiers, or query knowledge base for "all" clients if needed.
        *   Use knowledge base to understand:
            *   Network topology and expected communication patterns
            *   Infrastructure-specific IOC validation
            *   Expected vs. anomalous patterns

2.  **Individual IOC Analysis:**
    *   For each IOC `Ii` in `${IOC_LIST}`:
        *   Use `pivot_on_indicator` with `indicator=Ii` to find all related events.
        *   Use `lookup_entity` with appropriate entity type to get context.
        *   Use `get_ioc_matches` to check IOC status.
        *   **Alert Correlation:** Use `get_alerts_by_entity` with `entity_value=Ii` and appropriate `entity_type` to find related alerts.
        *   **Event-Specific Analysis:**
            *   If `Ii` is an IP: Use `get_network_events` with `source_ip=Ii` or `destination_ip=Ii` to get network traffic events.
            *   If `Ii` is a domain: Use `get_dns_events` with `domain=Ii` to get DNS query events.
            *   If `Ii` is an email address: Use `get_email_events` with `sender_email=Ii` or `recipient_email=Ii` to get email events.
        *   Store individual analysis in `IOC_ANALYSIS[Ii]`.

3.  **Cross-IOC Event Correlation:**
    *   For each pair of IOCs (`Ii`, `Ij`):
        *   Use `search_security_events` with query correlating both IOCs.
        *   **Temporal Correlation:** Use `get_alerts_by_time_window` to find alerts for both IOCs occurring in the same time window.
        *   **Network Correlation:** If both IOCs are IPs, use `get_network_events` to find network connections between them.
        *   **DNS Correlation:** If one IOC is a domain and another is an IP, use `get_dns_events` with `domain=Ii` and `resolved_ip=Ij` to find DNS resolution events.
        *   Identify events where both IOCs appear together.
        *   Calculate correlation strength based on:
            - Number of shared events
            - Time proximity
            - Event types
            - Alert correlations
        *   Store correlation data in `IOC_CORRELATION[Ii][Ij]`.

4.  **Attack Pattern Identification:**
    *   Analyze correlated events to identify:
        *   Attack chains (initial access → execution → persistence → etc.)
        *   Common attack patterns
        *   MITRE ATT&CK technique combinations
        *   TTP patterns
    *   Store patterns in `${ATTACK_PATTERNS}`.

5.  **Campaign Identification:**
    *   Use `get_threat_intel` with queries about IOCs to identify:
        *   Known campaigns
        *   Threat actor associations
        *   Related threat intelligence
    *   Use `search_cases` to find related cases with similar IOCs.
    *   Store campaign data in `${CAMPAIGN_DATA}`.

6.  **Threat Actor Attribution:**
    *   Based on IOCs, attack patterns, and threat intelligence:
        *   Identify potential threat actors
        *   Map to known threat groups
        *   Attribute TTPs to threat actors
    *   Store attribution in `${THREAT_ACTOR_ATTRIBUTION}`.

7.  **Relationship Mapping:**
    *   Create relationship map showing:
        *   Connections between IOCs
        *   Shared events
        *   Temporal relationships
        *   Case associations
    *   Store relationship map in `${RELATIONSHIP_MAP}`.

8.  **Document Findings (Update Case with Findings):**
    *   Include knowledge base findings (network topology, infrastructure context, expected patterns) in the correlation analysis.
    *   **Document what was reviewed from case**: Reference original alert details from SOC1, previous comments, completed tasks.
    *   **Document what additional analysis was performed**: What additional events were fetched from SIEM, what pivots were performed, what new insights were discovered.
    *   Prepare correlation summary: `CORRELATION_SUMMARY = "SOC2 Multi-IOC Correlation Analysis for Case ${CASE_ID}: **Case Context Reviewed:** [summary of case details, IOCs from observables]. **Additional SIEM Analysis:** [what additional events were fetched, pivots performed]. IOCs Analyzed: ${IOC_LIST}. Individual IOC Analysis: [...]. Cross-IOC Correlations: [...]. Attack Patterns Identified: ${ATTACK_PATTERNS}. Campaign Data: ${CAMPAIGN_DATA}. Threat Actor Attribution: ${THREAT_ACTOR_ATTRIBUTION}. Relationship Map: ${RELATIONSHIP_MAP}. Infrastructure Context (KB): [...]."`
    *   Use `add_case_comment` with `case_id=${CASE_ID}` and `content=${CORRELATION_SUMMARY}`.
    *   **Update case observables**: Attach any new IOCs discovered during correlation.
    *   **Update case status/priority** if findings warrant it.
    *   **Task Management:** 
        *   Use `update_case_task_status` with `task_id=<TASK_ID>`, `status="completed"` to mark the correlation task as completed when finishing, so downstream tiers know this analysis exists and does not need to be repeated.
        *   Ensure all pending tasks from SOC1 have been addressed.

9.  **Return Results:**
    *   Compile all correlation data into `${CORRELATION_RESULTS}`.

## Completion Criteria

The multi-IOC correlation has been successfully completed:
*   All IOCs have been individually analyzed.
*   Cross-IOC correlations have been identified.
*   Attack patterns have been identified.
*   Campaign associations have been found.
*   Threat actor attribution has been performed.
*   Relationship mapping has been created.
*   Findings have been documented.

## Notes

*   **MANDATORY: SOC2 MUST ALWAYS START FROM `${CASE_ID}`** - never begin from raw `${ALERT_ID}` in the alert queue.
*   **MANDATORY: Read ALL case details first** - review case comments, tasks, observables, evidence, and previous actions before starting new analysis.
*   **MANDATORY: Complete pending tasks** - identify and complete any pending tasks from SOC1 or previous SOC2 work before starting new analysis.
*   This runbook is for comprehensive correlation analysis.
*   **Fetch additional events from SIEM** - use extended time frames and comprehensive queries.
*   **Perform pivots** - pivot on all IOCs to find related activity across the environment.
*   **Update case with findings** - document what additional analysis was performed and what new insights were discovered.
*   Use extended time frames for better correlation.
*   Document all relationships for future reference.

