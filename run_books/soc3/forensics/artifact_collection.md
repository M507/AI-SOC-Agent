# SOC3: Forensic Artifact Collection Runbook

Initiate collection of forensic artifacts from an endpoint for incident investigation and analysis. This runbook guides SOC3 (IR-level expert) analysts in collecting comprehensive forensic data. SOC3 reviews case context from SOC1 and SOC2 before initiating collection.

## Scope

This runbook covers:
*   Forensic artifact collection procedures.
*   Selection of artifact types to collect.
*   Documentation of collection actions.

## SOC Tier

**Tier:** SOC3 (Tier 3)

## Inputs

*   `${ENDPOINT_ID}`: The endpoint ID to collect artifacts from.
*   `${CASE_ID}`: The relevant case ID for documentation.
*   `${ARTIFACT_TYPES}`: List of artifact types to collect (default: ["processes", "network", "filesystem"]).
    *   Available types: `processes`, `network`, `filesystem`, `registry`, `memory`, `logs`

## Outputs

*   `${COLLECTION_STATUS}`: Status of the collection operation.
*   `${ARTIFACTS_COLLECTED}`: List of artifacts collected.
*   `${DOCUMENTATION_STATUS}`: Status of documentation.

## Tools

*   **EDR Tools:** `get_endpoint_summary`, `collect_forensic_artifacts`
*   **Case Management Tools:** `review_case`, `add_case_comment`, `update_case_status`, `list_case_tasks`, `update_case_task_status`
*   **Knowledge Base Tools:** `kb_list_clients`, `kb_get_client_infra`

## Workflow Steps

1.  **Receive Case & Review Context (MANDATORY):**
    *   Obtain `${ENDPOINT_ID}`, `${CASE_ID}`, and `${ARTIFACT_TYPES}`.
    *   **MUST use `review_case` with `case_id=${CASE_ID}` as the FIRST action.**
    *   **Read ALL case details:**
        *   Case title, description, status, priority, tags
        *   ALL case comments from SOC1 and SOC2
        *   ALL observables, assets, evidence
        *   Review SOC1 alert details and SOC2 investigation findings
    *   **Review case timeline**: Use `list_case_timeline_events` to understand case history.
    *   If `${ARTIFACT_TYPES}` not provided, use default: `["processes", "network", "filesystem"]`.
    *   **Task Management:**
        *   Use `list_case_tasks` with `case_id=${CASE_ID}` to find ALL tasks assigned to SOC3 (e.g., "Forensic Artifact Collection").
        *   Review tasks from SOC1 and SOC2 to understand investigation context and what artifacts are needed.
        *   For each relevant task found, use `update_case_task_status` with `task_id=<TASK_ID>`, `status="in_progress"` to mark it as in-progress when starting the collection.
    *   **Determine artifact types based on case context**: Review SOC1 and SOC2 findings to determine what artifacts are most relevant.
    *   **Knowledge Base Context:**
        *   Use `kb_list_clients` to list available client environments.
        *   If client name is known from case context, use `kb_get_client_infra` with `client_name=<CLIENT_NAME>` to get infrastructure knowledge.
        *   If client name is unknown, check case observables/comments for client identifiers, or query knowledge base for "all" clients if needed.
        *   Use knowledge base to understand:
            *   Endpoint context and criticality
            *   Expected artifact locations and patterns
            *   Infrastructure-specific collection considerations

2.  **Get Endpoint Information:**
    *   Use `get_endpoint_summary` with `endpoint_id=${ENDPOINT_ID}`.
    *   Verify endpoint details: hostname, platform, current status.
    *   **Note:** Artifact collection can be performed on isolated or active endpoints.

3.  **Determine Artifact Types:**
    *   Based on case requirements, select appropriate artifact types:
        *   **processes**: Running processes and process trees
        *   **network**: Network connections and DNS queries
        *   **filesystem**: File system artifacts and modifications
        *   **registry**: Windows registry keys and modifications
        *   **memory**: Memory dumps and process memory
        *   **logs**: System logs and event logs
    *   Store selected types in `${ARTIFACT_TYPES}`.

4.  **Execute Artifact Collection:**
    *   Use `collect_forensic_artifacts` with `endpoint_id=${ENDPOINT_ID}` and `artifact_types=${ARTIFACT_TYPES}`.
    *   Wait for collection completion confirmation.
    *   Set `${COLLECTION_STATUS}` = "Artifacts collected successfully" or "Collection failed: [error]".
    *   Store collected artifacts list in `${ARTIFACTS_COLLECTED}`.

5.  **Document Collection:**
    *   Prepare collection comment: `COLLECTION_COMMENT = "SOC3 (IR Expert) Forensic Artifact Collection for Case ${CASE_ID}: Endpoint ID: ${ENDPOINT_ID}. Artifact Types Collected: ${ARTIFACT_TYPES}. Collection Status: ${COLLECTION_STATUS}. **Case Context Reviewed:** [summary of SOC1/SOC2 findings that informed artifact selection]. Infrastructure Context (KB): [...]. Collected at: [timestamp]. Artifacts: ${ARTIFACTS_COLLECTED}. **Note:** Forensic artifacts have been collected. Analysis should follow."`
    *   Include knowledge base findings (endpoint context, infrastructure considerations) in the comment.
    *   Document what case context was reviewed and why specific artifact types were selected.
    *   Use `add_case_comment` with `case_id=${CASE_ID}` and `content=${COLLECTION_COMMENT}`.
    *   Set `${DOCUMENTATION_STATUS}` = "Documented".
    *   **Task Management:**
        *   Use `update_case_task_status` with `task_id=<TASK_ID>`, `status="completed"` to mark the collection task as completed when finishing.

6.  **Next Steps:**
    *   **Note:** After collection, consider:
        *   Artifact analysis
        *   Timeline reconstruction
        *   Attack chain analysis
        *   Remediation planning
        *   Incident reporting

## Completion Criteria

The forensic artifacts have been successfully collected:
*   Endpoint information has been verified.
*   Artifact types have been determined.
*   Collection action has been executed.
*   Collection status has been documented.
*   Next steps have been identified.

## Artifact Type Selection Guide

*   **For Malware Investigation:**
    *   Recommended: `["processes", "network", "filesystem", "registry"]`
*   **For Account Compromise:**
    *   Recommended: `["processes", "network", "logs"]`
*   **For Data Exfiltration:**
    *   Recommended: `["network", "filesystem", "logs"]`
*   **For Comprehensive Investigation:**
    *   Recommended: `["processes", "network", "filesystem", "registry", "memory", "logs"]`

## Notes

*   **SOC3 acts as IR-level expert**: Review case context from SOC1 and SOC2 to determine appropriate artifact types.
*   **Review ALL case details first**: Read SOC1 and SOC2 findings to understand what artifacts are most relevant.
*   Artifact collection may take time depending on endpoint and artifact types.
*   Ensure sufficient storage for collected artifacts.
*   Document all collected artifacts for chain of custody.
*   Document what case context informed artifact selection decisions.
*   Coordinate with forensic analysis team if needed.
*   **Provide guidance if needed**: If case needs additional investigation before collection, provide guidance to SOC1/SOC2.

