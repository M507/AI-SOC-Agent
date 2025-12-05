# SOC3: Endpoint Isolation Runbook

Isolate an endpoint from the network to prevent further compromise or lateral movement. This is a critical response action executed by SOC3 (IR-level expert) when active threats are confirmed. SOC3 confirms malicious activity when evidence is strong before taking disruptive actions.

## Scope

This runbook covers:
*   Endpoint isolation procedures.
*   Verification of isolation status.
*   Documentation of isolation actions.

This runbook explicitly **requires**:
*   SOC2 analysis confirming active threat.
*   Authorization for disruptive actions.

## SOC Tier

**Tier:** SOC3 (Tier 3)  
**Authority:** SOC3 can execute containment actions

## Inputs

*   `${ENDPOINT_ID}`: The endpoint ID to isolate.
*   `${CASE_ID}`: The relevant case ID for documentation.
*   `${ISOLATION_REASON}`: The reason for isolation (e.g., "Active malware detected", "Confirmed compromise", "Lateral movement detected").

## Outputs

*   `${ISOLATION_STATUS}`: Status of the isolation operation.
*   `${DOCUMENTATION_STATUS}`: Status of documentation.

## Tools

*   **EDR Tools:** `get_endpoint_summary`, `isolate_endpoint`
*   **Case Management Tools:** `review_case`, `add_case_comment`, `update_case_status`, `list_case_tasks`, `update_case_task_status`
*   **Knowledge Base Tools:** `kb_list_clients`, `kb_get_client_infra`

## Workflow Steps

1.  **Receive Case & Review Evidence (MANDATORY):**
    *   Obtain `${ENDPOINT_ID}`, `${CASE_ID}`, and `${ISOLATION_REASON}`.
    *   **MUST use `review_case` with `case_id=${CASE_ID}` as the FIRST action.**
    *   **Read ALL case details:**
        *   Case title, description, status, priority, tags
        *   ALL case comments from SOC1 and SOC2
        *   ALL observables, assets, evidence
        *   Review SOC1 alert details and SOC2 investigation findings
    *   **Review case timeline**: Use `list_case_timeline_events` to understand case history.
    *   **Confirm evidence is strong**: Review SOC1 and SOC2 findings to confirm malicious activity before taking disruptive action.
    *   Verify authorization for isolation action.
    *   **Task Management:**
        *   Use `list_case_tasks` with `case_id=${CASE_ID}` to find ALL tasks assigned to SOC3 (e.g., "Network Containment", "Endpoint Isolation").
        *   Review tasks from SOC1 and SOC2 to understand investigation context.
        *   For each relevant task found, use `update_case_task_status` with `task_id=<TASK_ID>`, `status="in_progress"` to mark it as in-progress when starting the isolation.
    *   **If evidence is not strong or case needs additional analysis**: Provide guidance to SOC1/SOC2 on what additional analysis is needed before taking action.
    *   **Knowledge Base Context:**
        *   Use `kb_list_clients` to list available client environments.
        *   If client name is known from case context, use `kb_get_client_infra` with `client_name=<CLIENT_NAME>` to get infrastructure knowledge.
        *   If client name is unknown, check case observables/comments for client identifiers, or query knowledge base for "all" clients if needed.
        *   Use knowledge base to understand:
            *   Endpoint context and criticality
            *   Network topology and isolation impact
            *   Whether endpoint is a known/expected host in the infrastructure

2.  **Get Endpoint Information:**
    *   Use `get_endpoint_summary` with `endpoint_id=${ENDPOINT_ID}`.
    *   Verify endpoint details: hostname, platform, current status, isolation status.
    *   **Warning:** If endpoint is already isolated, document and skip isolation step.

3.  **Execute Isolation:**
    *   Use `isolate_endpoint` with `endpoint_id=${ENDPOINT_ID}`.
    *   Wait for confirmation of isolation completion.
    *   Set `${ISOLATION_STATUS}` = "Endpoint isolated successfully" or "Isolation failed: [error]".

4.  **Verify Isolation:**
    *   Use `get_endpoint_summary` with `endpoint_id=${ENDPOINT_ID}` to verify `is_isolated` status is `true`.
    *   Confirm endpoint is disconnected from network.

5.  **Document Isolation:**
    *   Prepare isolation comment: `ISOLATION_COMMENT = "SOC3 (IR Expert) Endpoint Isolation for Case ${CASE_ID}: Endpoint ID: ${ENDPOINT_ID}. Reason: ${ISOLATION_REASON}. **Evidence Reviewed:** [summary of SOC1/SOC2 findings that confirmed malicious activity]. Isolation Status: ${ISOLATION_STATUS}. Infrastructure Context (KB): [...]. Isolated at: [timestamp]. **Note:** Endpoint is now isolated from network. Forensic collection and remediation should follow."`
    *   Include knowledge base findings (endpoint context, network topology insights) in the comment.
    *   Document what evidence was reviewed and why malicious activity was confirmed.
    *   Use `add_case_comment` with `case_id=${CASE_ID}` and `content=${ISOLATION_COMMENT}`.
    *   Set `${DOCUMENTATION_STATUS}` = "Documented".
    *   **Task Management:**
        *   Use `update_case_task_status` with `task_id=<TASK_ID>`, `status="completed"` to mark the isolation task as completed when finishing.

6.  **Next Steps:**
    *   **Note:** After isolation, consider:
        *   Forensic artifact collection (use `artifact_collection.md` runbook)
        *   Process termination if needed (use `process_termination.md` runbook)
        *   Remediation planning
        *   User notification

## Completion Criteria

The endpoint has been successfully isolated:
*   Endpoint information has been verified.
*   Isolation action has been executed.
*   Isolation status has been verified.
*   Isolation action has been documented in the case.
*   Next steps have been identified.

## Warning

⚠️ **This is a disruptive action that will disconnect the endpoint from the network.**
*   Ensure proper authorization before execution.
*   Verify active threat before isolating.
*   Notify affected users if possible.
*   Plan for forensic collection and remediation.

## Notes

*   **SOC3 acts as IR-level expert**: Confirm malicious activity when evidence is strong before taking disruptive actions.
*   **Review ALL case details first**: Read SOC1 and SOC2 findings to understand full context.
*   **Confirm evidence is strong**: Review SOC1 alert details and SOC2 investigation findings before isolating.
*   **Provide guidance if needed**: If evidence is not strong, provide guidance to SOC1/SOC2 on what additional analysis is needed.
*   Only execute after evidence is confirmed strong and active threat is verified.
*   Document all actions and evidence confirmation for audit purposes.
*   Coordinate with affected users and IT support.
*   Plan for remediation and release from isolation.

