# SOC3: Process Termination Runbook

Terminate a specific malicious process running on an endpoint by its process ID. This is a critical response action executed by SOC3 (IR-level expert) when malicious processes are identified. SOC3 confirms malicious activity when evidence is strong before taking disruptive actions.

## Scope

This runbook covers:
*   Process termination procedures.
*   Verification of process termination.
*   Documentation of termination actions.

This runbook explicitly **requires**:
*   SOC2 analysis confirming malicious process.
*   Authorization for disruptive actions.

## SOC Tier

**Tier:** SOC3 (Tier 3)  
**Authority:** SOC3 can execute containment actions

## Inputs

*   `${ENDPOINT_ID}`: The endpoint ID where the process is running.
*   `${PROCESS_ID}`: The process ID (PID) to terminate.
*   `${CASE_ID}`: The relevant case ID for documentation.
*   `${TERMINATION_REASON}`: The reason for termination (e.g., "Malicious process detected", "Malware execution confirmed").

## Outputs

*   `${TERMINATION_STATUS}`: Status of the termination operation.
*   `${DOCUMENTATION_STATUS}`: Status of documentation.

## Tools

*   **EDR Tools:** `get_endpoint_summary`, `kill_process_on_endpoint`
*   **Case Management Tools:** `review_case`, `add_case_comment`, `update_case_status`, `list_case_tasks`, `update_case_task_status`
*   **Knowledge Base Tools:** `kb_list_clients`, `kb_get_client_infra`

## Workflow Steps

1.  **Receive Case & Review Evidence (MANDATORY):**
    *   Obtain `${ENDPOINT_ID}`, `${PROCESS_ID}`, `${CASE_ID}`, and `${TERMINATION_REASON}`.
    *   **MUST use `review_case` with `case_id=${CASE_ID}` as the FIRST action.**
    *   **Read ALL case details:**
        *   Case title, description, status, priority, tags
        *   ALL case comments from SOC1 and SOC2
        *   ALL observables, assets, evidence
        *   Review SOC1 alert details and SOC2 investigation findings
    *   **Review case timeline**: Use `list_case_timeline_events` to understand case history.
    *   **Confirm evidence is strong**: Review SOC1 and SOC2 findings to confirm malicious process before taking disruptive action.
    *   Verify authorization for process termination.
    *   **Task Management:**
        *   Use `list_case_tasks` with `case_id=${CASE_ID}` to find ALL tasks assigned to SOC3 (e.g., "Process Termination", "Malware Removal").
        *   Review tasks from SOC1 and SOC2 to understand investigation context.
        *   For each relevant task found, use `update_case_task_status` with `task_id=<TASK_ID>`, `status="in_progress"` to mark it as in-progress when starting the termination.
    *   **If evidence is not strong or case needs additional analysis**: Provide guidance to SOC1/SOC2 on what additional analysis is needed before taking action.
    *   **Knowledge Base Context:**
        *   Use `kb_list_clients` to list available client environments.
        *   If client name is known from case context, use `kb_get_client_infra` with `client_name=<CLIENT_NAME>` to get infrastructure knowledge.
        *   If client name is unknown, check case observables/comments for client identifiers, or query knowledge base for "all" clients if needed.
        *   Use knowledge base to understand:
            *   Endpoint context and criticality
            *   Expected processes and services
            *   Infrastructure-specific termination considerations

2.  **Get Endpoint Information:**
    *   Use `get_endpoint_summary` with `endpoint_id=${ENDPOINT_ID}`.
    *   Verify endpoint details: hostname, platform, current status.
    *   **Note:** If endpoint is isolated, process termination may still be needed.

3.  **Execute Process Termination:**
    *   Use `kill_process_on_endpoint` with `endpoint_id=${ENDPOINT_ID}` and `pid=${PROCESS_ID}`.
    *   Wait for confirmation of termination completion.
    *   Set `${TERMINATION_STATUS}` = "Process terminated successfully" or "Termination failed: [error]".

4.  **Verify Termination:**
    *   **Note:** Verification may require additional endpoint queries or forensic collection.
    *   Document verification status.

5.  **Document Termination:**
    *   Prepare termination comment: `TERMINATION_COMMENT = "SOC3 (IR Expert) Process Termination for Case ${CASE_ID}: Endpoint ID: ${ENDPOINT_ID}. Process ID: ${PROCESS_ID}. Reason: ${TERMINATION_REASON}. **Evidence Reviewed:** [summary of SOC1/SOC2 findings that confirmed malicious process]. Termination Status: ${TERMINATION_STATUS}. Infrastructure Context (KB): [...]. Terminated at: [timestamp]. **Note:** Process has been terminated. Verify termination and check for persistence mechanisms."`
    *   Include knowledge base findings (endpoint context, expected processes) in the comment.
    *   Document what evidence was reviewed and why malicious process was confirmed.
    *   Use `add_case_comment` with `case_id=${CASE_ID}` and `content=${TERMINATION_COMMENT}`.
    *   Set `${DOCUMENTATION_STATUS}` = "Documented".
    *   **Task Management:**
        *   Use `update_case_task_status` with `task_id=<TASK_ID>`, `status="completed"` to mark the termination task as completed when finishing.

6.  **Next Steps:**
    *   **Note:** After termination, consider:
        *   Verify process is terminated (may require forensic collection)
        *   Check for persistence mechanisms
        *   Check for related processes
        *   Forensic artifact collection if needed
        *   Remediation planning

## Completion Criteria

The process has been successfully terminated:
*   Endpoint information has been verified.
*   Termination action has been executed.
*   Termination status has been documented.
*   Next steps have been identified.

## Warning

⚠️ **This will terminate the specified process immediately.**
*   Ensure proper authorization before execution.
*   Verify malicious nature of process before terminating.
*   Be aware that termination may impact legitimate processes if PID is incorrect.
*   Check for process persistence mechanisms after termination.

## Notes

*   **SOC3 acts as IR-level expert**: Confirm malicious activity when evidence is strong before taking disruptive actions.
*   **Review ALL case details first**: Read SOC1 and SOC2 findings to understand full context.
*   **Confirm evidence is strong**: Review SOC1 alert details and SOC2 investigation findings before terminating.
*   **Provide guidance if needed**: If evidence is not strong, provide guidance to SOC1/SOC2 on what additional analysis is needed.
*   Only execute after evidence is confirmed strong and malicious process is verified.
*   Document all actions and evidence confirmation for audit purposes.
*   Verify termination and check for persistence.
*   Coordinate with IT support if needed.

