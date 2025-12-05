# Runbook Guidelines

This document provides general guidelines for creating, maintaining, and executing runbooks within the SamiGPT MCP server environment.

## General Principles

*   **Clarity:** Runbooks should be clear, concise, and easy to follow, even under pressure.
*   **Accuracy:** Ensure tool names, parameters, and expected outcomes are accurate and match the actual MCP tools (e.g., `review_case`, `search_security_events`, `list_runbooks`, `execute_as_agent`).
*   **Consistency:** Use consistent formatting, terminology, and structure across all runbooks so they can be parsed by `RunbookManager` and discovered by `list_runbooks`.
*   **Actionability:** Focus on concrete steps, required decisions, and explicit next actions for SOC1/SOC2/SOC3.
*   **SOC-Tier Alignment:** Clearly indicate which SOC tier owns the runbook and what escalation targets exist (e.g., SOC1 → SOC2, SOC2 → SOC3).

## SOC Tier Fundamental Principles

### SOC1 (Tier 1) - Alert-First Triage
*   **MUST ALWAYS BEGIN FROM SECURITY ALERTS (`${ALERT_ID}`)**, never from existing cases.
*   **Primary role is to close false positives** quickly without creating unnecessary cases.
*   **If uncertain about legitimacy**: Leave the alert as an open case with ALL alert details documented (alert ID, event data, context, detection rule name, timestamps, host/user info, and anything else relevant).
*   **Every open case MUST include comprehensive alert details** for downstream analysts (SOC2).
*   Use `get_security_alert_by_id` as the FIRST step in every workflow.

### SOC2 (Tier 2) - Case-First Investigation
*   **MUST ALWAYS BEGIN FROM CASES (`${CASE_ID}`)**, never from raw alert queue.
*   **Should read all case details** including notes, tasks, evidence, and previous actions before starting investigation.
*   **Should complete any pending tasks** and perform additional analysis if needed.
*   **Must be capable of** fetching more events from SIEM, running deeper investigations, pivoting on hosts, users, IPs, and timelines, and updating the case with findings.
*   Use `review_case` as the FIRST step, then `list_case_tasks` to identify pending work.

### SOC3 (Tier 3) - IR-Level Expert
*   **Acts as the IR-level expert** handling advanced investigations, response actions, containment, and eradication steps.
*   **Confirms malicious activity when evidence is strong** before taking disruptive actions.
*   **Should guide SOC1 and SOC2** on complex cases when needed.
*   Reviews case context from SOC1 and SOC2 before executing response actions.
*   Use `review_case` as the FIRST step to understand full context and evidence.

## Required Structure

Runbooks are structured markdown documents that the MCP server parses for metadata (see `RunbookManager`). To ensure compatibility and consistency with the existing runbooks under `soc1/`, `soc2/`, and `soc3/`, each runbook **should** follow this structure and section naming:

*   **Title (H1):** `# SOCx: <Runbook Name> Runbook`
    *   Example: `# SOC1: Initial Alert Triage Runbook`

*   **Objective (`## Objective`):**
    *   What is the goal of this runbook?
    *   Example: “Perform initial triage of an alert to decide whether to close as FP/BTP or escalate to SOC2.”

*   **Scope (`## Scope`):**
    *   Clearly list what this runbook covers.
    *   Explicitly list what it **excludes** (e.g., “Deep-dive investigation (SOC2 responsibility)”).

*   **SOC Tier (`## SOC Tier`):**
    *   State the SOC tier and any escalation targets.
    *   Example:
        *   `**Tier:** SOC1 (Tier 1)`
        *   `**Escalation Target:** SOC2 for suspicious/true positive cases`

*   **Inputs (`## Inputs`):**
    *   List all required and optional inputs using the `${VARIABLE_NAME}` convention.
    *   **SOC Tier-Specific Input Requirements:**
        *   **SOC1 runbooks**: MUST have `${ALERT_ID}` as **REQUIRED** input. Should NOT accept `${CASE_ID}` as primary input (SOC1 starts from alerts, not cases).
        *   **SOC2 runbooks**: MUST have `${CASE_ID}` as **REQUIRED** input. Should NOT accept `${ALERT_ID}` as primary input (SOC2 starts from cases, not raw alerts).
        *   **SOC3 runbooks**: MUST have `${CASE_ID}` as **REQUIRED** input.
    *   Examples: `${CASE_ID}`, `${ALERT_ID}`, `${FILE_HASH}`, `${ENDPOINT_ID}`, `${TIME_FRAME_HOURS}`.
    *   These variables are extracted by `RunbookManager` for metadata, so use **uppercase** names and `${...}` syntax.
    *   Clearly mark which inputs are **REQUIRED** vs optional.

*   **Outputs (`## Outputs`):**
    *   List the key outputs the runbook is expected to produce.
    *   Examples: `${ASSESSMENT}`, `${ACTION_TAKEN}`, `${INITIAL_SIEM_CONTEXT}`, `${DEEP_ANALYSIS_RESULTS}`, `${ISOLATION_STATUS}`.

*   **Tools (`## Tools`):**
    *   Group tools by functional area (matching existing runbooks):
        *   **Case Management Tools:** `review_case`, `add_case_comment`, `attach_observable_to_case`, `search_cases`, `update_case_status`, `add_case_task`.
        *   **SIEM Tools:** `get_security_alert_by_id`, `search_security_events`, `lookup_entity`, `get_ioc_matches`, `get_file_report`, `get_ip_address_report`, `pivot_on_indicator`, `get_entities_related_to_file`, `get_file_behavior_summary`, `get_threat_intel`.
        *   **CTI Tools:** `lookup_hash_ti` (and others as applicable).
        *   **EDR Tools:** `get_endpoint_summary`, `isolate_endpoint`, `kill_process_on_endpoint`, `collect_forensic_artifacts` (where relevant).
        *   **Runbook & Agent Tools (when applicable):** `list_runbooks`, `get_runbook`, `execute_runbook`, `list_agent_profiles`, `get_agent_profile`, `route_case_to_agent`, `execute_as_agent`.
    *   Tool names **must** be wrapped in backticks (`` `tool_name` ``) so `RunbookManager` can extract them.

*   **Workflow Steps (`## Workflow Steps`):**
    *   Detail the ordered sequence of actions the AI/analyst should follow.
    *   Use numbered steps with bolded titles, consistent with existing runbooks (e.g., `initial_alert_triage.md`, `malware_deep_analysis.md`, `endpoint_isolation.md`).
    *   **MANDATORY FIRST STEP by SOC Tier:**
        *   **SOC1 runbooks**: MUST start with "Receive Alert (MANDATORY)" and call `get_security_alert_by_id` with `${ALERT_ID}` as the FIRST action.
        *   **SOC2 runbooks**: MUST start with "Receive Case (MANDATORY)" and call `review_case` with `${CASE_ID}` as the FIRST action, then `list_case_tasks` to identify pending work.
        *   **SOC3 runbooks**: MUST start with "Receive Case & Review Evidence (MANDATORY)" and call `review_case` with `${CASE_ID}` as the FIRST action to understand full context.
    *   Example patterns:
        *   SOC1: `1.  **Receive Alert (MANDATORY):** Obtain ${ALERT_ID} from SIEM alert queue. MUST use \`get_security_alert_by_id\` as FIRST action.`
        *   SOC2: `1.  **Receive Case (MANDATORY):** Obtain ${CASE_ID} from case management. MUST use \`review_case\` as FIRST action, then \`list_case_tasks\` to identify pending work.`
        *   SOC3: `1.  **Receive Case & Review Evidence (MANDATORY):** Obtain ${CASE_ID}. MUST use \`review_case\` as FIRST action to review ALL case details and confirm evidence.`
    *   Within each step, explicitly reference which MCP tools to call, under what conditions, and what data to store (e.g., `${SIMILAR_CASE_IDS}`, `${ENRICHMENT_RESULTS}`, `${CONTAINMENT_RECOMMENDATION}`).
    *   Make decisions and branching explicit (e.g., "If IOC matches found, escalate to SOC2", "If endpoint already isolated, skip isolation step and document.").
    *   **For SOC1**: Document that if uncertain about legitimacy, leave as open case with ALL alert details.
    *   **For SOC2**: Document that additional events should be fetched from SIEM, pivots should be performed, and case should be updated with findings.
    *   **For SOC3**: Document that evidence should be confirmed strong before taking disruptive actions, and guidance should be provided to SOC1/SOC2 if needed.

*   **Completion Criteria (`## Completion Criteria`):**
    *   Bullet list describing when the runbook is considered successfully completed.
    *   **SOC Tier-Specific Completion Requirements:**
        *   **SOC1 runbooks**: MUST include "Workflow started from `${ALERT_ID}`" and "`get_security_alert_by_id` called as FIRST step". If case created, MUST include "ALL alert details included in case".
        *   **SOC2 runbooks**: MUST include "Workflow started from `${CASE_ID}`", "`review_case` called as FIRST step", "All pending tasks reviewed and completed", "Additional events fetched from SIEM", "Case updated with findings".
        *   **SOC3 runbooks**: MUST include "Workflow started from `${CASE_ID}`", "`review_case` called as FIRST step", "Evidence confirmed strong", "Case updated with actions".
    *   Mirror the style of existing runbooks:
        *   "All primary entities have been enriched…"
        *   "Appropriate action (closure or escalation) has been taken…"
        *   "All steps and findings have been documented in the case."

*   **Escalation Criteria (`## Escalation Criteria to SOCx`) (when applicable):**
    *   Clearly enumerate when to escalate to higher tiers (e.g., SOC1 → SOC2, SOC2 → SOC3).
    *   **SOC Tier-Specific Escalation Requirements:**
        *   **SOC1 → SOC2**: When uncertain about legitimacy (leave as open case with ALL alert details) OR when suspicious/true positive indicators found.
        *   **SOC2 → SOC3**: When active threat confirmed and containment actions needed, OR when case requires IR-level expertise.
        *   **SOC3 guidance to SOC1/SOC2**: When case needs additional analysis before response actions, or when complex investigation guidance is needed.
    *   Examples from existing runbooks:
        *   "True positive indicators are found…"
        *   "Active threat confirmed…"
        *   "Multiple endpoints affected…"
        *   "Uncertain about legitimacy - leave as open case with comprehensive alert details…"
        *   "Evidence confirmed strong - proceed with containment…"

*   **Warnings / Notes (`## Warning`, `## Notes`) (optional but recommended):**
    *   Capture important safety warnings (e.g., disruptive actions like isolation or process termination).
    *   Provide operational notes for analysts/agents following the runbook.
    *   **SOC Tier-Specific Notes:**
        *   **SOC1**: Emphasize "MUST ALWAYS START FROM `${ALERT_ID}`", "If uncertain leave as open case with ALL alert details", "Primary role is closing false positives".
        *   **SOC2**: Emphasize "MUST ALWAYS START FROM `${CASE_ID}`", "Read ALL case details first", "Complete pending tasks", "Fetch additional events from SIEM", "Update case with findings".
        *   **SOC3**: Emphasize "IR-level expert", "Confirm evidence is strong", "Review ALL case details", "Provide guidance to SOC1/SOC2 if needed".

## Workflow Diagrams (Recommended)

Runbooks **may** include a Mermaid sequence diagram to visualize the workflow, especially for complex multi-step investigations. When you add a diagram:

*   **Scope of the Diagram:**
    *   Show interactions between:
        *   **Analyst/Agent** (human or autonomous agent).
        *   **MCP Server** (SamiGPT runbook/agent tools).
        *   **Domain Integrations** (case management, SIEM, EDR, CTI).
    *   Focus on the **actual tools** invoked (e.g., `execute_as_agent`, `execute_runbook`, `review_case`, `search_security_events`, `isolate_endpoint`), not generic placeholders.

*   **Example Participants:**
    *   `Analyst`, `SOC1 Agent`, `MCP Server`, `Case Management`, `SIEM`, `EDR`, `CTI`.

Diagrams are **recommended** for clarity but are not required for the MCP tooling to function; the primary source of truth remains the structured sections and workflow steps.

## Reporting Requirements

*   **Runbook Reference in Reports:** If a runbook execution results in a generated report (e.g., triage outcome, investigation summary, containment report), the report **must** clearly state which runbook was used near the beginning of the report.
    *   Example: `**Runbook Used:** SOC1: Initial Alert Triage Runbook`
*   **Alignment with Agent Profiles:** When reports are produced as part of an agent-based execution (e.g., via `execute_as_agent`), ensure the report describes:
    *   Which agent executed the runbook (e.g., `soc1_triage_agent`).
    *   Which runbook path was used (e.g., `soc1/triage/initial_alert_triage`).

## Maintenance

*   **Periodic Review:** Runbooks should be reviewed periodically (e.g., quarterly) to ensure they remain accurate and aligned with:
    *   MCP tools exposed by the server.
    *   Agent profiles defined in `config/agent_profiles.json`.
    *   SOC tier responsibilities in `SOC_TIER_ORGANIZATION_PLAN.md`.
*   **Update on Change:** Update runbooks promptly when tools, procedures, or configurations change (e.g., new tools like `execute_as_agent`, new runbooks, or updated escalation criteria).
*   **Validation:**
    *   Use `list_runbooks` to confirm new/updated runbooks are discovered.
    *   Use `get_runbook` to verify that `Objective`, `Inputs`, `Tools`, and `Workflow Steps` are parsed correctly.
    *   Keep tool names and variable names (`${VARIABLE_NAME}`) in sync with the codebase and other documentation.

*(Extend these guidelines as additional runbooks and MCP tools are added.)*
