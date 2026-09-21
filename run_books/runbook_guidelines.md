# Runbook Guidelines

This document provides general guidelines for creating, maintaining, and executing runbooks within the SamiGPT MCP server environment.

**Current scope: SOC1 only.** Higher-tier runbook conventions can be restored when SOC2/SOC3 are reintroduced.

## General Principles

*   **Clarity:** Runbooks should be clear, concise, and easy to follow, even under pressure.
*   **Accuracy:** Ensure tool names, parameters, and expected outcomes are accurate and match the actual MCP tools (e.g., `review_case`, `search_security_events`, `list_runbooks`, `execute_as_agent`).
*   **Consistency:** Use consistent formatting, terminology, and structure across all runbooks so they can be parsed by `RunbookManager` and discovered by `list_runbooks`.
*   **Actionability:** Focus on concrete steps, required decisions, and explicit next actions for SOC1.
*   **SOC-Tier Alignment:** Clearly indicate that the runbook is SOC1-owned and what escalation / handoff expectations exist.

## Analyst approval (Requests view)

Irreversible MCP tools **file a request** instead of executing:

*   `close_alert`, `isolate_endpoint`, `release_endpoint_isolation`, `kill_process_on_endpoint`, `collect_forensic_artifacts`
*   `create_fine_tuning_recommendation` and `create_visibility_recommendation` file **informational** notes (Home Lab rule lookup / coverage check). No approve button. No engineering board.
*   `create_runbook_recommendation` files an **informational** note that a case-specific playbook is missing under `soc*/cases/`. Call it **only after** investigation finishes (final verdict). Never block triage for it. Server attaches existing case-runbook coverage evidence.
*   Before a visibility note: `search_lab_detection_rules` (1–3 keyword searches) then at most 1–2 `get_lab_detection_rule` calls. Only file a gap if the catalog does not already cover it.
*   `update_alert_verdict` is **not** gated. It is the AI's working assessment and runs immediately. It does not close the alert.
*   `create_approval_request` is for identity checks ("is this you?") and any custom follow-up (ACK vs escalate to an Elastic Security case).
*   After calling a gated tool, tell the analyst the action is **pending in Requests**. Do not claim it already happened. After a fine-tune, visibility, or runbook-gap note, say it is informational in Requests.

## SOC1 Fundamental Principles

*   **MUST ALWAYS BEGIN FROM SECURITY ALERTS (`${ALERT_ID}`)**, never from existing cases.
*   **Primary role is to close false positives** quickly without creating cases.
*   **If uncertain about legitimacy**: Write a full alert note and set an honest verdict (`uncertain` / `true_positive`). Do **not** create a case.
*   Use `get_security_alert_by_id` as the FIRST step in every workflow.
*   Use `get_rule_detections` / `get_security_alerts` to review past **closed** and **acknowledged** alerts of the same rule/type before deciding.

## Required Structure

Runbooks are structured markdown documents that the MCP server parses for metadata (see `RunbookManager`). To ensure compatibility and consistency with the existing runbooks under `soc1/`, each runbook **should** follow this structure and section naming:

*   **Title (H1):** `# SOC1: <Runbook Name> Runbook`
    *   Example: `# SOC1: Initial Alert Triage Runbook`

*   **Objective (`## Objective`):**
    *   What is the goal of this runbook?
    *   Example: “Perform initial triage of an alert to decide whether to close as FP/BTP or escalate for deeper investigation.”

*   **Scope (`## Scope`):**
    *   Clearly list what this runbook covers.
    *   Explicitly list what it **excludes** (e.g., “Deep-dive investigation (out of scope for SOC1).”).

*   **SOC Tier (`## SOC Tier`):**
    *   State the SOC tier and any escalation / handoff targets.
    *   Example:
        *   `**Tier:** SOC1 (Tier 1)`
        *   `**Escalation Target:** Human / future higher-tier investigation for suspicious/true positive cases`

*   **Inputs (`## Inputs`):**
    *   List all required and optional inputs using the `${VARIABLE_NAME}` convention.
    *   **SOC1 runbooks**: MUST have `${ALERT_ID}` as **REQUIRED** input. Should NOT accept `${CASE_ID}` as primary input (SOC1 starts from alerts, not cases).
    *   Examples: `${ALERT_ID}`, `${FILE_HASH}`, `${ENDPOINT_ID}`, `${TIME_FRAME_HOURS}`.
    *   These variables are extracted by `RunbookManager` for metadata, so use **uppercase** names and `${...}` syntax.
    *   Clearly mark which inputs are **REQUIRED** vs optional.

*   **Outputs (`## Outputs`):**
    *   List the key outputs the runbook is expected to produce.
    *   Examples: `${ASSESSMENT}`, `${ACTION_TAKEN}`, `${INITIAL_SIEM_CONTEXT}`.

*   **Tools (`## Tools`):**
    *   Group tools by functional area (matching existing runbooks):
        *   **SIEM Tools:** `get_security_alert_by_id`, `get_rule_detections`, `get_security_alerts` (incl. `status_filter=closed|acknowledged` and `rule_name`/`rule_id`), `search_security_events`, `search_kql_query`, `search_lucene_query`, `search_eql_query`, `search_dsl_query`, `search_esql_query`, `lookup_entity`, `get_ioc_matches`, `get_file_report`, `get_ip_address_report`, `pivot_on_indicator`, `get_entities_related_to_file`, `get_file_behavior_summary`, `get_threat_intel`.
        *   **NetBox Tools:** `netbox_lookup_ip`, `netbox_lookup_host`, `netbox_lookup_prefix`, `netbox_search`.
        *   **CTI Tools:** `lookup_hash_ti` (and others as applicable).
        *   **EDR Tools:** `get_endpoint_summary`, `isolate_endpoint`, `kill_process_on_endpoint`, `collect_forensic_artifacts` (where relevant).
        *   **Runbook & Agent Tools (when applicable):** `list_runbooks`, `get_runbook`, `execute_runbook`, `list_agent_profiles`, `get_agent_profile`, `route_case_to_agent`, `execute_as_agent`.
    *   Tool names **must** be wrapped in backticks (`` `tool_name` ``) so `RunbookManager` can extract them.
    *   SOC1 triage runbooks must **not** list `create_case` or other case-write tools.

*   **Workflow Steps (`## Workflow Steps`):**
    *   Detail the ordered sequence of actions the AI/analyst should follow.
    *   Use numbered steps with bolded titles, consistent with existing runbooks (e.g., `initial_alert_triage.md`).
    *   **MANDATORY FIRST STEP:** SOC1 runbooks MUST start with "Receive Alert (MANDATORY)" and call `get_security_alert_by_id` with `${ALERT_ID}` as the FIRST action.
    *   Example: `1.  **Receive Alert (MANDATORY):** Obtain ${ALERT_ID} from SIEM alert queue. MUST use \`get_security_alert_by_id\` as FIRST action.`
    *   Within each step, explicitly reference which MCP tools to call, under what conditions, and what data to store.
    *   Make decisions and branching explicit (e.g., "If IOC matches found, escalate for deeper investigation", "If uncertain, write a full alert note (no case)").
    *   Document that if uncertain about legitimacy, document on the alert with a full note (no case).

*   **Completion Criteria (`## Completion Criteria`):**
    *   Bullet list describing when the runbook is considered successfully completed.
    *   SOC1 runbooks MUST include "Workflow started from `${ALERT_ID}`" and "`get_security_alert_by_id` called as FIRST step". If not closing, MUST include "ALL alert details in the alert note".
    *   Mirror the style of existing runbooks:
        *   "All primary entities have been enriched…"
        *   "Appropriate action (closure or escalation) has been taken…"
        *   "All steps and findings have been documented in the case."

*   **Escalation Criteria (`## Escalation Criteria`) (when applicable):**
    *   Clearly enumerate when to escalate / hand off for deeper work.
    *   SOC1 escalates when uncertain about legitimacy (document on the alert with a full note (no case)) OR when suspicious/true positive indicators are found.
    *   Examples:
        *   "True positive indicators are found…"
        *   "Uncertain about legitimacy - document on the alert with a full note (no case)…"

*   **Warnings / Notes (`## Warning`, `## Notes`) (optional but recommended):**
    *   Capture important safety warnings (e.g., disruptive actions like isolation or process termination).
    *   Provide operational notes for analysts/agents following the runbook.
    *   Emphasize "MUST ALWAYS START FROM `${ALERT_ID}`", "If uncertain document on the alert with a full note (no case)", "Primary role is closing false positives".

## Workflow Diagrams (Recommended)

Runbooks **may** include a Mermaid sequence diagram to visualize the workflow, especially for complex multi-step investigations. When you add a diagram:

*   **Scope of the Diagram:**
    *   Show interactions between:
        *   **Analyst/Agent** (human or autonomous agent).
        *   **MCP Server** (SamiGPT runbook/agent tools).
        *   **Domain Integrations** (case management, SIEM, NetBox, EDR, CTI).
    *   Focus on the **actual tools** invoked (e.g., `execute_as_agent`, `execute_runbook`, `review_case`, `search_security_events`, `netbox_lookup_ip`), not generic placeholders.

*   **Example Participants:**
    *   `Analyst`, `SOC1 Agent`, `MCP Server`, `Case Management`, `SIEM`, `NetBox`, `EDR`, `CTI`.

Diagrams are **recommended** for clarity but are not required for the MCP tooling to function; the primary source of truth remains the structured sections and workflow steps.

## Reporting Requirements

*   **Runbook Reference in Reports:** If a runbook execution results in a generated report (e.g., triage outcome), the report **must** clearly state which runbook was used near the beginning of the report.
    *   Example: `**Runbook Used:** SOC1: Initial Alert Triage Runbook`
*   **Alignment with Agent Profiles:** When reports are produced as part of an agent-based execution (e.g., via `execute_as_agent`), ensure the report describes:
    *   Which agent executed the runbook (e.g., `soc1_triage_agent`).
    *   Which runbook path was used (e.g., `soc1/triage/initial_alert_triage`).

## Maintenance

*   **Periodic Review:** Runbooks should be reviewed periodically (e.g., quarterly) to ensure they remain accurate and aligned with:
    *   MCP tools exposed by the server.
    *   Agent profiles defined in `config/agent_profiles.json`.
*   **Update on Change:** Update runbooks promptly when tools, procedures, or configurations change.
*   **Validation:**
    *   Use `list_runbooks` to confirm new/updated runbooks are discovered.
    *   Use `get_runbook` to verify that `Objective`, `Inputs`, `Tools`, and `Workflow Steps` are parsed correctly.
    *   Keep tool names and variable names (`${VARIABLE_NAME}`) in sync with the codebase and other documentation.

*(Extend these guidelines as additional runbooks and MCP tools are added.)*
