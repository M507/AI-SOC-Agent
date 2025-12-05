# SOC1: Basic IOC Enrichment Runbook

## Objective

Perform basic enrichment of Indicators of Compromise (IOCs) to support initial triage decisions. This runbook provides quick enrichment for primary IOCs to help determine if escalation is needed.

## Scope

This runbook covers:
*   Basic enrichment of IOCs (IPs, domains, hashes, URLs).
*   Threat intelligence lookups.
*   SIEM entity lookups.
*   IOC match checking.

This runbook explicitly **excludes**:
*   Deep IOC analysis (SOC2 responsibility).
*   Multi-IOC correlation (SOC2 responsibility).
*   Historical analysis (SOC2 responsibility).

## SOC Tier

**Tier:** SOC1 (Tier 1)

## Inputs

*   `${IOC_VALUE}`: The IOC value to enrich (IP address, domain, hash, URL, etc.).
*   `${IOC_TYPE}`: The type of IOC (ip, domain, hash, url, email, etc.).
*   `${CASE_ID}`: (Optional) Case ID to attach enriched IOC as observable.

## Outputs

*   `${ENRICHMENT_RESULTS}`: Enrichment data including:
    - Threat intelligence data
    - SIEM context
    - IOC match status
    - Reputation information

## Tools

*   **CTI Tools:** `lookup_hash_ti`
*   **SIEM Tools:** `lookup_entity`, `get_ioc_matches`, `get_file_report`, `get_ip_address_report`

## Workflow Steps

1.  **Receive Input:** Obtain `${IOC_VALUE}`, `${IOC_TYPE}`, and optionally `${CASE_ID}`.

2.  **Enrich Based on IOC Type:**
    *   **If `${IOC_TYPE}` is "hash":**
        *   Use `lookup_hash_ti` with `hash_value=${IOC_VALUE}` to get CTI context.
        *   Use `get_file_report` with `file_hash=${IOC_VALUE}` to get SIEM file report.
        *   Use `get_ioc_matches` with `ioc_type="hash"` to check if it's a known IOC.
        *   Store results: `CTI_DATA`, `SIEM_FILE_REPORT`, `IOC_MATCH_STATUS`.
    *   **If `${IOC_TYPE}` is "ip":**
        *   Use `get_ip_address_report` with `ip=${IOC_VALUE}` to get reputation and context.
        *   Use `lookup_entity` with `entity_value=${IOC_VALUE}` and `entity_type="ip"` to get SIEM context.
        *   Use `get_ioc_matches` with `ioc_type="ip"` to check if it's a known IOC.
        *   Store results: `IP_REPORT`, `SIEM_CONTEXT`, `IOC_MATCH_STATUS`.
    *   **If `${IOC_TYPE}` is "domain":**
        *   Use `lookup_entity` with `entity_value=${IOC_VALUE}` and `entity_type="domain"` to get SIEM context.
        *   Use `get_ioc_matches` with `ioc_type="domain"` to check if it's a known IOC.
        *   Store results: `SIEM_CONTEXT`, `IOC_MATCH_STATUS`.
    *   **If `${IOC_TYPE}` is "url":**
        *   Use `lookup_entity` with `entity_value=${IOC_VALUE}` and `entity_type="url"` to get SIEM context.
        *   Use `get_ioc_matches` with `ioc_type="url"` to check if it's a known IOC.
        *   Store results: `SIEM_CONTEXT`, `IOC_MATCH_STATUS`.

3.  **Compile Enrichment Results:**
    *   Combine all enrichment data into `${ENRICHMENT_RESULTS}`:
        *   IOC value and type
        *   Threat intelligence data (if available)
        *   SIEM context (if available)
        *   IOC match status (known malicious or not)
        *   Reputation information (if available)

4.  **Attach Observable (if CASE_ID provided):**
    *   If `${CASE_ID}` is provided:
        *   Use `attach_observable_to_case` with `case_id=${CASE_ID}`, `observable_type=${IOC_TYPE}`, `observable_value=${IOC_VALUE}`, and description including enrichment summary.

5.  **Return Results:**
    *   Return `${ENRICHMENT_RESULTS}` for use in triage decision-making.

## Completion Criteria

The IOC has been successfully enriched:
*   Threat intelligence lookup completed (if applicable).
*   SIEM context obtained (if applicable).
*   IOC match status determined.
*   Enrichment results compiled.
*   Observable attached to case (if CASE_ID provided).

## Notes

*   This is a basic enrichment runbook for SOC1 efficiency.
*   For deep IOC analysis, escalate to SOC2.
*   Focus on quick reputation and match checks.

