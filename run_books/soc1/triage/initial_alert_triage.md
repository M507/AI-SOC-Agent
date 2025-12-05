SOC1 INITIAL ALERT TRIAGE RUNBOOK


OBJECTIVE
1. Provide a standardized, SOC1-ready procedure for initial triage of incoming SIEM alerts.
2. Ensure SOC1 always starts from the SIEM alert queue (get_recent_alerts), never from existing cases.
3. Prioritize fast closure of false positives and benign true positives without creating cases.
4. Create or use cases only for confirmed true positives (TP) that require SOC2 investigation.
5. CRITICAL: Group alerts by same host within 24 hours into a single case whenever possible to avoid case fragmentation and enable holistic incident investigation.

Section Outputs:
1. Clear statement of purpose and primary decision goals for SOC1.


SCOPE
1. Included:
   1.1 Initial review and triage of alerts selected from get_recent_alerts.
   1.2 Extraction of complete alert and event details from get_security_alert_by_id.
   1.3 Basic SIEM searches and entity enrichment focused on 3–5 key entities.
   1.4 Detection of false positives and benign true positives for direct closure.
   1.5 Decision-making on whether to leave alerts as uncertain (no case) or escalate confirmed TPs to SOC2.
2. Excluded:
   2.1 Deep-dive investigation and complex correlation (SOC2 responsibility).
   2.2 Containment, eradication, and response actions (SOC3 responsibility).
   2.3 Long-horizon threat hunting and broad environment-wide analysis.

Section Outputs:
1. Clear understanding of what SOC1 is expected and not expected to do.


SOC TIER AND ESCALATION
1. Tier: SOC1 (Tier 1).
2. Escalation Target: SOC2 for confirmed TPs requiring deep investigation.

Section Outputs:
1. Defined ownership for triage and escalation.


INPUTS
1. Required Inputs:
   1.1 Starting point: results from get_recent_alerts.
   1.2 Selected alert without a verdict from get_recent_alerts.
   1.3 ${ALERT_ID} for the chosen alert.
2. Optional Inputs:
   2.1 ${ALERT_DETAILS} from upstream systems.
   2.2 Client environment identifier if known.
3. Preconditions:
   3.1 SOC1 must not start from ${CASE_ID}. If only ${CASE_ID} is provided, the workflow must request a valid ${ALERT_ID} from get_recent_alerts.

Section Outputs:
1. Confirmed starting alert context and identifiers for triage.


TOOL CATEGORIES
1. Case Management Tools (CM):
   1.1 create_case
   1.2 list_cases
   1.3 search_cases
   1.4 review_case
   1.5 add_case_comment
   1.6 attach_observable_to_case
   1.7 update_case_status
   1.8 add_case_task
   1.9 list_case_tasks
   1.10 update_case_task_status
2. SIEM Tools:
   2.1 Alert Management:
       2.1.1 get_recent_alerts
       2.1.2 get_security_alert_by_id
       2.1.3 get_siem_event_by_id
       2.1.4 update_alert_verdict
       2.1.5 add_alert_note
   2.2 Event Search and Investigation:
       2.2.1 search_security_events
       2.2.2 get_network_events
       2.2.3 get_dns_events
       2.2.4 get_email_events
       2.2.5 get_alerts_by_entity
       2.2.6 get_alerts_by_time_window
   2.3 Entity Lookup and IOC:
       2.3.1 lookup_entity
       2.3.2 get_ioc_matches
       2.3.3 get_file_report
       2.3.4 get_ip_address_report
3. CTI Tools (Threat Intelligence):
   3.1 lookup_hash_ti
4. KB Tools (Knowledge Base):
   4.1 kb_list_clients
   4.2 kb_get_client_infra
5. Engineering Tools:
   5.1 list_fine_tuning_recommendations
   5.2 create_fine_tuning_recommendation
   5.3 add_comment_to_fine_tuning_recommendation
   5.4 list_visibility_recommendations
   5.5 create_visibility_recommendation
   5.6 add_comment_to_visibility_recommendation

Section Outputs:
1. Mapped toolset grouped by use: SIEM investigation, case management, KB, CTI, and engineering.


GLOBAL OUTPUT VARIABLES
1. ${ASSESSMENT}: FP, BTP, TP, or Uncertain.
2. ${ACTION_TAKEN}: Final triage action description.
3. ${CASE_ID}: Case identifier if an existing or new case is used.
4. ${PRIMARY_CASE_ID}: Primary related case when applicable.
5. ${ALERT_COMPLETE_DETAILS}: Full alert and event details extracted from SIEM.
6. ${KEY_ENTITIES}: 3–5 primary entities (IPs, hosts, users, hashes, domains, processes).
7. ${HOSTNAME}: Primary hostname extracted from alert events (for case correlation).
8. ${ENDPOINT_ID}: Primary endpoint ID if available (for case correlation).
9. ${HOST_IP}: Primary host IP address (for case correlation).
10. ${INITIAL_SIEM_CONTEXT}: Summary of targeted SIEM searches.
11. ${ENRICHMENT_RESULTS}: Enrichment results for primary entities.
12. ${KB_VERIFICATION_RESULTS}: KB verdicts for entities.
13. ${IOC_MATCH_RESULTS}: IOC match results for key entities.
14. ${ADDITIONAL_RELATED_CASES}: List of additional related cases discovered.
15. ${UNCERTAIN_ALERTS_SAME_HOST}: Uncertain alerts on the same host.
16. ${UNCERTAIN_PATTERN_ANALYSIS}: Pattern analysis for uncertain alerts.
17. ${CASE_STRATEGY}: EXACT_DUPLICATE, RELATED_CASE, NEW_CASE, or PENDING_INVESTIGATION.
18. ${ESCALATION_RECOMMENDATION}: Recommendation to SOC2 if TP.
19. ${ALERT_CASE_DECISION}: Whether the alert was attached to an existing case, a new case was created, or no case was used ("EXISTING_CASE", "NEW_CASE", "NO_CASE").
20. ${CASE_LINK_EXPLANATION}: Short explanation of why the alert was linked to an existing case or why a new case was created (for example, "Same host '${HOSTNAME}' within 24 hours; grouping related alerts" or "No existing case with same host/user/attack type; new phishing incident for different user and host").

Section Outputs:
1. Standard variable set used across all steps for consistent tracking.


TRIAGE WORKFLOW
Note: Steps 1 to 11 are executed in order. Step 8 contains parallel investigation sub-steps.


STEP 1 – GET RECENT ALERTS (MANDATORY ENTRY POINT)
Inputs:
1. None beyond connectivity to SIEM.

Actions:
1. Call get_recent_alerts to retrieve the current SIEM alert queue.
2. Filter alerts to those where verdict is not set.
3. Select the first alert without a verdict.
4. Extract ${ALERT_ID} from the selected alert.
5. If a ${CASE_ID} is provided instead of ${ALERT_ID}, stop and require get_recent_alerts to be used.

Decision Points:
1. If no alert without verdict is available, stop: nothing to triage.

Outputs:
1. Selected ${ALERT_ID} for triage.
2. Raw alert record from get_recent_alerts for reference.


STEP 2 – RETRIEVE ALERT DETAILS (MANDATORY FIRST ACTION)
Inputs:
1. ${ALERT_ID} from Step 1.

Actions:
1. Call get_security_alert_by_id with alert_id = ${ALERT_ID}.
2. Check the verdict field:
   2.1 If verdict exists (any value), treat the alert as already investigated and stop the runbook for this alert.
3. Extract and store complete alert data in ${ALERT_COMPLETE_DETAILS}, including:
   3.1 Alert ID, name/type, severity, detection rule name, timestamps.
   3.2 Full events array containing the events that triggered the alert.
4. For each event in events:
   4.1 Read and store the exact message field text.
   4.2 Store the raw event object.
   4.3 Extract entities from the event message and raw data:
       4.3.1 Users and accounts.
       4.3.2 Hosts and endpoint IDs.
       4.3.3 IP addresses, ports, and protocols.
       4.3.4 Domains and URLs.
       4.3.5 Processes, command lines, PIDs, parent processes.
       4.3.6 File paths and file hashes.
5. Derive ${KEY_ENTITIES} from the actual event messages (not just metadata or related_entities), limited to 3–5 most critical entities.
6. Derive ${ALERT_TYPE} (for example: Suspicious Login, Malware Detection, Network Alert, Email/Phishing).
7. Cross-check entities:
   7.1 Compare entities from event messages with alert metadata and related_entities.
   7.2 If they disagree, always trust the event messages.

Decision Points:
1. If verdict is already present on the alert, stop triage for this alert (END_VERDICT path).

Outputs:
1. ${ALERT_COMPLETE_DETAILS} including full event and entity context.
2. ${KEY_ENTITIES} derived from event messages.
3. ${ALERT_TYPE} classification.


STEP 3 – SET VERDICT TO IN-PROGRESS (ALERT LOCKING)
Inputs:
1. ${ALERT_ID}.

Actions:
1. Immediately after Step 2, call update_alert_verdict with:
   1.1 alert_id = ${ALERT_ID}.
   1.2 verdict = "in-progress".
   1.3 comment explaining that SOC1 has started investigation and is locking the alert.

Decision Points:
1. None.

Outputs:
1. Alert marked as in-progress so it is not re-selected by other agents via get_recent_alerts.


STEP 4 – QUICK ASSESSMENT (NO CASE YET)
Inputs:
1. ${ALERT_COMPLETE_DETAILS}.
2. ${KEY_ENTITIES}.

Actions:
1. Entity extraction verification:
   1.1 Confirm that all entities used in this step come from the events field and exact message text, not just metadata.
2. Knowledge base (KB) verification:
   2.1 Call kb_list_clients to identify available client environments.
   2.2 Call kb_get_client_infra for the relevant client.
   2.3 For each primary entity:
       2.3.1 For IPs, confirm if internal or known legitimate service.
       2.3.2 For hosts, confirm they match expected naming and roles.
       2.3.3 For users, confirm they are known and check tags such as RDP, VPN, expected-activity.
       2.3.4 For processes, confirm they are known legitimate applications.
   2.4 Record results in ${KB_VERIFICATION_RESULTS}.
3. Quick IOC check:
   3.1 For the top 2–3 most critical entities (hashes, IPs, domains), call get_ioc_matches using appropriate ioc_type.
   3.2 Record results in ${IOC_MATCH_RESULTS}.
4. Pattern and context check:
   4.1 Compare activity with known benign patterns from KB and prior knowledge:
       4.1.1 Scheduled jobs.
       4.1.2 Maintenance windows.
       4.1.3 Approved administrative activity.
       4.1.4 Known benign third-party services.

Decision Points:
1. Direct Closure Decision – FP/BTP vs Further Investigation:
   1.1 Close directly as FP or BTP (no case) if:
       1.1.1 All primary entities are internal or explicitly expected in KB.
       1.1.2 Users are known and, when relevant, have tags that match the alert type (for example, RDP, VPN, expected-activity).
       1.1.3 No IOC matches exist for the primary entities.
       1.1.4 No suspicious patterns or anomaly indicators are present.
   1.2 Otherwise, proceed to Case Strategy (Step 5).

Outputs:
1. ${KB_VERIFICATION_RESULTS}.
2. ${IOC_MATCH_RESULTS}.
3. Quick decision on whether the alert is a clear FP/BTP candidate or needs deeper case strategy.


STEP 4.3 – DIRECT CLOSURE ACTIONS (FP/BTP, NO CASE)
This step executes only if the decision in Step 4 is to close directly as FP or BTP.

Inputs:
1. ${ALERT_ID}, ${ALERT_COMPLETE_DETAILS}, ${KB_VERIFICATION_RESULTS}, ${IOC_MATCH_RESULTS}, ${ALERT_TYPE}.

Actions:
1. Add alert note:
   1.1 Call add_alert_note with a concise summary:
       1.1.1 What was checked (KB verification, IOC checks, patterns).
       1.1.2 Why the activity is FP or BTP.
       1.1.3 Concrete recommendations for rule improvement and exclusions.
2. Update verdict to false_positive or benign_true_positive using update_alert_verdict:
   2.1 Include a comment referencing KB results, IOC results, and reasons.
3. Evaluate fine-tuning recommendations:
   3.1 Use list_fine_tuning_recommendations to find matching detection patterns.
   3.2 If a matching recommendation exists:
       3.2.1 Add a comment to it with add_comment_to_fine_tuning_recommendation summarizing this new FP/BTP instance.
   3.3 If no matching recommendation exists:
       3.3.1 Create a new recommendation using create_fine_tuning_recommendation with a title focused on reducing false positives for this alert type.

Decision Points:
1. Determine whether to update an existing fine-tuning item or create a new one.

Outputs:
1. ${ASSESSMENT} = "false_positive" or "benign_true_positive".
2. ${ACTION_TAKEN} = direct closure with documented reasoning and engineering feedback.
3. Alert verdict updated and notes added, no case created.

If direct closure is performed, the runbook ends here for this alert.


STEP 5 – CASE STRATEGY AND EXISTING CASE CHECK
This step is executed only if Step 4 did not result in direct closure.
This step MUST be completed before any new case is created. Always search for existing related cases first and prefer attaching the alert to an existing case over creating a new one when appropriate.

CRITICAL PRIORITY: Same-host alerts within 24 hours should ALWAYS be grouped into the same case unless there is explicit evidence they are unrelated incidents. This is the most common relationship pattern and prevents case fragmentation.

Inputs:
1. ${ALERT_COMPLETE_DETAILS}, ${KEY_ENTITIES}, ${ALERT_TYPE}, timestamps.

Actions:
1. Extract hostname and endpoint ID from ${ALERT_COMPLETE_DETAILS} and ${KEY_ENTITIES}:
   1.1 Identify the primary hostname, endpoint ID, and IP address from the alert events.
   1.2 Store these as ${HOSTNAME}, ${ENDPOINT_ID}, and ${HOST_IP} for case correlation.
2. Initial case search for duplicates and related incidents (prioritize same-host cases):
   MANDATORY: This search MUST be exhaustive and documented. Document all search attempts and results explicitly.
   2.1 Use search_cases with text containing:
       2.1.1 ${ALERT_ID} (exact duplicate).
       2.1.2 ${HOSTNAME} (CRITICAL: same hostname within last 24 hours).
       2.1.3 ${ENDPOINT_ID} (if available, same endpoint within last 24 hours).
       2.1.4 ${HOST_IP} (same IP address within last 24 hours).
   2.2 Use list_cases with status = open or in_progress to enumerate ALL active cases:
       2.2.1 This MUST return all currently open and in-progress cases.
       2.2.2 For EACH case returned, use review_case to examine it.
       2.2.3 Create a list of all cases that match ${HOSTNAME}, ${ENDPOINT_ID}, or ${HOST_IP} within the last 24 hours.
       2.2.4 Document this list explicitly - note which cases were checked and which matched the hostname.
   2.3 For each active case found, review_case to check:
       2.3.1 Case title and description for hostname matches with ${HOSTNAME} (case-insensitive match).
       2.3.2 Case observables for matching hostnames, endpoint IDs, or IPs.
       2.3.3 Case comments and timeline for related alert types on the same host.
       2.3.4 Case creation time (if within 24 hours of current alert timestamp, prioritize it).
       2.3.5 MANDATORY: Record whether this case matches ${HOSTNAME} - if yes, add it to SAME_HOST_CASES list.
   2.4 Use search_cases with primary ${KEY_ENTITIES} (user accounts, IPs, hashes, domains):
       2.4.1 Search for same user account within last 24 hours.
       2.4.2 Search for same IP addresses, file hashes, or domains.
       2.4.3 Search for similar alert types or detection rules within last 24 hours.
   2.5 VALIDATION CHECKPOINT: Before proceeding, explicitly document:
       2.5.1 List all same-host cases found (hostname matches within 24 hours).
       2.5.2 List all other related cases found (entity, timeline, similar alert type).
       2.5.3 If NO same-host cases were found, explicitly state: "No existing cases found for hostname '${HOSTNAME}' within 24 hours."
       2.5.4 If same-host cases WERE found, explicitly state: "Found X existing case(s) for hostname '${HOSTNAME}': [case IDs and titles]."
3. Classification and prioritization of related cases (in priority order):
   3.1 EXACT_DUPLICATE_CASES: cases already containing this ${ALERT_ID}.
   3.2 SAME_HOST_CASES (HIGHEST PRIORITY): cases with the same hostname, endpoint ID, or host IP within the last 24 hours, regardless of alert type. These should be grouped together unless explicitly unrelated.
   3.3 HOST_RELATED_CASES: same host or endpoint within 24–48 hours (still highly relevant).
   3.4 ENTITY_RELATED_CASES: same user account, IP, hash, or domain within 24 hours.
   3.5 TIMELINE_RELATED_CASES: alerts within 2 hours but different hosts (lower priority).
   3.6 SIMILAR_ALERT_TYPE_CASES: same or similar alert types within 24 hours (lowest priority).
4. Initial case strategy (prioritize same-host cases):
   4.1 If EXACT_DUPLICATE_CASES is not empty:
       4.1.1 Set ${PRIMARY_CASE_ID} to the most relevant duplicate case.
       4.1.2 Set ${CASE_STRATEGY} = "EXACT_DUPLICATE".
   4.2 Else if SAME_HOST_CASES is not empty (within 24 hours):
       4.2.1 Prioritize cases from the same hostname within the last 24 hours.
       4.2.2 If multiple same-host cases exist, select the most recent open case or the case with the most related alerts.
       4.2.3 Set ${PRIMARY_CASE_ID} to the selected same-host case.
       4.2.4 Set ${CASE_STRATEGY} = "RELATED_CASE".
       4.2.5 Set ${CASE_LINK_EXPLANATION} = "Same host '${HOSTNAME}' within 24 hours; grouping related alerts for holistic investigation."
   4.3 Else if any HOST_RELATED_CASES (24–48 hours), ENTITY_RELATED_CASES, or TIMELINE_RELATED_CASES exist:
       4.3.1 Prioritize HOST_RELATED_CASES over other types.
       4.3.2 Set ${PRIMARY_CASE_ID} to the most relevant open case.
       4.3.3 Set ${CASE_STRATEGY} = "RELATED_CASE".
   4.4 Else:
       4.4.1 Set ${PRIMARY_CASE_ID} = null.
       4.4.2 Set ${CASE_STRATEGY} = "PENDING_INVESTIGATION".
5. Throughout this step, group alerts logically by host, user account, and threat / alert category so that related activity is handled under a single case whenever practical, avoiding duplicate, fragmented investigations. SAME-HOST ALERTS WITHIN 24 HOURS SHOULD ALMOST ALWAYS BE GROUPED TOGETHER.

Decision Points:
1. EXACT_DUPLICATE vs RELATED_CASE vs PENDING_INVESTIGATION.
2. Confirm that a new case will only be created later if no relevant case exists OR if this alert is of a clearly different nature from existing cases.

Outputs:
1. ${CASE_STRATEGY}.
2. ${PRIMARY_CASE_ID} when applicable.
3. Categorized sets of related cases.


STEP 5.3 – HANDLE EXACT DUPLICATE (SKIP INVESTIGATION)
This step executes only if ${CASE_STRATEGY} = "EXACT_DUPLICATE".

Inputs:
1. ${ALERT_ID}, ${PRIMARY_CASE_ID}, ${ALERT_TYPE}, ${ALERT_COMPLETE_DETAILS}.

Actions:
1. Add comment to existing case using add_case_comment:
   1.1 Document:
       1.1.1 Alert ID and type.
       1.1.2 That this is an exact duplicate of an already-processed alert.
       1.1.3 Relevant timestamps from the alert.
2. Add note to alert using add_alert_note:
   2.1 Document exact-duplicate status and link to ${PRIMARY_CASE_ID}.
3. Update alert verdict to false_positive using update_alert_verdict with a comment explaining that this is a duplicate of an already-triaged alert.

Decision Points:
1. None beyond confirming exact-duplicate status from Step 5.

Outputs:
1. ${ASSESSMENT} = "false_positive" (duplicate).
2. ${ACTION_TAKEN} = duplicate recorded, no new investigation.
3. Alert verdict updated and linked to existing case; runbook ends for this alert.

If ${CASE_STRATEGY} is "RELATED_CASE" or "PENDING_INVESTIGATION", continue to Step 8.


STEP 8 – PARALLEL INVESTIGATION
This step runs only for ${CASE_STRATEGY} = "RELATED_CASE" or "PENDING_INVESTIGATION".
Sub-steps 8.1 to 8.6 should be executed in parallel where possible.


STEP 8.1 – KB VERIFICATION (PARALLEL)
Inputs:
1. ${KEY_ENTITIES}, ${ALERT_COMPLETE_DETAILS}.

Actions:
1. Repeat and deepen KB verification for primary entities:
   1.1 Call kb_list_clients and kb_get_client_infra.
   1.2 Validate IPs, hosts, users, and processes as internal, expected, or unknown.

Decision Points:
1. Identify any entities that cannot be confirmed as expected via KB.

Outputs:
1. Updated ${KB_VERIFICATION_RESULTS} with more detailed status per entity.


STEP 8.2 – IOC CHECK (PARALLEL)
Inputs:
1. ${KEY_ENTITIES}.

Actions:
1. Use get_ioc_matches for top 3–5 entities:
   1.1 Hashes (ioc_type = "hash").
   1.2 IPs (ioc_type = "ip").
   1.3 Domains (ioc_type = "domain").

Decision Points:
1. Determine if any primary entities match known IOCs.

Outputs:
1. Updated ${IOC_MATCH_RESULTS}.


STEP 8.3 – SIEM SEARCH (PARALLEL)
Inputs:
1. ${ALERT_COMPLETE_DETAILS}, ${KEY_ENTITIES}, event IDs and timestamps.

Actions:
1. Use events from get_security_alert_by_id as the primary reference.
2. Use message and raw fields to derive correct entities to search for.
3. Perform targeted searches based on alert type:
   3.1 Suspicious Login: search_security_events for the user in the last 24 hours.
   3.2 Malware Detection: search_security_events for file hash in the last 24 hours.
   3.3 Network Alert: get_network_events and, if applicable, get_dns_events.
   3.4 Email/Phishing: get_email_events for relevant sender/recipient/subject.
4. Use get_alerts_by_entity and get_alerts_by_time_window to find related alerts.
5. Use lookup_entity where needed for additional SIEM context.
6. Capture a concise, high-value subset of results as ${INITIAL_SIEM_CONTEXT}.

Decision Points:
1. Identify whether SIEM context shows suspicious chains, escalation, or lateral movement.

Outputs:
1. ${INITIAL_SIEM_CONTEXT} summarizing up to 10–20 most relevant events and alerts.


STEP 8.4 – ENTITY ENRICHMENT (PARALLEL)
Inputs:
1. ${KEY_ENTITIES}.

Actions:
1. Limit to 3–5 most critical entities.
2. For hashes:
   2.1 lookup_hash_ti.
   2.2 get_file_report.
   2.3 get_ioc_matches with ioc_type = "hash".
3. For IPs:
   3.1 get_ip_address_report.
   3.2 get_ioc_matches with ioc_type = "ip".
4. For domains:
   4.1 lookup_entity with entity_type = "domain".
   4.2 get_ioc_matches with ioc_type = "domain".
5. For users:
   5.1 lookup_entity with entity_type = "user".
6. Store this per-entity in ${ENRICHMENT_RESULTS}.

Decision Points:
1. Identify whether enrichment confirms or raises suspicion about entities.

Outputs:
1. ${ENRICHMENT_RESULTS} detailing threat scores, classifications, and context.


STEP 8.5 – FIND ADDITIONAL RELATED CASES (PARALLEL)
Inputs:
1. ${ALERT_COMPLETE_DETAILS}, ${KEY_ENTITIES}, ${HOSTNAME}, ${ENDPOINT_ID}, ${HOST_IP}, initial related case results from Step 5.

Actions:
1. CRITICAL: Perform exhaustive same-host case search (this is the highest priority):
   MANDATORY: Document all search results explicitly.
   1.1 Use list_cases (status = open or in_progress) to get ALL active cases:
       1.1.1 Count and record the total number of active cases returned.
       1.1.2 For EACH case, you MUST use review_case to examine it (do not skip any).
   1.2 For each active case, use review_case to examine:
       1.2.1 Case title for hostname matches with ${HOSTNAME} (case-insensitive, check for partial matches).
       1.2.2 Case description for hostname, endpoint ID, or IP matches.
       1.2.3 Case observables for matching hostnames, endpoint IDs, or IPs.
       1.2.4 Case creation time and recent comments for timeline alignment (must be within 24 hours of current alert).
       1.2.5 MANDATORY: Record your finding: "[Case ID] - Hostname match: YES/NO - Within 24h: YES/NO"
   1.3 Use search_cases with ${HOSTNAME} explicitly to find all cases mentioning this hostname:
       1.3.1 Try exact hostname match.
       1.3.2 Try partial hostname match if needed.
       1.3.3 Document all cases found.
   1.4 Use search_cases with ${ENDPOINT_ID} (if available) to find endpoint-related cases.
   1.5 Use search_cases with ${HOST_IP} to find IP-related cases.
   1.6 Prioritize any cases found with the same hostname within the last 24 hours as HIGH PRIORITY candidates.
   1.7 MANDATORY DOCUMENTATION: Create an explicit list:
       1.7.1 "Same-host cases found for '${HOSTNAME}' within 24 hours: [list case IDs and titles]"
       1.7.2 "Total cases checked: [number]"
       1.7.3 If none found, explicitly state: "No same-host cases found for '${HOSTNAME}' within 24 hours."
2. Additional entity-based searches:
   2.1 Find cases with same primary entities (user accounts, IPs, hashes, domains) within last 24 hours.
   2.2 Find cases aligned in time (alerts within 2 hours) even if different hosts.
   2.3 Find cases with similar alert types or detection rules within last 24 hours.
3. Group candidate related cases by:
   3.1 Host (highest priority grouping factor).
   3.2 User account.
   3.3 Threat / alert category.
   3.4 This supports holistic incident views and reduces duplicated triage effort.
4. Merge and prioritize findings into ${ADDITIONAL_RELATED_CASES}, with same-host cases within 24 hours at the top of the list.

Decision Points:
1. Determine if a more suitable existing case exists than the current ${PRIMARY_CASE_ID}, giving highest priority to same-host cases within 24 hours.
2. If you found same-host cases, you MUST prioritize them over all other correlation factors.

Outputs:
1. Updated ${ADDITIONAL_RELATED_CASES} with same-host cases prioritized at the top.
2. Explicit documentation of search results and findings.


STEP 8.6 – FIND UNCERTAIN ALERTS ON SAME HOST (PARALLEL)
Inputs:
1. Hostname or endpoint ID from ${ALERT_COMPLETE_DETAILS}.

Actions:
1. Call get_all_uncertain_alerts_for_host with:
   1.1 hostname from alert events.
   1.2 hours_back = 168.
2. Analyze results for patterns:
   2.1 Common alert types or rules.
   2.2 Increasing frequency.
   2.3 Shared entities.
3. Store alerts in ${UNCERTAIN_ALERTS_SAME_HOST}.
4. Store analysis summary in ${UNCERTAIN_PATTERN_ANALYSIS}.

Decision Points:
1. Decide whether multiple uncertain alerts indicate a larger incident.

Outputs:
1. ${UNCERTAIN_ALERTS_SAME_HOST}.
2. ${UNCERTAIN_PATTERN_ANALYSIS}.


STEP 8.7 – CONVERGENCE AND CASE STRATEGY FINALIZATION
Inputs:
1. ${KB_VERIFICATION_RESULTS}.
2. ${IOC_MATCH_RESULTS}.
3. ${INITIAL_SIEM_CONTEXT}.
4. ${ENRICHMENT_RESULTS}.
5. ${ADDITIONAL_RELATED_CASES}.
6. ${UNCERTAIN_ALERTS_SAME_HOST}, ${UNCERTAIN_PATTERN_ANALYSIS}.
7. Initial ${CASE_STRATEGY} and ${PRIMARY_CASE_ID} from Step 5.
8. ${HOSTNAME}, ${ENDPOINT_ID}, ${HOST_IP} from Step 5.

Actions:
1. Combine all investigation outputs.
2. CRITICAL: Re-evaluate ${ADDITIONAL_RELATED_CASES} for same-host matches:
   2.1 If ${ADDITIONAL_RELATED_CASES} contains any cases with the same hostname within 24 hours:
       2.1.1 These cases should take absolute priority over all other correlation factors.
       2.1.2 Select the most recent open case or the case with the most related alerts on this host.
       2.1.3 Update ${PRIMARY_CASE_ID} to this same-host case.
       2.1.4 Set ${CASE_STRATEGY} = "RELATED_CASE".
       2.1.5 Set ${CASE_LINK_EXPLANATION} = "Same host '${HOSTNAME}' within 24 hours; grouping all host-related alerts for comprehensive investigation."
3. If ${CASE_STRATEGY} = "PENDING_INVESTIGATION":
   3.1 If ${ADDITIONAL_RELATED_CASES} contains same-host cases within 24 hours:
       3.1.1 Select the best same-host case (prioritize recent open cases).
       3.1.2 Set ${PRIMARY_CASE_ID} to that case.
       3.1.3 Set ${CASE_STRATEGY} = "RELATED_CASE".
       3.1.4 Set ${CASE_LINK_EXPLANATION} = "Same host '${HOSTNAME}' within 24 hours; consolidating related alerts."
   3.2 Else if ${ADDITIONAL_RELATED_CASES} contains other related cases (entity, timeline, similar alert type):
       3.2.1 Select the most relevant existing case.
       3.2.2 Set ${PRIMARY_CASE_ID} to that case.
       3.2.3 Set ${CASE_STRATEGY} = "RELATED_CASE".
   3.3 Else if no additional related cases are found:
       3.3.1 Keep ${PRIMARY_CASE_ID} = null.
       3.3.2 Set ${CASE_STRATEGY} = "NEW_CASE".
4. If ${CASE_STRATEGY} = "RELATED_CASE":
   4.1 Re-confirm ${PRIMARY_CASE_ID} is still the best choice using ${ADDITIONAL_RELATED_CASES}:
       4.1.1 If a same-host case within 24 hours exists in ${ADDITIONAL_RELATED_CASES} but ${PRIMARY_CASE_ID} is not a same-host case, update ${PRIMARY_CASE_ID} to the same-host case.
       4.1.2 Prioritize same-host cases over entity-based or timeline-based correlations.
5. MANDATORY VALIDATION CHECKPOINT: Before proceeding to Step 9, explicitly document:
   5.1 Final ${CASE_STRATEGY} decision.
   5.2 Final ${PRIMARY_CASE_ID} (if applicable).
   5.3 Explicit confirmation: "For hostname '${HOSTNAME}', I have checked [X] active cases and found [same-host cases list or 'none']."
   5.4 If ${CASE_STRATEGY} = "NEW_CASE", explicitly state: "CONFIRMED: No existing case for hostname '${HOSTNAME}' within 24 hours after exhaustive search."

Decision Points:
1. Final decision between RELATED_CASE and NEW_CASE when NOT an exact duplicate.
2. Ensure same-host cases within 24 hours are always selected over other correlation types.
3. If you cannot explicitly confirm the case search results, DO NOT proceed to create a new case - re-examine existing cases first.

Outputs:
1. Finalized ${CASE_STRATEGY}.
2. Finalized ${PRIMARY_CASE_ID} (prioritizing same-host cases).
3. Updated ${CASE_LINK_EXPLANATION} if case strategy changed.


STEP 9 – ASSESSMENT
Inputs:
1. All investigation results from Step 8.
2. ${ADDITIONAL_RELATED_CASES} (especially same-host cases within 24 hours).

Actions:
1. Assess overall outcome:
   1.1 False Positive (FP).
   1.2 Benign True Positive (BTP).
   1.3 True Positive / Suspicious (TP).
   1.4 Uncertain.
2. Use ${UNCERTAIN_PATTERN_ANALYSIS} to decide:
   2.1 If multiple uncertain alerts on the same host indicate a likely TP that should be escalated.
   2.2 If a single uncertain alert with no pattern remains Uncertain and does not justify a case.
3. Consider case correlation context:
   3.1 If ${ADDITIONAL_RELATED_CASES} contains same-host cases within 24 hours, note that these alerts should be grouped together regardless of assessment.
   3.2 Multiple TP or uncertain alerts on the same host within 24 hours strongly suggests a single incident that should be investigated holistically.
4. Set ${ASSESSMENT} accordingly.

Decision Points:
1. Select final assessment category (FP, BTP, TP, Uncertain) based on combined evidence.

Outputs:
1. ${ASSESSMENT} for this alert.


STEP 10 – ANALYZE RESULTS AND CREATE VISIBILITY RECOMMENDATIONS
Inputs:
1. ${ASSESSMENT}.
2. Investigation outputs (${KB_VERIFICATION_RESULTS}, ${IOC_MATCH_RESULTS}, ${INITIAL_SIEM_CONTEXT}, ${ENRICHMENT_RESULTS}, ${ADDITIONAL_RELATED_CASES}, ${UNCERTAIN_PATTERN_ANALYSIS}).

Actions:
1. For TP or Uncertain assessments:
   1.1 Identify visibility gaps:
       1.1.1 Missing SIEM or KB data.
       1.1.2 Limited event context that made triage difficult.
       1.1.3 Detection rules lacking necessary context.
   1.2 If meaningful gaps are found:
       1.2.1 Prepare a visibility recommendation title.
       1.2.2 Prepare a description summarizing the gap and its impact.
       1.2.3 Call create_visibility_recommendation with appropriate tags.
2. Record any created visibility recommendation in later notes or case comments.

Decision Points:
1. Decide whether visibility improvements are required based on investigation difficulties.

Outputs:
1. Optional new or updated visibility recommendations in the engineering board.


STEP 11 – FINAL ACTION BASED ON ASSESSMENT
This step branches into three sub-paths: FP/BTP, TP, and Uncertain.


STEP 11.1 – CASE ID DETERMINATION (ONLY FOR TP)
Case determination for TP MUST only occur after all assessment, investigation, and correlation steps (Steps 4–10) are complete. Never call create_case earlier in the workflow; always exhaust existing-case correlation options first.

CRITICAL RULE: Before creating any new case, perform a FINAL exhaustive check for same-host cases within the last 24 hours. Same-host alerts should almost always be grouped together.

MANDATORY VALIDATION: You MUST explicitly document the results of the case search before creating any new case. If you cannot explicitly confirm that NO same-host cases exist within 24 hours, you MUST NOT create a new case.

Inputs:
1. ${ASSESSMENT}, ${CASE_STRATEGY}, ${PRIMARY_CASE_ID}, ${ALERT_COMPLETE_DETAILS}, ${KEY_ENTITIES}, ${HOSTNAME}, ${ENDPOINT_ID}, ${HOST_IP}, ${ADDITIONAL_RELATED_CASES}.

Actions:
1. If ${ASSESSMENT} is not TP, skip to the relevant FP/BTP or Uncertain sub-step.
2. CRITICAL FINAL CHECK: Before proceeding, perform an exhaustive same-host case search:
   MANDATORY STEPS - DO NOT SKIP ANY:
   2.1 Use list_cases (status = open or in_progress) to get ALL active cases:
       2.1.1 This MUST return a complete list of all currently open and in-progress cases.
       2.1.2 Count the number of active cases returned.
       2.1.3 Document: "Checking [X] active cases for hostname '${HOSTNAME}' matches."
   2.2 For EACH active case returned, use review_case to check:
       2.2.1 Case title for hostname match with ${HOSTNAME} (case-insensitive, partial matches count).
       2.2.2 Case description for hostname, endpoint ID, or IP matches with ${HOSTNAME}, ${ENDPOINT_ID}, or ${HOST_IP}.
       2.2.3 Case observables for matching hostnames, endpoint IDs, or IPs.
       2.2.4 Case creation time (must be within 24 hours of current alert timestamp).
       2.2.5 MANDATORY: For each case checked, record: "[Case ID] - [Case Title] - Hostname match: YES/NO - Within 24h: YES/NO"
   2.3 Use search_cases with ${HOSTNAME} explicitly (text search) to find ALL cases mentioning this hostname:
       2.3.1 Try multiple search variations: exact hostname, partial hostname, IP address.
       2.3.2 Document all cases found in this search.
   2.4 MANDATORY DOCUMENTATION: Before proceeding, explicitly state:
       2.4.1 "Same-host case search results for hostname '${HOSTNAME}':"
       2.4.2 "Total active cases checked: [number]"
       2.4.3 "Same-host cases found within 24 hours: [list case IDs, titles, and timestamps]"
       2.4.4 "If no same-host cases found, explicitly state: 'CONFIRMED: No existing cases found for hostname '${HOSTNAME}' within 24 hours after exhaustive search of [X] active cases.'"
   2.5 If any same-host case is found within 24 hours:
       2.5.1 Select the most recent open case or the case with the most related alerts.
       2.5.2 Set ${CASE_ID} = that case (override ${PRIMARY_CASE_ID} if different).
       2.5.3 Do NOT create a new case.
       2.5.4 Set ${ALERT_CASE_DECISION} = "EXISTING_CASE".
       2.5.5 Set ${CASE_LINK_EXPLANATION} = "Same host '${HOSTNAME}' within 24 hours; grouping all host-related alerts for comprehensive investigation. Found existing case [Case ID] created at [timestamp]."
       2.5.6 Proceed to Step 11.3 with this existing case.
3. If ${PRIMARY_CASE_ID} exists (RELATED_CASE) and no same-host case override occurred:
   3.1 Set ${CASE_ID} = ${PRIMARY_CASE_ID}.
   3.2 Do not create a new case.
   3.3 Set ${ALERT_CASE_DECISION} = "EXISTING_CASE".
   3.4 Set ${CASE_LINK_EXPLANATION} to a short justification describing why this alert is linked to the existing case (for example, "Related to ongoing RDP investigation on host X" or "Same user and attack type within 30 minutes").
4. If ${PRIMARY_CASE_ID} is null (NEW_CASE candidate) and no same-host case was found in step 2:
   4.1 Perform a final related-case check using search_cases and list_cases by:
       4.1.1 Hostname (re-check with explicit search).
       4.1.2 Endpoint ID if available.
       4.1.3 Primary entities (user, IP, hash, domain).
       4.1.4 Alert timestamp ± 24 hours (extended window).
       4.1.5 Similar alert types or rules.
   4.2 Review ${ADDITIONAL_RELATED_CASES} for any missed same-host cases.
   4.3 If any related case is found (especially same-host):
       4.3.1 Prioritize same-host cases over other correlations.
       4.3.2 Choose the most relevant case.
       4.3.3 Set ${CASE_ID} = that case.
       4.3.4 Do not create a new case.
       4.3.5 Set ${ALERT_CASE_DECISION} = "EXISTING_CASE".
       4.3.6 Set ${CASE_LINK_EXPLANATION} with a concise reason for the linkage (for example, "Same host '${HOSTNAME}' within 24 hours; grouping related alerts" or "Same host and user within 1 hour; same malware family").
   4.4 If no related case is found after exhaustive checks (including same-host within 24 hours):
       MANDATORY PRE-CREATION VALIDATION:
       4.4.0 Before creating a new case, you MUST explicitly confirm:
             4.4.0.1 "I have checked ALL [X] active cases using list_cases and review_case."
             4.4.0.2 "I have searched using search_cases with hostname '${HOSTNAME}'."
             4.4.0.3 "I have searched using search_cases with IP '${HOST_IP}'."
             4.4.0.4 "I have checked ${ADDITIONAL_RELATED_CASES} from Step 8.5."
             4.4.0.5 "CONFIRMED: No existing case found for hostname '${HOSTNAME}' within 24 hours after exhaustive search."
             4.4.0.6 If you cannot explicitly confirm all of the above, DO NOT create a new case - re-examine existing cases first.
       4.4.1 Create a new case using create_case only if:
             4.4.1.1 ${ASSESSMENT} = TP.
             4.4.1.2 No relevant case exists after all exhaustive checks documented above.
             4.4.1.3 You have explicitly confirmed the pre-creation validation (step 4.4.0).
       4.4.2 Case title: "[Alert Type] - [Primary Entity] - [Date/Time]".
       4.4.3 Case description must include all critical alert details from ${ALERT_COMPLETE_DETAILS}, including hostname, entities, and timestamps.
       4.4.4 Set case priority from alert severity.
       4.4.5 Set case status to in_progress and tag with soc1-triage and alert type.
       4.4.6 Set ${CASE_ID} to the new case ID.
       4.4.7 Set ${ALERT_CASE_DECISION} = "NEW_CASE".
       4.4.8 Set ${CASE_LINK_EXPLANATION} to explain why a new case was required, explicitly stating:
             4.4.8.1 "Exhaustive search completed: checked [X] active cases, searched hostname '${HOSTNAME}' and IP '${HOST_IP}'."
             4.4.8.2 "No existing case found for hostname '${HOSTNAME}' within 24 hours; new incident on this host."
             4.4.8.3 Or: "No existing case with same host/user/attack type; isolated incident."
             4.4.8.4 This explanation must prove that the search was thorough and documented.

Decision Points:
1. Existing related case vs new case creation for TP.

Outputs:
1. ${CASE_ID} for TP path, or null if FP/BTP or Uncertain.
2. ${ALERT_CASE_DECISION} and ${CASE_LINK_EXPLANATION} populated for this alert, indicating whether it was attached to an existing case or a new case was created and why.


STEP 11.2 – FINAL ACTION FOR FP/BTP
This executes when ${ASSESSMENT} = FP or BTP and no earlier direct closure already occurred.

Inputs:
1. ${ALERT_ID}, ${ASSESSMENT}, ${ALERT_COMPLETE_DETAILS}, ${KB_VERIFICATION_RESULTS}, ${IOC_MATCH_RESULTS}, ${INITIAL_SIEM_CONTEXT}, ${ENRICHMENT_RESULTS}, optional ${CASE_ID}.

Actions:
0. Set ${ALERT_CASE_DECISION}:
   0.1 If ${CASE_ID} exists, set ${ALERT_CASE_DECISION} = "EXISTING_CASE".
   0.2 If no case is used, set ${ALERT_CASE_DECISION} = "NO_CASE".
   0.3 In all cases, set ${CASE_LINK_EXPLANATION} to briefly explain why the alert was linked to a case or left without a case (for example, "FP linked to existing noise case on host X" or "Clear FP; no case required").
1. Add comprehensive alert note via add_alert_note:
   1.1 Investigation summary (KB, IOC, SIEM, enrichment).
   1.2 Final FP/BTP assessment and reasoning.
1.3 Case reference if a related case exists, explicitly stating whether the alert was attached to an existing case or no case was used, using ${ALERT_CASE_DECISION} and ${CASE_LINK_EXPLANATION}.
   1.4 Fine-tuning or rule-improvement recommendations.
2. Update alert verdict with update_alert_verdict:
   2.1 verdict = "false_positive" or "benign_true_positive".
   2.2 Include a reference to the detailed note.
3. Fine-tuning recommendations:
   3.1 Use list_fine_tuning_recommendations to find matching items.
   3.2 Add a comment or create a new entry as in Step 4.3.
4. If ${CASE_ID} exists (related case):
   4.1 Add a brief comment to the case summarizing the FP/BTP decision.
   4.2 Optionally close the case if all associated alerts are FP/BTP using update_case_status.

Decision Points:
1. Determine whether an existing fine-tuning item is updated or a new item is created.
2. Decide whether to close a related case if all alerts are FP/BTP.

Outputs:
1. ${ACTION_TAKEN} = "Closed as FP/BTP during SOC1 triage with engineering feedback."
2. Alert verdict updated, notes and recommendations recorded, case optionally updated.


STEP 11.3 – FINAL ACTION FOR CONFIRMED TP
This executes when ${ASSESSMENT} = TP.

Inputs:
1. ${ALERT_ID}, ${CASE_ID}, ${ALERT_COMPLETE_DETAILS}, ${KEY_ENTITIES}, ${INITIAL_SIEM_CONTEXT}, ${ENRICHMENT_RESULTS}, ${KB_VERIFICATION_RESULTS}, ${IOC_MATCH_RESULTS}, ${ADDITIONAL_RELATED_CASES}, ${UNCERTAIN_ALERTS_SAME_HOST}, ${UNCERTAIN_PATTERN_ANALYSIS}.

Actions:
1. Add a detailed alert note with add_alert_note:
   1.1 All key timestamps (alert and event).
   1.2 Investigation summary and key findings.
   1.3 Reason for TP decision and need for SOC2 investigation.
   1.4 MANDATORY CASE CORRELATION DOCUMENTATION:
       1.4.1 Explicitly state ${ALERT_CASE_DECISION} ("EXISTING_CASE" or "NEW_CASE").
       1.4.2 Include ${CASE_LINK_EXPLANATION} explaining why this alert was added to an existing case or why a new case was created.
       1.4.3 If EXISTING_CASE: State which case it was linked to, the case creation time, and why (e.g., "Linked to Case #[ID] - Same host '${HOSTNAME}' within 24 hours; case created at [timestamp]. This alert is part of the same incident.")
       1.4.4 If NEW_CASE: Explicitly document the exhaustive search performed: "Created new Case #[ID]. Exhaustive search completed: checked [X] active cases, searched hostname '${HOSTNAME}' and IP '${HOST_IP}'. No existing case found for hostname '${HOSTNAME}' within 24 hours."
   1.5 Case ID reference: ${CASE_ID}.
   1.6 Any visibility recommendations created in Step 10.
2. Add a detailed case comment via add_case_comment for ${CASE_ID}:
   2.1 All essential alert and event details from ${ALERT_COMPLETE_DETAILS}.
   2.2 Triaging timestamps and findings.
   2.3 Primary entities and their enrichment context.
   2.4 Related alerts and cases.
   2.5 MANDATORY: Explicit statement that this is confirmed TP and is escalated to SOC2.
   2.6 MANDATORY: Include ${CASE_LINK_EXPLANATION} explaining why this alert belongs in this case:
       2.6.1 If EXISTING_CASE: "This alert was added to existing case because: [explanation from ${CASE_LINK_EXPLANATION}]. Same host '${HOSTNAME}' within 24 hours."
       2.6.2 If NEW_CASE: "New case created for this alert. Exhaustive search confirmed no existing case for hostname '${HOSTNAME}' within 24 hours."
   2.7 Document host, user, attack type, and timeframe correlation details.
3. Attach observables to the case using attach_observable_to_case for top 3–5 primary entities.
4. Update case status with update_case_status to in_progress.
5. Update alert verdict to true_positive using update_alert_verdict with a clear escalation comment.
6. Create an initial SOC2 task via add_case_task:
   6.1 Title: "Deep Investigation – [Alert Type]" or alert-specific variant (for example, malware, network, user).
   6.2 Description:
       6.2.1 Alert context, timestamps, and key entities.
       6.2.2 Why SOC2 investigation is required.
       6.2.3 Summary of SOC1 findings.
       6.2.4 Specific verification and investigation steps SOC2 should take.
   6.3 Priority = high or critical depending on severity and IOC matches.
7. Update uncertain alerts on the same host when applicable:
   7.1 For each alert in ${UNCERTAIN_ALERTS_SAME_HOST} that is clearly part of the same incident:
       7.1.1 Update verdict from uncertain to true_positive using update_alert_verdict.
       7.1.2 Add an alert note linking it to ${CASE_ID} and ${ALERT_ID} and explaining the correlation.
8. Ensure that alerts within the same incident are grouped logically by host, user account, and threat category in case comments and tasks so that SOC2 can see a holistic view rather than fragmented per-alert notes.

Decision Points:
1. Which uncertain alerts on the same host should be upgraded to TP and linked to the case.

Outputs:
1. ${ACTION_TAKEN} = "Escalated to SOC2 with case and tasks created or updated."
2. ${ESCALATION_RECOMMENDATION} summarizing why escalation is required.


STEP 11.3.1 – TASK MANAGEMENT FOR SOC2
Inputs:
1. ${CASE_ID}, ${IOC_MATCH_RESULTS}, ${INITIAL_SIEM_CONTEXT}, ${ENRICHMENT_RESULTS}, ${ADDITIONAL_RELATED_CASES}.

Actions:
1. List existing tasks with list_case_tasks.
2. Mark any completed SOC1-related tasks as completed using update_case_task_status.
3. Create additional SOC2 tasks as needed, such as:
   3.1 IOC verification and impact assessment.
   3.2 Network traffic deep analysis.
   3.3 File hash and endpoint investigation.
   3.4 User account activity investigation.
   3.5 Alert correlation and pattern analysis.
   3.6 Endpoint deep investigation for specific hosts.
   3.7 Threat intelligence gap analysis when enrichment was incomplete.

Decision Points:
1. Which specific SOC2 tasks are required based on findings.

Outputs:
1. Structured SOC2 task list aligned with the confirmed TP and case.


STEP 11.4 – FINAL ACTION FOR UNCERTAIN ALERTS
This executes when ${ASSESSMENT} = Uncertain.

Inputs:
1. ${ALERT_ID}, ${ASSESSMENT}, ${ALERT_COMPLETE_DETAILS}, investigation outputs, any visibility recommendation IDs.

Actions:
0. Set ${ALERT_CASE_DECISION} = "NO_CASE" and set ${CASE_LINK_EXPLANATION} to briefly explain why no case was created (for example, "Insufficient evidence to justify case; alert left as Uncertain for monitoring").
1. Add a comprehensive alert note via add_alert_note:
   1.1 Investigation summary across KB, IOC, SIEM, enrichment, and cases.
   1.2 Explicit statement that the alert remains Uncertain.
   1.3 Explanation of why legitimacy cannot be confirmed or denied.
1.4 Statement that no case was created and that the alert is left open for monitoring, explicitly including ${ALERT_CASE_DECISION} and ${CASE_LINK_EXPLANATION} so it is clear that this alert was not attached to any case and why.
   1.5 Reference to any visibility recommendation created in Step 10.
2. Update alert verdict to uncertain using update_alert_verdict with a clear comment.

Decision Points:
1. None beyond confirming that criteria for TP or FP/BTP are not met.

Outputs:
1. ${ACTION_TAKEN} = "Alert assessed as Uncertain and left open for monitoring; no case created."
2. Alert verdict set to uncertain with full documentation.


COMPLETION CRITERIA
1. Workflow started from get_recent_alerts, not from existing cases.
2. get_security_alert_by_id was executed first for the selected alert, and existing verdicts were respected.
3. Exact event messages were read and used to extract entities and understand what actually happened.
4. Verdict was set to in-progress before investigation began.
5. Quick Assessment (Step 4) was performed to attempt FP/BTP closure before any case work.
6. Case Strategy (Step 5) explicitly evaluated exact duplicates and related cases.
7. Parallel investigation (Step 8) ran before any new case creation.
8. Final assessment (Step 9) was made based on combined investigation results.
9. Visibility recommendations (Step 10) were evaluated and created when appropriate.
10. Final action (Step 11) followed policy:
    10.1 Cases were created or updated only for confirmed TPs and only after related-case checks.
    10.2 False positives and benign true positives were closed without new case creation.
    10.3 Uncertain alerts did not result in case creation and remain documented in alert notes.
11. All actions and decisions were clearly documented in alert notes and, when applicable, in case comments and tasks.

Section Outputs:
1. Clear verification that the SOC1 triage for this alert is complete and compliant with policy.


