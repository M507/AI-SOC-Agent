# SOC2: Case Analysis Runbook

## Objective

To provide a standardized process for SOC2 analysts to perform **DEEP, ADVANCED investigation and analysis** of cases escalated from SOC1. **SOC2 MUST ALWAYS BEGIN FROM CASES (`${CASE_ID}`), NEVER FROM RAW ALERT QUEUE.** 

**SOC2's Core Mission:** SOC2 performs investigation **LEVELS ABOVE SOC1** by:
- **Advanced Elastic/KQL Querying:** Deep, complex queries across multiple indices, extended time windows, and comprehensive entity analysis
- **Comprehensive Entity Pivoting:** Analyze ALL entities (not just 3-5 primary entities like SOC1)
- **Extended Time Analysis:** Query 7-30 days back (vs SOC1's 24-hour window) to identify attack patterns and persistence
- **Attack Chain Reconstruction:** Build complete attack timelines and map to MITRE ATT&CK
- **Multi-Case Correlation:** Evidence-based correlation across cases and alerts
- **Deep CTI Enrichment:** Comprehensive threat intelligence analysis for all entities

This runbook guides the analyst in:
1. **MANDATORY:** Starting with `${CASE_ID}` and reviewing ALL case details first.
2. Completing pending tasks from SOC1 or previous SOC2 work.
3. Performing **DEEP SIEM analysis** using advanced Elastic/KQL queries (SOC2's core strength).
4. Performing comprehensive entity pivoting and correlation beyond SOC1's scope.
5. Completing comprehensive CTI enrichment for ALL entities.
6. Determining if case-specific runbooks should be executed (e.g., malware analysis, suspicious login investigation).
7. Reconstructing attack chains and mapping to MITRE ATT&CK techniques.
8. Producing detailed containment recommendations for SOC3.
9. Documenting all findings comprehensively.

## Scope

This runbook covers:
*   Initial case review and context gathering (SOC2 MUST start from `${CASE_ID}`).
*   Task management - completing pending tasks and creating new investigation tasks.
*   **DEEP SIEM Analysis (SOC2 Core):**
    *   Advanced Elastic/KQL querying across multiple indices
    *   Complex queries with aggregations, joins, and cross-correlations
    *   Extended time windows (7-30 days vs SOC1's 24 hours)
    *   Comprehensive entity pivoting on ALL entities (not just 3-5 like SOC1)
    *   Deep network, DNS, and email analysis
    *   Advanced alert correlation and event chain analysis
*   **Comprehensive CTI and Entity Enrichment:**
    *   Full enrichment of ALL important IOCs (not just subset like SOC1)
    *   Advanced threat intelligence analysis
    *   File behavior analysis and entity relationships
*   Entity correlation and connection discovery (with evidence-based approach).
*   Client infrastructure verification.
*   Attack chain reconstruction and MITRE ATT&CK mapping.
*   Containment recommendation generation.

This runbook explicitly **excludes**:
*   Starting from raw alerts (SOC1 responsibility).
*   Direct containment execution (SOC3 responsibility).
*   Initial triage of new alerts (SOC1 responsibility).

## SOC Tier

**Tier:** SOC2 (Tier 2)  
**Escalation Target:** SOC3 for containment actions

## Inputs

*   `${CASE_ID}`: **REQUIRED** - The identifier for the case from the case management system. SOC2 MUST ALWAYS START FROM `${CASE_ID}`, never from `${ALERT_ID}`.

## Outputs

*   `${CASE_ASSESSMENT}`: Comprehensive assessment of the case (threat level, attack chain, scope).
*   `${CORRELATION_FINDINGS}`: Documented connections to other cases/alerts (only with clear evidence).
*   `${CONTAINMENT_RECOMMENDATIONS}`: Detailed recommendations for SOC3 (endpoints, processes, network IOCs).
*   `${INVESTIGATION_SUMMARY}`: Complete investigation summary with all findings.

## Tools

*   **Case Management:** `review_case`, `list_case_tasks`, `list_case_timeline_events`, `add_case_task`, `update_case_task_status`, `add_case_comment`, `attach_observable_to_case`, `update_case_status`, `link_cases`, `add_case_asset`
*   **SIEM:** `search_security_events`, `search_kql_query`, `pivot_on_indicator`, `get_network_events`, `get_dns_events`, `get_email_events`, `get_alerts_by_entity`, `get_alerts_by_time_window`, `get_security_alert_by_id`
*   **CTI:** `lookup_hash_ti`, `get_threat_intel`, `get_file_report`, `get_file_behavior_summary`, `get_entities_related_to_file`, `get_ip_address_report`
*   **Entity Analysis:** `lookup_entity`, `get_ioc_matches`, `search_user_activity`
*   **KB:** `kb_list_clients`, `kb_get_client_infra`

## Workflow Steps

1.  **Review Case (MANDATORY FIRST STEP):**
    *   **SOC2 MUST ALWAYS START FROM `${CASE_ID}`** - this is the entry point for all SOC2 workflows.
    *   **MUST use `review_case` with `case_id=${CASE_ID}` as the FIRST action.**
    *   Read ALL case details:
        *   Title, description, status, priority, tags
        *   ALL observables (IPs, domains, hashes, users, hostnames)
        *   ALL evidence files and artifacts
        *   ALL assets (endpoints, servers, networks, user accounts)
    *   Review ALL case comments and notes to understand previous analysis.
    *   Extract alert details from case description/comments (SOC1 should have documented all alert details).
    *   Store complete case context in `${CASE_CONTEXT}`.

2.  **Review Case Tasks and Timeline:**
    *   Use `list_case_tasks` to identify all tasks for this case.
    *   Use `list_case_timeline_events` to understand case history.
    *   Identify pending tasks (`status="pending"`) that need completion.
    *   Review completed tasks to understand what analysis has already been done.
    *   **Do not repeat work** that is already marked as `completed` unless explicitly needed.

3.  **Complete Pending Tasks:**
    *   For each pending task:
        *   Update task status to `in_progress` using `update_case_task_status`.
        *   Perform the analysis described in the task.
        *   Document findings in case comment referencing the task.
        *   Update task status to `completed`.
    *   If a task cannot be completed, document why and update status accordingly.

4.  **Initial Case Assessment:**
    *   Analyze all case data to understand:
        *   What type of threat/incident this is (malware, suspicious login, network anomaly, etc.)
        *   What entities are involved (hosts, users, IPs, domains, hashes)
        *   What analysis gaps exist
        *   What additional investigation is needed
    *   **Determine if case-specific runbooks should be executed:**
        *   **Check for case-specific runbooks in `run_books/soc2/cases/*.md`:**
            *   **If malware-related:** Case involves malware, file hashes, or malicious executables → Execute `soc2/cases/malware_deep_analysis.md` runbook
            *   **If suspicious login:** Case involves suspicious login, authentication anomalies, or account compromise → Execute `soc2/cases/suspicious_login_investigation.md` runbook
            *   **Other case types:** Check for other case-specific runbooks that match the case type
        *   **If case-specific runbook matches:**
            *   Execute the case-specific runbook (it will perform deep SIEM analysis tailored to that case type)
            *   Case-specific runbook will handle Steps 5-9 (SIEM Analysis, CTI Enrichment, KB Verification, Correlation, Attack Chain)
            *   Return to this main runbook at Step 10 (Add Timeline Events) after case-specific runbook completes
        *   **If no case-specific runbook matches:**
            *   Continue with generic Step 5 (Comprehensive SIEM Analysis) below
        *   **If multi-IOC correlation needed:** Use Step 8 (Correlation Analysis) or `soc2/correlation/multi_ioc_correlation.md` runbook

5.  **Comprehensive SIEM Analysis (SOC2 Core Strength - Deep Elastic Querying):**
    *   **CRITICAL:** This is where SOC2 demonstrates its advanced capabilities far beyond SOC1. SOC1 performed basic searches - SOC2 performs DEEP, COMPREHENSIVE analysis using advanced Elastic/KQL queries.
    *   **Note:** If Step 4 identified a case-specific runbook (e.g., `malware_deep_analysis.md`, `suspicious_login_investigation.md`), that runbook should have been executed instead of this generic Step 5. Only proceed with this Step 5 if no case-specific runbook matched the case type or if generic analysis is still needed.
    *   Create task: "SOC2 - Comprehensive SIEM Analysis" if not exists.
    *   **Analysis Branch Selection Logic:**
        *   **CRITICAL:** Use logic to determine which analysis branches are applicable based on case type, entities involved, and investigation needs
        *   **It's OKAY to use ALL branches if all are applicable** - don't limit yourself if the case requires comprehensive analysis across all areas
        *   **Choose applicable branches:**
            *   If case involves network activity → Use Network Analysis branch
            *   If case involves DNS queries or domain activity → Use DNS Analysis branch
            *   If case involves email or phishing → Use Email Analysis branch
            *   If case involves multiple alerts or entities → Use Alert Correlation branch
            *   If case involves file hashes or processes → Use Entity Pivoting branch
            *   If case requires deep event analysis → Use Security Event Search branch
            *   If case requires complex queries → Use Advanced KQL Queries branch
        *   **If ALL branches are applicable (e.g., comprehensive malware case with network, DNS, email, and multiple alerts), use ALL branches** - this is expected for complex cases
    *   **Advanced KQL/Elastic Querying (MANDATORY - SOC2's Core Strength):**
        *   **Use `search_kql_query` extensively** - this is SOC2's primary tool for deep investigation:
            *   **Complex multi-index queries:** Query across multiple Elastic indices simultaneously (security-events, network-logs, dns-logs, email-logs, endpoint-events, etc.)
            *   **Time-based analysis:** Expand time windows beyond SOC1's 24-hour searches. Query 7-30 days back to identify attack patterns, persistence mechanisms, and historical activity
            *   **Aggregations and statistics:** Use KQL aggregations (stats, count, sum, avg) to identify patterns, anomalies, and trends
            *   **Join operations:** Join events across different indices to correlate activities (e.g., join process execution with network connections)
            *   **Advanced filtering:** Use complex WHERE clauses with multiple conditions, regex patterns, and nested queries
            *   **Field-level analysis:** Query specific fields deeply (process.command_line, network.payload, file.path, registry.key, etc.)
            *   **Cross-correlation queries:** Query for relationships between entities that SOC1 couldn't identify (e.g., same process hash on multiple hosts, same user accessing multiple suspicious domains)
        *   **Query Strategy:**
            *   Start with broad queries to understand scope, then narrow down with specific filters
            *   Query for attack patterns and MITRE ATT&CK techniques
            *   Query for lateral movement indicators (SMB, RDP, WMI, PowerShell remoting)
            *   Query for persistence mechanisms (scheduled tasks, services, registry run keys, startup folders)
            *   Query for data exfiltration patterns (large outbound transfers, unusual protocols, suspicious domains)
            *   Query for privilege escalation indicators (UAC bypass, token manipulation, process injection)
    *   **Entity Pivoting (Use for comprehensive entity analysis - can be used with other branches):**
        *   **Use `pivot_on_indicator` for ALL entities** - SOC1 only pivoted on 3-5 primary entities. SOC2 pivots on EVERY entity:
            *   **All hosts/endpoints** identified in the case
            *   **All users** (not just primary user - include service accounts, admin accounts, compromised accounts)
            *   **All IP addresses** (source, destination, internal, external)
            *   **All domains** (queried domains, resolved domains, C2 domains)
            *   **All file hashes** (executables, scripts, documents, DLLs)
            *   **All process names** and command lines
            *   **All registry keys** and file paths
            *   **All network ports** and protocols
            *   **Timelines** - pivot on time ranges to identify attack progression
        *   **Pivot Strategy:**
            *   For each entity, query for ALL related activity (not just recent activity)
            *   Identify relationships between entities that weren't obvious
            *   Find additional compromised systems or accounts
            *   Identify attack progression and lateral movement paths
        *   **Note:** Use this branch for comprehensive entity analysis. Can be used together with other branches if applicable.
    *   **Deep Network Analysis (Use if case involves network activity - can be used with other branches):**
        *   **Use `get_network_events` with comprehensive parameters:**
            *   Query full network traffic for all involved IPs (not just primary IPs)
            *   Analyze connection patterns and data transfer volumes
            *   Identify C2 communications and beaconing patterns
            *   Detect data exfiltration (large outbound transfers, unusual protocols)
            *   Analyze network timing patterns (beacon intervals, connection durations)
            *   Correlate network activity with process execution
        *   **Advanced Network Queries:**
            *   Query for unusual port usage (non-standard ports, high ports)
            *   Query for protocol anomalies (HTTP over non-standard ports, encrypted traffic to suspicious domains)
            *   Query for network-based lateral movement (SMB, RDP, WMI connections)
        *   **Note:** Use this branch if case involves network activity. Can be used together with other branches if applicable.
    *   **Deep DNS Analysis (Use if case involves DNS/domain activity - can be used with other branches):**
        *   **Use `get_dns_events` comprehensively:**
            *   Query ALL DNS queries for involved domains (not just primary domain)
            *   Analyze DNS query patterns (frequency, timing, query types)
            *   Identify DNS tunneling or data exfiltration via DNS
            *   Correlate DNS queries with network connections
            *   Identify subdomain enumeration or domain generation algorithms (DGA)
            *   Query for DNS resolution failures that might indicate C2 infrastructure
        *   **Advanced DNS Queries:**
            *   Query for unusual DNS query types (TXT, MX, CNAME abuse)
            *   Query for DNS-based persistence or C2 mechanisms
        *   **Note:** Use this branch if case involves DNS or domain activity. Can be used together with other branches if applicable.
    *   **Deep Email Analysis (Use if case involves email/phishing activity - can be used with other branches):**
        *   **Use `get_email_events` comprehensively:**
            *   Query ALL email activity for involved users (not just primary user)
            *   Analyze email headers for spoofing or manipulation
            *   Identify phishing campaigns and related emails
            *   Analyze attachments and links in emails
            *   Correlate email activity with other attack vectors
        *   **Note:** Use this branch if case involves email or phishing activity. Can be used together with other branches if applicable.
    *   **Alert Correlation (Use if case involves multiple alerts or entities - can be used with other branches):**
        *   **Use `get_alerts_by_entity` for comprehensive correlation:**
            *   Query alerts for ALL entities (not just primary entities)
            *   Identify alert patterns and clusters
            *   Correlate alerts across longer time windows (7-30 days)
        *   **Use `get_alerts_by_time_window` for temporal correlation:**
            *   Query alerts in expanded time windows around the incident
            *   Identify alert sequences that indicate attack progression
            *   Correlate alerts with events to build complete timeline
        *   **Use `get_security_alert_by_id` to read ALL related alerts:**
            *   Read alert details and AI comments for all correlated alerts
            *   Extract entities and events from related alerts
            *   Build comprehensive understanding of the full incident scope
        *   **Note:** Use this branch if case involves multiple alerts or requires correlation. Can be used together with other branches if applicable.
    *   **Security Event Search (Use for deep event analysis - can be used with other branches):**
        *   **Use `search_security_events` for comprehensive event analysis:**
            *   Search for security events related to case entities
            *   Identify event patterns and anomalies
            *   Analyze event sequences and chains
        *   **Event Deep Dive:**
            *   **For each significant event identified:**
                *   Query for related events using event IDs, timestamps, and entities
                *   Analyze event chains and process trees
                *   Identify parent-child process relationships
                *   Trace file access and modification chains
                *   Analyze registry modifications and persistence mechanisms
        *   **Note:** Use this branch for deep event analysis. Can be used together with other branches if applicable.
    *   **Documentation:**
        *   Document ALL queries executed (KQL queries, parameters, time ranges)
        *   Document ALL events found (not just summaries - include event IDs, timestamps, full details)
        *   Document ALL pivots performed and entities analyzed
        *   Document patterns identified, anomalies detected, and relationships discovered
        *   Document which analysis branches were used and why
        *   Store comprehensive SIEM analysis results in `${SIEM_DEEP_ANALYSIS_RESULTS}`
    *   **Summary:**
        *   **Use logic to determine which branches are applicable** - choose branches based on case type, entities, and investigation needs
        *   **It's OKAY to use ALL branches if all are applicable** - complex cases may require comprehensive analysis across all areas (KQL queries, entity pivoting, network analysis, DNS analysis, email analysis, alert correlation, event search)
        *   **Don't limit yourself** - if the case requires it, use all applicable analysis branches to ensure comprehensive investigation

6.  **CTI and Entity Enrichment (Comprehensive - Beyond SOC1's Limited Enrichment):**
    *   **CRITICAL:** SOC1 enriched only 3-5 primary entities. SOC2 enriches **ALL important IOCs** comprehensively.
    *   Create task: "SOC2 - CTI and Entity Enrichment" if not exists.
    *   **Comprehensive Entity Enrichment (ALL Entities, Not Just Subset):**
        *   **File Hashes (Deep Analysis):**
            *   Use `lookup_hash_ti` for ALL file hashes (not just primary hash)
            *   Use `get_file_report` for comprehensive file analysis
            *   Use `get_file_behavior_summary` for behavior analysis (process trees, network activity, persistence mechanisms)
            *   Use `get_entities_related_to_file` to find ALL hosts, users, and alerts related to each hash
            *   Analyze file relationships (parent processes, dropped files, modified files)
        *   **IP Addresses (Comprehensive Analysis):**
            *   Use `get_ip_address_report` for ALL IP addresses (source, destination, internal, external)
            *   Use `lookup_entity` for SIEM context on ALL IPs
            *   Analyze IP reputation, geolocation, and threat intelligence
            *   Identify IP relationships (same ASN, same hosting provider, etc.)
        *   **Domains (Deep Analysis):**
            *   Use `lookup_entity` for ALL domains (queried domains, resolved domains, C2 domains)
            *   Use `get_threat_intel` for comprehensive threat intelligence on domains
            *   Analyze domain relationships (subdomains, parent domains, DNS infrastructure)
            *   Identify domain generation algorithms (DGA) or suspicious domain patterns
        *   **Users (Comprehensive Activity Analysis):**
            *   Use `search_user_activity` for ALL users (not just primary user - include service accounts, admin accounts, compromised accounts)
            *   Use `lookup_entity` for user context in SIEM
            *   Analyze user activity patterns, privilege changes, and account modifications
            *   Identify compromised accounts and privilege escalation
        *   **Additional Entities:**
            *   Enrich process names, command lines, registry keys, file paths
            *   Analyze relationships between all entities
    *   **Advanced Threat Intelligence:**
        *   Use `get_threat_intel` for rich CTI context:
            *   Threat actors and campaigns
            *   TTPs (Tactics, Techniques, and Procedures)
            *   Threat intelligence reports and IOCs
            *   Historical threat data and patterns
    *   **Documentation:**
        *   Document ALL enrichment results (not just summaries)
        *   Include threat scores, classifications, and confidence levels
        *   Document relationships and correlations discovered through enrichment
        *   Store comprehensive enrichment results in `${CTI_ENRICHMENT_RESULTS}`

7.  **Client Infrastructure Verification:**
    *   Use `kb_get_client_infra` to retrieve client infrastructure information.
    *   Verify if entities (IPs, hostnames, users) are internal/expected.
    *   This aids in false positive identification and understanding attack scope.
    *   Document infrastructure context.

8.  **Correlation and Connection Discovery:**
    *   Create task: "SOC2 - Multi-Case Correlation Analysis" if not exists.
    *   **CRITICAL: Only make connections with clear, documented evidence.**
    *   Read AI comments for all related alerts using `get_security_alert_by_id` and `get_alerts_by_entity`.
    *   Look for:
        *   Shared IOCs (IPs, domains, hashes, user accounts)
        *   Temporal proximity with logical relationship
        *   Behavioral patterns matching across cases
        *   Explicit relationships documented in case comments
    *   **Never make speculative connections** - if evidence is unclear, document as hypothesis.
    *   Use `link_cases` only when clear evidence exists.
    *   Document all correlation findings with evidence.

9.  **Attack Chain Reconstruction (SOC2 Advanced Analysis):**
    *   Create task: "SOC2 - Attack Chain Reconstruction" if not exists.
    *   **Use SIEM analysis results** from Step 5 to reconstruct complete attack chain:
        *   **Initial Access:** How did the attacker gain initial access? (phishing, exploit, credential theft, etc.)
        *   **Execution:** What was executed? (processes, scripts, commands, file execution)
        *   **Persistence:** How did the attacker maintain access? (scheduled tasks, services, registry, startup folders, etc.)
        *   **Privilege Escalation:** How did the attacker escalate privileges? (UAC bypass, token manipulation, process injection, etc.)
        *   **Defense Evasion:** How did the attacker evade detection? (process hollowing, DLL sideloading, fileless techniques, etc.)
        *   **Credential Access:** How did the attacker obtain credentials? (LSASS dumping, credential harvesting, keylogging, etc.)
        *   **Discovery:** What did the attacker discover? (network scanning, system enumeration, account discovery, etc.)
        *   **Lateral Movement:** How did the attacker move laterally? (SMB, RDP, WMI, PowerShell remoting, etc.)
        *   **Collection:** What data did the attacker collect? (file access, data staging, clipboard capture, etc.)
        *   **Command and Control:** How did the attacker communicate? (C2 channels, DNS tunneling, protocol abuse, etc.)
        *   **Exfiltration:** How did the attacker exfiltrate data? (network transfers, cloud storage, email, etc.)
        *   **Impact:** What impact did the attacker cause? (data destruction, encryption, service disruption, etc.)
    *   **Map to MITRE ATT&CK Framework:**
        *   Identify specific MITRE ATT&CK techniques for each stage
        *   Document technique IDs (e.g., T1055, T1078, T1021)
        *   Provide evidence for each technique mapping
    *   **Build Timeline:**
        *   Create chronological timeline of attack activities
        *   Include all events, pivots, and correlations discovered
        *   Identify attack progression and key milestones
    *   **Document attack chain comprehensively** in case comment with:
        *   Complete attack lifecycle
        *   MITRE ATT&CK technique mappings
        *   Evidence for each stage
        *   Timeline of activities
        *   Relationships between attack stages

10. **Add Timeline Events to Case Timeline (MANDATORY):**
    *   **CRITICAL:** Add ALL discovered events to the case timeline in chronological order. This provides visual timeline for investigation and SOC3.
    *   **Use `add_case_timeline_event` for each significant event:**
        *   **Event Sources:** Events discovered from:
            *   Step 5 (SIEM Analysis) - all significant events from KQL queries, pivots, network/DNS/email analysis
            *   Step 6 (CTI Enrichment) - enrichment events, threat intelligence findings
            *   Step 8 (Correlation) - correlated events from other cases/alerts
            *   Step 9 (Attack Chain) - attack chain stages and milestones
        *   **Event Ordering:**
            *   Sort ALL events by timestamp in chronological order
            *   Ensure events are added in the correct sequence (earliest to latest)
            *   Include events from all sources (SIEM, CTI, correlation, attack chain)
        *   **Event Details for Each Timeline Event:**
            *   **Title:** Brief descriptive title (e.g., "Malware Execution Detected", "Lateral Movement via SMB", "C2 Communication Established")
            *   **Content:** Detailed event description including:
                *   What happened (event type, action)
                *   When it happened (timestamp)
                *   Where it happened (hostname, IP, endpoint)
                *   Who/what was involved (user, process, file, domain, etc.)
                *   Event ID (if available from SIEM)
                *   Evidence and context
            *   **Event Date:** Use actual event timestamp (not current time)
            *   **Source:** Event source (e.g., "SIEM", "CTI", "Correlation", "Attack Chain")
            *   **Category ID:** Appropriate category (e.g., malware, network, process, file, user)
            *   **Tags:** Relevant tags (e.g., "initial-access", "execution", "persistence", "lateral-movement", "c2", "exfiltration")
            *   **Include in Summary:** Set to true for key events
            *   **Include in Graph:** Set to true for events that show relationships
            *   **Sync IOCs/Assets:** Set to true to automatically sync with IOCs and assets
            *   **Related Asset IDs:** Link to related assets if applicable
            *   **Related IOC IDs:** Link to related IOCs if applicable
        *   **Timeline Event Categories:**
            *   Initial Access events
            *   Execution events (process execution, script execution, command execution)
            *   Persistence events (scheduled tasks, services, registry modifications)
            *   Privilege Escalation events
            *   Defense Evasion events
            *   Credential Access events
            *   Discovery events (network scanning, enumeration)
            *   Lateral Movement events (SMB, RDP, WMI connections)
            *   Collection events (file access, data staging)
            *   Command and Control events (C2 communications, DNS queries)
            *   Exfiltration events (data transfers, uploads)
            *   Impact events (data destruction, encryption)
        *   **Documentation:**
            *   Document all timeline events added
            *   Ensure chronological order is maintained
            *   Verify all significant events are included
            *   Store timeline event summary in `${TIMELINE_EVENTS_ADDED}`

11. **Add IOCs, Assets, Notes, Evidences, and Tasks (MANDATORY):**
    *   **CRITICAL:** Add ALL discovered IOCs, assets, notes, evidences, and create tasks (including human tasks) based on investigation findings.
    *   **Add IOCs/Observables:**
        *   **Use `attach_observable_to_case` for ALL discovered IOCs:**
            *   **File Hashes:** All file hashes discovered (executables, scripts, DLLs, documents)
                *   Observable type: "hash"
                *   Description: Include hash type (MD5, SHA256), file name, threat classification, discovery context
            *   **IP Addresses:** All IP addresses involved (source, destination, C2, exfiltration)
                *   Observable type: "ip"
                *   Description: Include IP role (C2, exfiltration, lateral movement), reputation, discovery context
            *   **Domains:** All domains involved (C2 domains, exfiltration domains, suspicious domains)
                *   Observable type: "domain"
                *   Description: Include domain role, threat intelligence, discovery context
            *   **URLs:** All URLs involved (phishing URLs, C2 URLs, download URLs)
                *   Observable type: "url"
                *   Description: Include URL purpose, threat classification, discovery context
            *   **Email Addresses:** All email addresses involved (phishing senders, compromised accounts)
                *   Observable type: "email"
                *   Description: Include email role, threat classification, discovery context
            *   **Registry Keys:** Suspicious registry keys (persistence mechanisms)
                *   Observable type: "registry" or "other"
                *   Description: Include registry key path, purpose, discovery context
            *   **File Paths:** Suspicious file paths (malware locations, persistence locations)
                *   Observable type: "file_path" or "other"
                *   Description: Include file path, purpose, discovery context
        *   **Tags for Observables:**
            *   Add relevant tags (e.g., "c2", "malware", "persistence", "lateral-movement", "exfiltration")
            *   Include MITRE ATT&CK technique tags if applicable
    *   **Add Assets:**
        *   **Use `add_case_asset` for ALL discovered assets:**
            *   **Endpoints:** All compromised or involved endpoints
                *   Asset type: "endpoint"
                *   Include: Endpoint ID, hostname, IP address, operating system, last seen time
                *   Description: Include compromise status, role in attack, discovery context
            *   **Servers:** All involved servers
                *   Asset type: "server"
                *   Include: Server name, IP address, role, last seen time
                *   Description: Include involvement in attack, discovery context
            *   **User Accounts:** All compromised or involved user accounts
                *   Asset type: "user_account"
                *   Include: Username, account type, domain, last seen time
                *   Description: Include compromise status, privilege level, discovery context
            *   **Networks:** Involved network segments
                *   Asset type: "network"
                *   Include: Network CIDR, description
                *   Description: Include involvement in attack, discovery context
            *   **Applications:** Involved applications or services
                *   Asset type: "application"
                *   Include: Application name, version, description
                *   Description: Include involvement in attack, discovery context
        *   **Tags for Assets:**
            *   Add relevant tags (e.g., "compromised", "suspicious", "lateral-movement-target", "data-exfiltration-source")
    *   **Add Notes/Comments:**
        *   **Use `add_case_comment` for comprehensive documentation:**
            *   **Investigation Notes:** Document key findings, patterns, anomalies discovered
            *   **Analysis Notes:** Document analysis methodology, queries used, reasoning
            *   **Correlation Notes:** Document relationships and correlations discovered
            *   **Threat Intelligence Notes:** Document CTI findings and threat context
            *   **Attack Chain Notes:** Document attack chain stages and progression
            *   **Containment Notes:** Document containment considerations and recommendations
        *   **Reference Tasks:** Reference related tasks in comments
        *   **Include Timestamps:** Include timestamps for all activities
    *   **Add Evidences:**
        *   **Use `add_case_evidence` for evidence files and artifacts:**
            *   **SIEM Query Results:** Export and attach significant SIEM query results
                *   Evidence type: "log" or "file"
                *   Description: Include query details, time range, findings
            *   **Process Trees:** Attach process tree diagrams or exports
                *   Evidence type: "file" or "other"
                *   Description: Include process relationships, suspicious processes
            *   **Network Captures:** Attach network capture files if available
                *   Evidence type: "network_capture"
                *   Description: Include capture time, protocols, findings
            *   **File Artifacts:** Attach suspicious files or file metadata
                *   Evidence type: "file"
                *   Description: Include file details, analysis results
            *   **Screenshots:** Attach screenshots of SIEM dashboards, analysis views
                *   Evidence type: "screenshot"
                *   Description: Include what the screenshot shows, context
            *   **Registry Exports:** Attach registry key exports if applicable
                *   Evidence type: "registry" or "file"
                *   Description: Include registry keys, purpose, findings
            *   **Memory Dumps:** Attach memory dumps if available
                *   Evidence type: "memory_dump"
                *   Description: Include dump details, analysis results
        *   **Evidence Documentation:**
            *   Document all evidence added
            *   Include evidence collection time, source, and analysis results
    *   **Create Tasks (Including Human Tasks):**
        *   **Use `add_case_task` for investigation tasks and human tasks:**
            *   **Investigation Tasks (AI/Automated):**
                *   Tasks that can be completed by AI/skills (e.g., "Deep SIEM Analysis", "CTI Enrichment", "Attack Chain Reconstruction")
                *   Status: "completed" if already done, "pending" if needs to be done
                *   Assignee: "SOC2" or leave empty for team assignment
            *   **Human Tasks (Manual/AI Cannot Complete):**
                *   **Identify tasks that require human intervention:**
                    *   Tasks requiring manual analysis or decision-making
                    *   Tasks requiring access to systems AI cannot access
                    *   Tasks requiring coordination with other teams
                    *   Tasks requiring approval or authorization
                    *   Tasks requiring specialized tools or knowledge AI doesn't have
                *   **Examples of Human Tasks:**
                    *   "Manual endpoint investigation - collect forensic artifacts from [endpoint]"
                    *   "Coordinate with IT team to isolate [endpoint]"
                    *   "Review and approve containment recommendations"
                    *   "Contact threat intelligence team for additional context on [IOC]"
                    *   "Perform manual log analysis on [system] (AI cannot access)"
                    *   "Coordinate with legal/compliance for data breach notification"
                    *   "Obtain management approval for [action]"
                *   Status: "pending"
                *   Assignee: Specify appropriate team/person (e.g., "SOC3", "IT Team", "Management", "Threat Intel Team")
                *   Priority: Set based on urgency and impact
                *   Description: Clearly describe what needs to be done, why it requires human intervention, and what the expected outcome is
            *   **Task Documentation:**
                *   Document all tasks created (both AI and human tasks)
                *   Ensure tasks reference related IOCs, assets, and evidence
                *   Link tasks to timeline events if applicable
        *   **Task Management:**
            *   Review all tasks to ensure completeness
            *   Update task status as work progresses
            *   Document task completion or blockers
    *   **Documentation:**
        *   Document all IOCs, assets, notes, evidences, and tasks added
        *   Store summary in `${IOCS_ASSETS_ADDED}`

12. **Generate Containment Recommendations:**
    *   Create task: "SOC2 - Containment Recommendations for SOC3" if not exists.
    *   Based on investigation findings, produce detailed recommendations:
        *   Endpoint isolation candidates (with endpoint IDs and justification)
        *   Processes to terminate (with PIDs and hostnames)
        *   Network indicators to block (IPs, domains, URLs)
        *   Forensic collection priorities (which endpoints, what artifacts)
    *   Document recommendations clearly for SOC3 execution.

13. **Final Case Update:**
    *   Update case status and priority based on investigation findings.
    *   Add comprehensive investigation summary using `add_case_comment`:
        *   What happened (threat summary)
        *   How it happened (attack chain)
        *   Who/what was affected (hosts, users, data)
        *   What should SOC3 do next (containment recommendations)
    *   Attach any new observables via `attach_observable_to_case`.
    *   Add any new assets via `add_case_asset`.
    *   If containment is required, ensure case is ready for SOC3 escalation.

14. **End Workflow:**
    *   All tasks should be completed or updated.
    *   Case should have comprehensive documentation.
    *   If escalation to SOC3 is needed, case status should reflect this.
    *   End runbook execution.

## Decision Points

*   **If case is false positive:** Update case status, document findings, close case.
*   **If case requires case-specific analysis:** Execute appropriate case runbook (malware_deep_analysis, suspicious_login_investigation).
*   **If case requires containment:** Ensure containment recommendations are clear and escalate to SOC3.
*   **If case needs more investigation:** Create additional tasks and continue analysis.

## Notes

*   **SOC2's Core Strength:** Advanced Elastic/KQL querying and deep SIEM analysis. SOC1 performs basic searches - SOC2 performs comprehensive, deep analysis using complex queries across extended time windows.
*   **SOC2 Advantages Over SOC1:**
    *   **Deep Elastic Querying:** Complex KQL queries with aggregations, joins, and cross-index searches (vs SOC1's basic searches)
    *   **Extended Time Windows:** Query 7-30 days back (vs SOC1's 24-hour window) to identify patterns and persistence
    *   **Comprehensive Entity Analysis:** Pivot on ALL entities (vs SOC1's 3-5 primary entities)
    *   **Attack Chain Reconstruction:** Build complete attack timelines and map to MITRE ATT&CK (vs SOC1's basic triage)
    *   **Advanced Correlation:** Multi-case correlation with evidence-based approach (vs SOC1's basic case search)
*   Always read ALL case details, comments, tasks, and timeline events before starting new analysis.
*   **Use `search_kql_query` extensively** - this is SOC2's primary tool for deep investigation. Don't rely on basic search functions - use advanced KQL queries.
*   Never make connections without clear evidence - document hypotheses instead.
*   Every major investigation step should have a corresponding task.
*   Document everything comprehensively for SOC3 to take decisive action.
*   **Query Strategy:** Start broad to understand scope, then narrow down with specific filters. Query for attack patterns, MITRE ATT&CK techniques, and persistence mechanisms.

