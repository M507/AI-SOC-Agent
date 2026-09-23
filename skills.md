# SamiGPT Skills

MCP tools exposed by SamiGPT, grouped by solution in the MCP Skill Vector (MSV).

**Default skill vector:** `MSV:1/IRIS:Y/TH:Y/SIEM:Y/EDR:Y/CTI:Y/KB:Y/NB:Y/ENG:Y/RB:Y/AG:Y/RU:Y`

Enable/disable groups with `SOLUTION:Y|N` (e.g. `NB:Y`). Override one tool with `SK:tool_name=N` or `SK:tool_name=Y`.

**Adding a skill?** Follow [`src/mcp/ADDING_A_SKILL.md`](src/mcp/ADDING_A_SKILL.md).

---

## IRIS skills (`IRIS`)

Case management tools when this cluster may talk to IRIS. TheHive uses the same tool names.

**Solution metric:** `IRIS`

| Skill | Label |
|---|---|
| `create_case` | Create Case |
| `review_case` | Review Case |
| `list_cases` | List Cases |
| `search_cases` | Search Cases |
| `add_case_comment` | Add Case Comment |
| `attach_observable_to_case` | Attach Observable To Case |
| `update_case_status` | Update Case Status |
| `assign_case` | Assign Case |
| `get_case_timeline` | Get Case Timeline |
| `add_case_task` | Add Case Task |
| `list_case_tasks` | List Case Tasks |
| `update_case_task_status` | Update Case Task Status |
| `add_case_asset` | Add Case Asset |
| `list_case_assets` | List Case Assets |
| `add_case_evidence` | Add Case Evidence |
| `list_case_evidence` | List Case Evidence |
| `update_case` | Update Case |
| `link_cases` | Link Cases |
| `add_case_timeline_event` | Add Case Timeline Event |
| `list_case_timeline_events` | List Case Timeline Events |

## TheHive skills (`TH`)

Case management tools when this cluster may talk to TheHive. IRIS uses the same tool names.

**Solution metric:** `TH`

| Skill | Label |
|---|---|
| `create_case` | Create Case |
| `review_case` | Review Case |
| `list_cases` | List Cases |
| `search_cases` | Search Cases |
| `add_case_comment` | Add Case Comment |
| `attach_observable_to_case` | Attach Observable To Case |
| `update_case_status` | Update Case Status |
| `assign_case` | Assign Case |
| `get_case_timeline` | Get Case Timeline |
| `add_case_task` | Add Case Task |
| `list_case_tasks` | List Case Tasks |
| `update_case_task_status` | Update Case Task Status |
| `add_case_asset` | Add Case Asset |
| `list_case_assets` | List Case Assets |
| `add_case_evidence` | Add Case Evidence |
| `list_case_evidence` | List Case Evidence |
| `update_case` | Update Case |
| `link_cases` | Link Cases |
| `add_case_timeline_event` | Add Case Timeline Event |
| `list_case_timeline_events` | List Case Timeline Events |

## Elastic / ELK skills (`SIEM`)

Search, alerts, detections, Elastic Defend isolation, and Home Lab rule suggestions against the Elastic cluster bound to this tab.

`get_security_alerts` / `get_rule_detections` support filtering by rule name/id and workflow status (`open`, `acknowledged`/`akn`, `closed`), including historical ack/closed review. `get_security_alert_by_id` also attaches Security Solution / Rule Tuner notes for that alert. Use `get_alert_notes` to batch-read notes across similar past alerts (notes are not on alert `_source`).

Query languages: `search_kql_query` (KQL), `search_lucene_query` (Lucene), `search_eql_query` (EQL), `search_dsl_query` (Query DSL JSON), `search_esql_query` (ES|QL).

**Solution metric:** `SIEM`

| Skill | Label |
|---|---|
| `search_security_events` | Search Security Events |
| `get_file_report` | Get File Report |
| `get_file_behavior_summary` | Get File Behavior Summary |
| `get_entities_related_to_file` | Get Entities Related To File |
| `get_ip_address_report` | Get IP Address Report |
| `search_user_activity` | Search User Activity |
| `pivot_on_indicator` | Pivot On Indicator |
| `search_kql_query` | Run a KQL search |
| `search_lucene_query` | Run a Lucene search |
| `search_eql_query` | Run an EQL search |
| `search_dsl_query` | Run an Elasticsearch DSL search |
| `search_esql_query` | Run an ES|QL search |
| `get_recent_alerts` | Get Recent Alerts |
| `get_network_events` | Get Network Events |
| `get_dns_events` | Get DNS Events |
| `get_alerts_by_entity` | Get Alerts By Entity |
| `get_alerts_by_time_window` | Get Alerts By Time Window |
| `get_all_uncertain_alerts_for_host` | Uncertain alerts for a host |
| `get_email_events` | Get Email Events |
| `get_security_alerts` | Get Security Alerts |
| `get_security_alert_by_id` | Get Security Alert By Id |
| `get_siem_event_by_id` | Get Siem Event By Id |
| `close_alert` | Close Alert |
| `update_alert_verdict` | Update Alert Verdict |
| `tag_alert` | Tag Alert |
| `add_alert_note` | Add Alert Note |
| `get_alert_notes` | Get Alert Notes |
| `create_elastic_case` | Create Elastic Security case |
| `isolate_endpoint` | Isolate endpoint (Elastic Defend) |
| `release_endpoint_isolation` | Release endpoint isolation |
| `lookup_entity` | Lookup Entity |
| `get_ioc_matches` | Get IOC matches |
| `get_threat_intel` | Get Threat Intel |
| `list_security_rules` | List Security Rules |
| `search_security_rules` | Search Security Rules |
| `get_rule_detections` | Get Rule Detections |
| `list_rule_errors` | List Rule Errors |
| `search_lab_detection_rules` | Search Home Lab detection rules |
| `get_lab_detection_rule` | Get a Home Lab detection rule |
| `create_fine_tuning_recommendation` | File a fine-tune suggestion |
| `create_visibility_recommendation` | File a visibility-gap note |

## EDR skills (`EDR`)

Endpoint isolation, process kill, and forensic collection.

**Solution metric:** `EDR`

| Skill | Label |
|---|---|
| `get_endpoint_summary` | Get Endpoint Summary |
| `get_detection_details` | Get Detection Details |
| `isolate_endpoint` | Isolate endpoint (Elastic Defend) |
| `release_endpoint_isolation` | Release endpoint isolation |
| `kill_process_on_endpoint` | Kill Process On Endpoint |
| `collect_forensic_artifacts` | Collect Forensic Artifacts |

## Threat intel skills (`CTI`)

Hash lookups against configured CTI platforms.

**Solution metric:** `CTI`

| Skill | Label |
|---|---|
| `lookup_hash_ti` | Look up hash in threat intel |

## Knowledge base skills (`KB`)

Client infrastructure notes used during investigations.

**Solution metric:** `KB`

| Skill | Label |
|---|---|
| `kb_list_clients` | List knowledge-base clients |
| `kb_get_client_infra` | Get client infrastructure |

## NetBox skills (`NB`)

DCIM/IPAM lookups against NetBox for host, IP, and prefix enrichment.

**Solution metric:** `NB`

| Skill | Label |
|---|---|
| `netbox_lookup_ip` | Look up IP in NetBox |
| `netbox_lookup_host` | Look up host in NetBox |
| `netbox_lookup_prefix` | Look up prefix in NetBox |
| `netbox_search` | Search NetBox assets |

## Engineering skills (`ENG`)

GitHub Issues (or Trello / ClickUp) recommendation boards.

**Solution metric:** `ENG`

Configured provider: **GitHub Issues** on `M507/HomeLab-DaC`  
Labels: `fine-tuning`, `visibility`

| Skill | Label |
|---|---|
| `list_fine_tuning_recommendations` | List Fine Tuning Recommendations |
| `list_visibility_recommendations` | List Visibility Recommendations |
| `add_comment_to_fine_tuning_recommendation` | Add Comment To Fine Tuning Recommendation |
| `add_comment_to_visibility_recommendation` | Add Comment To Visibility Recommendation |

`create_fine_tuning_recommendation` / `create_visibility_recommendation` file a Requests note and also open a GitHub Issue when ENG is GitHub.

## Runbook skills (`RB`)

Saved investigation runbooks and post-triage requests for missing case playbooks.

**Solution metric:** `RB`

| Skill | Label |
|---|---|
| `list_runbooks` | List Runbooks |
| `get_runbook` | Get Runbook |
| `execute_runbook` | Execute Runbook |
| `create_runbook_recommendation` | File a runbook-gap note |
| `save_case_runbook` | Save a case runbook file |

`create_runbook_recommendation` is **informational** (Requests view). File it only **after** the investigation finishes if no `soc*/cases` playbook matched the alert type.

`save_case_runbook` writes a finished markdown playbook under `run_books/<soc>/cases/`. Analysts start this from the Requests **Create runbook** button (Open WebUI session with the gap note + last alert).

## Agent profile skills (`AG`)

SOC-tier agent personas and routing.

**Solution metric:** `AG`

| Skill | Label |
|---|---|
| `list_agent_profiles` | List Agent Profiles |
| `get_agent_profile` | Get Agent Profile |
| `route_case_to_agent` | Route Case To Agent |
| `execute_as_agent` | Execute As Agent |

## Rules engine skills (`RU`)

Chained investigation workflows.

**Solution metric:** `RU`

| Skill | Label |
|---|---|
| `list_rules` | List Rules |
| `execute_rule` | Execute Rule |

## Core (always available)

Not gated by a solution metric in the skill vector.

| Skill | Label |
|---|---|
| `create_approval_request` | File an analyst approval request (Requests view) |

---

**Unique MSV skills:** 87  
**Listed above (IRIS+TH share case tools):** 109 rows  
**Including core:** 87

