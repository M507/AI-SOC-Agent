# SamiGPT MCP Tools Documentation

This document provides comprehensive documentation for all tools available in the SamiGPT MCP server. These tools enable AI assistants and automation systems to interact with case management systems, SIEM platforms, and EDR solutions for security incident response and investigation.

## Naming Conventions

**Important:** Tool names follow strict naming conventions for clarity and consistency:

- **Case Management Tools**: All case management-related tools **must** contain the word `case` in their name (e.g., `review_case`, `list_cases`, `add_case_comment`).
- **Alert Tools**: All alert-related tools **must** be in the SIEM category and contain the word `alert` in their name (e.g., `get_security_alerts`, `get_security_alert_by_id`).

This ensures clear distinction between case management operations and SIEM alert operations.

## Table of Contents

- [Case Management Tools](#case-management-tools)
- [SIEM Tools](#siem-tools)
- [CTI Tools](#cti-tools)
- [EDR Tools](#edr-tools)
- [Engineering Tools](#engineering-tools)
- [Rules Engine Tools](#rules-engine-tools)

---

## Case Management Tools

Case management tools allow you to create, review, update, and manage security incidents and cases in your case management system (TheHive, IRIS, etc.).

**Naming Convention:** All case management tools contain the word `case` in their name (e.g., `review_case`, `list_cases`, `add_case_comment`).

### `create_case`

Create a new case for investigation. Follows the case standard format defined in standards/case_standard.md. Use this when triaging an alert and no case exists yet.

**Parameters:**
- `title` (string, required): Case title following format: `[Alert Type] - [Primary Entity] - [Date/Time]`. Example: `'Malware Detection - 10.10.1.2 - 2025-11-18'`
- `description` (string, required): Comprehensive case description including alert details, initial assessment, key entities, and severity justification
- `priority` (string, optional): Case priority based on severity, impact, and IOC matches. Valid values: `low`, `medium`, `high`, `critical`. Default: `medium`
- `status` (string, optional): Case status. Valid values: `open`, `in_progress`, `closed`. New cases should start as `open`. Default: `open`
- `tags` (array, optional): Tags for categorization (e.g., `['malware', 'suspicious-login', 'ioc-match', 'soc1-triage']`)
- `alert_id` (string, optional): Associated alert ID if case is created from an alert

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case_id` (string): The ID of the created case
- `case` (object): Created case details including:
  - `id` (string): Case identifier
  - `title` (string): Case title
  - `description` (string): Case description
  - `status` (string): Current status
  - `priority` (string): Priority level
  - `tags` (array): Case tags
  - `created_at` (string): ISO timestamp of creation
  - `updated_at` (string): ISO timestamp of last update

**Usage Example:**
```json
{
  "name": "create_case",
  "arguments": {
    "title": "Malware Detection - 10.10.1.2 - 2025-11-18",
    "description": "Alert triggered for suspicious file execution on endpoint 10.10.1.2. File hash matches known malware indicators. Endpoint isolated pending investigation.",
    "priority": "high",
    "status": "open",
    "tags": ["malware", "endpoint", "soc1-triage"],
    "alert_id": "alert-12345"
  }
}
```

**Use Cases:**
- Create a new case when triaging an alert that requires investigation
- Escalate alerts to case management for tracking
- Document security incidents for investigation workflow
- Link cases to source alerts for traceability

---

### `review_case`

Retrieve and review the full details of a case including title, description, status, priority, observables, and comments.

**Parameters:**
- `case_id` (string, required): The ID of the case to review

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case` (object): Complete case details including:
  - `id` (string): Case identifier
  - `title` (string): Case title
  - `description` (string): Case description
  - `status` (string): Current status (open, in_progress, closed)
  - `priority` (string): Priority level (low, medium, high, critical)
  - `assignee` (string): Assigned analyst
  - `tags` (array): Case tags
  - `observables` (array): List of observables attached to the case
  - `created_at` (string): ISO timestamp of creation
  - `updated_at` (string): ISO timestamp of last update
- `timeline` (array): Chronological list of comments and events

**Usage Example:**
```json
{
  "name": "review_case",
  "arguments": {
    "case_id": "CASE-2024-001"
  }
}
```

**Use Cases:**
- Get complete context about a security incident
- Review case history and timeline
- Check attached observables and IOCs
- Understand case status and assignment

---

### `list_cases`

List cases from the case management system, optionally filtered by status.

**Parameters:**
- `status` (string, optional): Filter by status. Valid values: `open`, `in_progress`, `closed`
- `limit` (integer, optional): Maximum number of cases to return (default: 50)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `count` (integer): Number of cases returned
- `cases` (array): List of case summaries, each containing:
  - `id` (string): Case identifier
  - `title` (string): Case title
  - `status` (string): Current status
  - `priority` (string): Priority level
  - `assignee` (string): Assigned analyst
  - `created_at` (string): ISO timestamp of creation

**Usage Example:**
```json
{
  "name": "list_cases",
  "arguments": {
    "status": "open",
    "limit": 20
  }
}
```

**Use Cases:**
- Get overview of all open incidents
- Monitor case workload
- Find cases needing attention
- Generate case reports

---

### `search_cases`

Search for cases using text search, status, priority, tags, or assignee filters.

**Parameters:**
- `text` (string, optional): Text to search for in case title/description
- `status` (string, optional): Filter by status (`open`, `in_progress`, `closed`)
- `priority` (string, optional): Filter by priority (`low`, `medium`, `high`, `critical`)
- `tags` (array, optional): Array of tags to filter by
- `assignee` (string, optional): Filter by assignee username
- `limit` (integer, optional): Maximum results (default: 50)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `count` (integer): Number of matching cases
- `cases` (array): List of matching case summaries

**Usage Example:**
```json
{
  "name": "search_cases",
  "arguments": {
    "text": "malware",
    "priority": "high",
    "status": "open",
    "limit": 10
  }
}
```

**Use Cases:**
- Find cases related to specific threats
- Search by keywords or tags
- Filter cases by analyst
- Identify high-priority incidents

---

### `add_case_comment`

Add a comment or note to a case.

**Parameters:**
- `case_id` (string, required): The ID of the case
- `content` (string, required): The comment content
- `author` (string, optional): The author of the comment

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `comment` (object): Comment details including:
  - `id` (string): Comment identifier
  - `case_id` (string): Associated case ID
  - `author` (string): Comment author
  - `content` (string): Comment text
  - `created_at` (string): ISO timestamp of creation

**Usage Example:**
```json
{
  "name": "add_case_comment",
  "arguments": {
    "case_id": "CASE-2024-001",
    "content": "Investigation completed. No threats detected after analysis.",
    "author": "analyst@example.com"
  }
}
```

**Use Cases:**
- Document investigation findings
- Add analysis notes
- Record remediation steps
- Update case status with context

---

### `attach_observable_to_case`

Attach an observable such as an IP address, file hash, domain, or URL to a case for tracking and analysis.

**Parameters:**
- `case_id` (string, required): The ID of the case
- `observable_type` (string, required): Type of observable. Common types:
  - `ip`: IP address
  - `hash`: File hash (MD5, SHA256, etc.)
  - `domain`: Domain name
  - `url`: URL
  - `email`: Email address
  - `filename`: Filename
  - `registry`: Registry key
  - `user-agent`: User agent string
- `observable_value` (string, required): The value of the observable
- `description` (string, optional): Description of the observable
- `tags` (array, optional): Tags for the observable

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `observable` (object): Observable details including:
  - `type` (string): Observable type
  - `value` (string): Observable value
  - `description` (string): Description
  - `tags` (array): Tags

**Usage Example:**
```json
{
  "name": "attach_observable_to_case",
  "arguments": {
    "case_id": "CASE-2024-001",
    "observable_type": "ip",
    "observable_value": "192.168.1.100",
    "description": "Suspicious IP address from firewall logs",
    "tags": ["malicious", "external"]
  }
}
```

**Use Cases:**
- Track IOCs (Indicators of Compromise)
- Document suspicious entities
- Link related observables to cases
- Enable automated enrichment

---

### `update_case_status`

Update the status of a case.

**Parameters:**
- `case_id` (string, required): The ID of the case
- `status` (string, required): New status. Valid values:
  - `open`: Case is newly opened
  - `in_progress`: Case is being actively worked on
  - `closed`: Case is resolved and closed

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case` (object): Updated case details including:
  - `id` (string): Case identifier
  - `title` (string): Case title
  - `status` (string): New status

**Usage Example:**
```json
{
  "name": "update_case_status",
  "arguments": {
    "case_id": "CASE-2024-001",
    "status": "closed"
  }
}
```

**Use Cases:**
- Mark cases as resolved
- Update case workflow status
- Close completed investigations
- Track case lifecycle

---

### `assign_case`

Assign a case to a specific user or analyst.

**Parameters:**
- `case_id` (string, required): The ID of the case
- `assignee` (string, required): The username or ID of the assignee

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `assignment` (object): Assignment details including:
  - `case_id` (string): Case identifier
  - `assignee` (string): Assigned analyst
  - `assigned_at` (string): ISO timestamp of assignment

**Usage Example:**
```json
{
  "name": "assign_case",
  "arguments": {
    "case_id": "CASE-2024-001",
    "assignee": "analyst@example.com"
  }
}
```

**Use Cases:**
- Distribute workload among analysts
- Assign cases based on expertise
- Escalate to senior analysts
- Reassign cases

---

### `get_case_timeline`

Retrieve the timeline of comments and events for a case, ordered chronologically.

**Parameters:**
- `case_id` (string, required): The ID of the case

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case_id` (string): Case identifier
- `count` (integer): Number of timeline events
- `timeline` (array): Chronological list of events, each containing:
  - `author` (string): Event author
  - `content` (string): Event content
  - `created_at` (string): ISO timestamp

**Usage Example:**
```json
{
  "name": "get_case_timeline",
  "arguments": {
    "case_id": "CASE-2024-001"
  }
}
```

**Use Cases:**
- Review case history
- Understand investigation progression
- Audit case activities
- Generate case reports

---

### `update_case`

Update a case with new information (title, description, priority, status, tags, assignee).

**Parameters:**
- `case_id` (string, required): The ID of the case to update
- `title` (string, optional): New case title
- `description` (string, optional): New case description
- `priority` (string, optional): New priority (low, medium, high, critical)
- `status` (string, optional): New status (open, in_progress, closed)
- `tags` (array, optional): New tags list
- `assignee` (string, optional): New assignee

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case` (object): Updated case details

**Usage Example:**
```json
{
  "name": "update_case",
  "arguments": {
    "case_id": "CASE-2024-001",
    "priority": "high",
    "status": "in_progress",
    "tags": ["malware", "investigation"]
  }
}
```

**Use Cases:**
- Update case priority based on investigation findings
- Change case status as investigation progresses
- Add or modify case tags
- Update case description with new findings
- Reassign cases to different analysts

---

### `link_cases`

Link two cases together to indicate a relationship (e.g., duplicate, related, escalated from).

**Parameters:**
- `source_case_id` (string, required): The ID of the source case
- `target_case_id` (string, required): The ID of the target case to link to
- `link_type` (string, optional): Type of link. Valid values:
  - `related_to`: Cases are related
  - `duplicate_of`: Source case is a duplicate of target
  - `escalated_from`: Source case was escalated from target
  - `child_of`: Source case is a child of target
  - `blocked_by`: Source case is blocked by target
  Default: `related_to`

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `source_case_id` (string): Source case identifier
- `target_case_id` (string): Target case identifier
- `link_type` (string): Type of link created
- `message` (string): Success message

**Usage Example:**
```json
{
  "name": "link_cases",
  "arguments": {
    "source_case_id": "CASE-2024-001",
    "target_case_id": "CASE-2024-002",
    "link_type": "related_to"
  }
}
```

**Use Cases:**
- Link related security incidents
- Mark duplicate cases
- Track case escalation relationships
- Build case hierarchies
- Document case dependencies

---

### `add_case_timeline_event`

Add an event to a case timeline for tracking investigation activities and milestones.

**Parameters:**
- `case_id` (string, required): The ID of the case
- `title` (string, required): Event title
- `content` (string, required): Event content/description
- `source` (string, optional): Event source (e.g., "SamiGPT", "SIEM", "EDR")
- `category_id` (integer, optional): Event category ID
- `tags` (array, optional): Event tags
- `color` (string, optional): Event color (hex format, e.g., "#1572E899")
- `event_date` (string, optional): Event date in ISO format (defaults to current time)
- `include_in_summary` (boolean, optional): Include event in case summary (default: true)
- `include_in_graph` (boolean, optional): Include event in case graph (default: true)
- `sync_iocs_assets` (boolean, optional): Sync with IOCs and assets (default: true)
- `asset_ids` (array, optional): Related asset IDs
- `ioc_ids` (array, optional): Related IOC IDs
- `custom_attributes` (object, optional): Custom attributes
- `raw` (string, optional): Raw event data
- `tz` (string, optional): Timezone (default: "+00:00")

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case_id` (string): Case identifier
- `event` (object): Created event details
- `message` (string): Success message

**Usage Example:**
```json
{
  "name": "add_case_timeline_event",
  "arguments": {
    "case_id": "CASE-2024-001",
    "title": "Endpoint Isolated",
    "content": "Endpoint 10.10.1.2 was isolated from the network due to malware detection",
    "source": "SamiGPT",
    "tags": ["containment", "response"]
  }
}
```

**Use Cases:**
- Track investigation milestones
- Document response actions
- Record containment activities
- Log forensic collection events
- Build chronological investigation timeline

---

### `list_case_timeline_events`

List all timeline events associated with a case.

**Parameters:**
- `case_id` (string, required): The ID of the case

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case_id` (string): Case identifier
- `count` (integer): Number of timeline events
- `events` (array): List of timeline events, each containing:
  - Event details (title, content, source, timestamp, etc.)

**Usage Example:**
```json
{
  "name": "list_case_timeline_events",
  "arguments": {
    "case_id": "CASE-2024-001"
  }
}
```

**Use Cases:**
- Review case investigation history
- Audit case activities
- Generate case timeline reports
- Understand investigation progression
- Track response actions

---

### `add_case_task`

Add a task to a case. Tasks represent actionable items for investigation and response, typically assigned to SOC2 or SOC3 tiers.

**Parameters:**
- `case_id` (string, required): The ID of the case
- `title` (string, required): Task title
- `description` (string, required): Task description
- `assignee` (string, optional): Assignee ID or SOC tier (e.g., "SOC2", "SOC3")
- `priority` (string, optional): Task priority (low, medium, high, critical). Default: medium
- `status` (string, optional): Task status (pending, in_progress, completed, blocked). Default: pending

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case_id` (string): Case identifier
- `task` (object): Created task details
- `message` (string): Success message

**Usage Example:**
```json
{
  "name": "add_case_task",
  "arguments": {
    "case_id": "CASE-2024-001",
    "title": "Collect forensic artifacts from endpoint",
    "description": "Collect process list, network connections, and file system artifacts from endpoint 10.10.1.2",
    "assignee": "SOC3",
    "priority": "high",
    "status": "pending"
  }
}
```

**Use Cases:**
- Create investigation tasks
- Assign work to SOC tiers
- Track investigation progress
- Manage response workflows
- Document actionable items

---

### `list_case_tasks`

List all tasks associated with a case.

**Parameters:**
- `case_id` (string, required): The ID of the case

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case_id` (string): Case identifier
- `count` (integer): Number of tasks
- `tasks` (array): List of tasks

**Usage Example:**
```json
{
  "name": "list_case_tasks",
  "arguments": {
    "case_id": "CASE-2024-001"
  }
}
```

**Use Cases:**
- Review case task list
- Check task status
- Monitor investigation progress
- Track assigned work
- Generate task reports

---

### `update_case_task_status`

Update the status of a task associated with a case. Use this to mark tasks as in-progress when starting work and completed when finishing.

**Parameters:**
- `case_id` (string, required): The ID of the case
- `task_id` (string, required): The ID of the task to update
- `status` (string, required): New task status. Valid values:
  - `pending`: Task is pending and not yet started
  - `in_progress`: Task is currently being worked on
  - `completed`: Task has been finished
  - `blocked`: Task is blocked and cannot proceed

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case_id` (string): Case identifier
- `task_id` (string): Task identifier
- `task` (object): Updated task details
- `message` (string): Success message

**Usage Example:**
```json
{
  "name": "update_case_task_status",
  "arguments": {
    "case_id": "CASE-2024-001",
    "task_id": "task-123",
    "status": "completed"
  }
}
```

**Use Cases:**
- Mark tasks as in-progress when starting work
- Update task status to completed when finished
- Mark tasks as blocked when dependencies prevent progress
- Track task workflow and progress
- Update task status during investigation

---

### `add_case_asset`

Add an asset (endpoint, server, network, user account, application) to a case.

**Parameters:**
- `case_id` (string, required): The ID of the case
- `asset_name` (string, required): Asset name/identifier
- `asset_type` (string, required): Asset type. Valid values:
  - `endpoint`: Endpoint device
  - `server`: Server
  - `network`: Network segment
  - `user_account`: User account
  - `application`: Application
- `description` (string, optional): Asset description
- `ip_address` (string, optional): IP address if applicable
- `hostname` (string, optional): Hostname if applicable
- `tags` (array, optional): Tags for the asset

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case_id` (string): Case identifier
- `asset` (object): Created asset details
- `message` (string): Success message

**Usage Example:**
```json
{
  "name": "add_case_asset",
  "arguments": {
    "case_id": "CASE-2024-001",
    "asset_name": "workstation-01",
    "asset_type": "endpoint",
    "ip_address": "10.10.1.2",
    "hostname": "workstation-01.example.com",
    "tags": ["compromised", "isolated"]
  }
}
```

**Use Cases:**
- Track affected assets
- Document compromised systems
- Link assets to investigations
- Manage asset inventory
- Support asset-based analysis

---

### `list_case_assets`

List all assets associated with a case.

**Parameters:**
- `case_id` (string, required): The ID of the case

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case_id` (string): Case identifier
- `count` (integer): Number of assets
- `assets` (array): List of assets

**Usage Example:**
```json
{
  "name": "list_case_assets",
  "arguments": {
    "case_id": "CASE-2024-001"
  }
}
```

**Use Cases:**
- Review case assets
- Check affected systems
- Generate asset reports
- Track asset status
- Support asset management

---

### `add_case_evidence`

Upload and attach evidence (file, log, screenshot, network capture, etc.) to a case.

**Parameters:**
- `case_id` (string, required): The ID of the case
- `file_path` (string, required): Path to the evidence file
- `description` (string, optional): Description of the evidence
- `evidence_type` (string, optional): Type of evidence. Common types:
  - `file`: General file
  - `screenshot`: Screenshot image
  - `log`: Log file
  - `network_capture`: Network packet capture
  - `memory_dump`: Memory dump file
  - `registry`: Registry export
  - `other`: Other evidence type

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case_id` (string): Case identifier
- `evidence` (object): Created evidence details
- `message` (string): Success message

**Usage Example:**
```json
{
  "name": "add_case_evidence",
  "arguments": {
    "case_id": "CASE-2024-001",
    "file_path": "/path/to/forensic_artifacts.zip",
    "description": "Forensic artifacts collected from endpoint 10.10.1.2",
    "evidence_type": "file"
  }
}
```

**Use Cases:**
- Attach forensic evidence
- Upload investigation files
- Store log files
- Preserve network captures
- Document investigation artifacts

---

### `list_case_evidence`

List all evidence files associated with a case.

**Parameters:**
- `case_id` (string, required): The ID of the case

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `case_id` (string): Case identifier
- `count` (integer): Number of evidence files
- `evidence` (array): List of evidence files

**Usage Example:**
```json
{
  "name": "list_case_evidence",
  "arguments": {
    "case_id": "CASE-2024-001"
  }
}
```

**Use Cases:**
- Review case evidence
- Check attached files
- Generate evidence reports
- Audit evidence collection
- Support forensic analysis

---

## SIEM Tools

SIEM tools enable searching and analyzing security events, logs, and indicators across your security information and event management platform. These tools are essential for Security Operations Center (SOC) and Incident Response (IR) investigations.

**Naming Convention:** All alert-related tools in the SIEM category contain the word `alert` in their name (e.g., `get_security_alerts`, `get_security_alert_by_id`). This distinguishes SIEM alerts from case management cases.

### Implementation Status

The following checklist shows which SIEM tools are currently implemented:

**Core Search & Analysis Tools:**
- [x] `search_security_events`
- [x] `get_file_report`
- [x] `get_file_behavior_summary`
- [x] `get_entities_related_to_file`
- [x] `get_ip_address_report`
- [x] `search_user_activity`
- [x] `pivot_on_indicator`
- [x] `search_kql_query`

**Alert Management Tools:**
- [x] `get_security_alerts`
- [x] `get_security_alert_by_id`
- [x] `get_recent_alerts`
- [x] `close_alert`
- [x] `update_alert_verdict`
- [x] `tag_alert`
- [x] `add_alert_note`

**Event Management Tools:**
- [x] `get_siem_event_by_id`

**Entity & Intelligence Tools:**
- [x] `lookup_entity`
- [x] `get_ioc_matches`
- [x] `get_threat_intel`

**Detection Rule Management:**
- [x] `list_security_rules`
- [x] `search_security_rules`
- [x] `get_rule_detections`
- [x] `list_rule_errors`

### Essential Investigation Tools

The following tools are critical for effective security investigations, ordered by importance:

1. **Event Search & Query** - Search and filter security events across all data sources
2. **Time Range Analysis** - Analyze events within specific time windows
3. **Correlation & Pivoting** - Connect related events and indicators
4. **Alert Management** - View, triage, and manage security alerts
5. **Threat Intelligence Lookup** - Enrich events with threat intelligence
6. **User Behavior Analytics** - Analyze user activity patterns
7. **Network Traffic Analysis** - Examine network connections and flows
8. **File Analysis** - Investigate files, hashes, and executables
9. **Endpoint Activity** - Review endpoint logs and activities
10. **Authentication Analysis** - Analyze login and authentication events
11. **DNS Analysis** - Investigate DNS queries and resolutions
12. **Process Analysis** - Examine process execution and relationships
13. **Registry Analysis** - Review Windows registry modifications
14. **Email Analysis** - Investigate email-related security events
15. **Web Proxy Analysis** - Analyze web browsing and proxy logs
16. **Firewall Analysis** - Review firewall rules and blocked connections
17. **Vulnerability Correlation** - Match events with known vulnerabilities
18. **Compliance Reporting** - Generate compliance and audit reports
19. **Baseline Comparison** - Compare current activity to baselines

### `search_security_events`

Search security events and logs across all environments using a query string.

**Parameters:**
- `query` (string, required): Search query in vendor-specific query language (e.g., KQL for Elastic, SPL for Splunk)
- `limit` (integer, optional): Maximum number of events to return (default: 100)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `query` (string): The query that was executed
- `total_count` (integer): Total number of matching events
- `returned_count` (integer): Number of events returned
- `events` (array): List of security events, each containing:
  - `id` (string): Event identifier
  - `timestamp` (string): ISO timestamp of the event
  - `source_type` (string): Event source type
  - `message` (string): Event message/log entry
  - `host` (string): Hostname where event occurred
  - `username` (string): Username associated with event
  - `ip` (string): IP address
  - `process_name` (string): Process name
  - `file_hash` (string): File hash if applicable

**Usage Example:**
```json
{
  "name": "search_security_events",
  "arguments": {
    "query": "source_ip:192.168.1.100 AND event_type:malware",
    "limit": 50
  }
}
```

**Use Cases:**
- Investigate security incidents
- Search for specific attack patterns
- Correlate events across systems
- Hunt for threats

---

### `get_file_report`

Retrieve an aggregated report about a file identified by its hash.

**Parameters:**
- `file_hash` (string, required): The file hash (MD5, SHA256, etc.)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `file_hash` (string): The file hash
- `first_seen` (string): ISO timestamp when file was first seen
- `last_seen` (string): ISO timestamp when file was last seen
- `detection_count` (integer): Number of detections
- `affected_hosts` (array): List of hostnames where file was seen

**Usage Example:**
```json
{
  "name": "get_file_report",
  "arguments": {
    "file_hash": "a1b2c3d4e5f6789012345678901234567890abcd"
  }
}
```

**Use Cases:**
- Analyze suspicious files
- Track file prevalence
- Identify affected systems
- Determine file reputation

---

### `get_file_behavior_summary`

Retrieve a high-level behavior summary for a file, including process trees, network activity, and persistence mechanisms.

**Parameters:**
- `file_hash` (string, required): The file hash

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `file_hash` (string): The file hash
- `process_trees` (array): Process execution trees
- `network_activity` (array): Network connections made
- `persistence_mechanisms` (array): Persistence techniques used
- `notes` (string): Additional analysis notes

**Usage Example:**
```json
{
  "name": "get_file_behavior_summary",
  "arguments": {
    "file_hash": "a1b2c3d4e5f6789012345678901234567890abcd"
  }
}
```

**Use Cases:**
- Understand malware behavior
- Analyze file execution patterns
- Identify persistence mechanisms
- Document attack techniques

---

### `get_entities_related_to_file`

Retrieve entities related to a file hash, such as hosts where it was seen, users who executed it, related processes, and alerts.

**Parameters:**
- `file_hash` (string, required): The file hash

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `indicator` (string): The file hash
- `hosts` (array): List of hostnames
- `users` (array): List of usernames
- `processes` (array): List of related processes
- `alerts` (array): List of related security alerts

**Usage Example:**
```json
{
  "name": "get_entities_related_to_file",
  "arguments": {
    "file_hash": "a1b2c3d4e5f6789012345678901234567890abcd"
  }
}
```

**Use Cases:**
- Identify all systems affected by a file
- Find users who executed suspicious files
- Correlate files with alerts
- Map attack scope

---

### `get_ip_address_report`

Retrieve an aggregated report about an IP address, including reputation, geolocation, and related alerts.

**Parameters:**
- `ip` (string, required): The IP address

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `ip` (string): The IP address
- `reputation` (string): Reputation score/status
- `geo` (object): Geolocation information
- `related_alerts` (array): List of related security alerts

**Usage Example:**
```json
{
  "name": "get_ip_address_report",
  "arguments": {
    "ip": "192.168.1.100"
  }
}
```

**Use Cases:**
- Check IP reputation
- Investigate suspicious IPs
- Correlate IPs with alerts
- Geographic threat intelligence

---

### `search_user_activity`

Search for security events related to a specific user, including authentication events, file access, and other activities.

**Parameters:**
- `username` (string, required): The username to search for
- `limit` (integer, optional): Maximum number of events to return (default: 100)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `username` (string): The username searched
- `total_count` (integer): Total number of matching events
- `returned_count` (integer): Number of events returned
- `events` (array): List of user-related security events

**Usage Example:**
```json
{
  "name": "search_user_activity",
  "arguments": {
    "username": "jdoe",
    "limit": 50
  }
}
```

**Use Cases:**
- Investigate user behavior
- Audit user activities
- Detect account compromise
- Track user actions

---

### `pivot_on_indicator`

Given an IOC (file hash, IP address, domain, etc.), search for all related security events across environments for further investigation.

**Parameters:**
- `indicator` (string, required): The IOC (hash, IP, domain, etc.)
- `limit` (integer, optional): Maximum number of events to return (default: 200)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `indicator` (string): The IOC searched
- `query` (string): The query that was executed
- `total_count` (integer): Total number of matching events
- `returned_count` (integer): Number of events returned
- `events` (array): List of related security events

**Usage Example:**
```json
{
  "name": "pivot_on_indicator",
  "arguments": {
    "indicator": "192.168.1.100",
    "limit": 100
  }
}
```

**Use Cases:**
- Expand investigation scope
- Find all occurrences of an IOC
- Correlate indicators across systems
- Threat hunting

---

### `search_kql_query`

Execute a KQL (Kusto Query Language) or advanced query for deeper investigations. This tool enables complex queries including advanced filtering, aggregations, time-based analysis, cross-index searches, and complex joins. Supports both KQL syntax and vendor-specific query DSL (e.g., Elasticsearch Query DSL).

**Note:** This tool is designed for SOC 2 and SOC 3 analysts who need to perform deeper investigations with complex queries. For simpler searches, use `search_security_events` instead.

**Parameters:**
- `kql_query` (string, required): KQL query string or advanced query DSL (JSON for Elasticsearch)
- `limit` (integer, optional): Maximum number of events to return (default: 500)
- `hours_back` (integer, optional): Optional time window in hours to limit the search

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `query` (string): The query that was executed
- `total_count` (integer): Total number of matching events
- `returned_count` (integer): Number of events returned
- `events` (array): List of security events, each containing:
  - `id` (string): Event identifier
  - `timestamp` (string): ISO timestamp of the event
  - `source_type` (string): Event source type
  - `message` (string): Event message/log entry
  - `host` (string): Hostname where event occurred
  - `username` (string): Username associated with event
  - `ip` (string): IP address
  - `process_name` (string): Process name
  - `file_hash` (string): File hash if applicable

**Usage Example 1: KQL-like Query**
```json
{
  "name": "search_kql_query",
  "arguments": {
    "kql_query": "host == \"server01\" and process contains \"powershell\" | where timestamp > ago(24h)",
    "limit": 500,
    "hours_back": 24
  }
}
```

**Usage Example 2: Elasticsearch Query DSL**
```json
{
  "name": "search_kql_query",
  "arguments": {
    "kql_query": "{\"query\": {\"bool\": {\"must\": [{\"match\": {\"process.name\": \"powershell\"}}, {\"range\": {\"@timestamp\": {\"gte\": \"now-24h\"}}}]}}, \"size\": 500}",
    "limit": 500
  }
}
```

**Use Cases:**
- Perform complex multi-field searches
- Execute advanced aggregations and statistical analysis
- Cross-index correlation searches
- Time-based pattern analysis
- Deep threat hunting investigations
- Complex join operations across data sources
- Advanced filtering with multiple conditions
- Custom investigation queries beyond standard search capabilities

**Supported Query Formats:**
- **KQL-like syntax**: Basic KQL patterns (field == value, field != value, field contains "value", time ranges with ago())
- **Elasticsearch Query DSL**: Full JSON query DSL for Elasticsearch
- **Vendor-specific**: Other SIEM query languages as supported by the backend

**Best Practices:**
- Use `hours_back` parameter to limit time range for better performance
- Start with smaller `limit` values for initial queries
- For Elasticsearch, use Query DSL for maximum flexibility
- Combine with other tools like `pivot_on_indicator` for comprehensive investigations

---

### `get_security_alerts`

Get security alerts directly from the SIEM platform. This tool retrieves active alerts that require investigation and triage.

**Note:** This tool operates on SIEM alerts (not cases). For case management operations, use the case management tools (e.g., `list_cases`, `review_case`).

**Parameters:**
- `hours_back` (integer, optional): How many hours to look back for alerts (default: 24)
- `max_alerts` (integer, optional): Maximum number of alerts to return (default: 10)
- `status_filter` (string, optional): Query string to filter alerts by status (default: excludes closed alerts)
- `severity` (string, optional): Filter by severity level (low, medium, high, critical)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `count` (integer): Number of alerts returned
- `alerts` (array): List of security alerts, each containing:
  - `id` (string): Alert identifier
  - `title` (string): Alert title/name
  - `severity` (string): Severity level
  - `status` (string): Alert status (open, in_progress, closed, etc.)
  - `created_at` (string): ISO timestamp of alert creation
  - `description` (string): Alert description
  - `source` (string): Source system that generated the alert
  - `related_entities` (array): Related IPs, domains, hashes, etc.

**Usage Example:**
```json
{
  "name": "get_security_alerts",
  "arguments": {
    "hours_back": 48,
    "max_alerts": 20,
    "severity": "high"
  }
}
```

**Use Cases:**
- Monitor active security alerts
- Triage incoming threats
- Prioritize investigation work
- Review alert backlog
- Generate alert summaries

---

### `get_security_alert_by_id`

Get detailed information about a specific security alert by its ID.

**Note:** This tool operates on SIEM alerts (not cases). For case management operations, use `review_case` instead.

**Parameters:**
- `alert_id` (string, required): The ID of the alert to retrieve
- `include_detections` (boolean, optional): Whether to include detection details (default: true)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `alert` (object): Complete alert details including:
  - `id` (string): Alert identifier
  - `title` (string): Alert title
  - `severity` (string): Severity level
  - `status` (string): Current status
  - `priority` (string): Priority level
  - `verdict` (string): Analyst verdict (if assigned)
  - `description` (string): Detailed description
  - `created_at` (string): ISO timestamp of creation
  - `updated_at` (string): ISO timestamp of last update
  - `detections` (array): List of detections that triggered the alert (if included)
  - `related_entities` (array): Related indicators and entities
  - `comments` (array): Analyst comments and notes

**Usage Example:**
```json
{
  "name": "get_security_alert_by_id",
  "arguments": {
    "alert_id": "alert-12345",
    "include_detections": true
  }
}
```

**Use Cases:**
- Get complete alert context
- Review alert details for investigation
- Check alert status and assignment
- Review detection details
- Understand alert root cause

---

### `get_siem_event_by_id`

Retrieve a specific security event by its unique identifier (event ID). This tool allows you to get the exact event details when you know the event ID.

**Note:** This tool operates on SIEM events (not alerts or cases). Events are individual log entries or security events. For alerts, use `get_security_alert_by_id`. For case management, use `review_case`.

**Parameters:**
- `event_id` (string, required): The unique identifier of the event to retrieve

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `event` (object): Complete event details including:
  - `id` (string): Event identifier
  - `timestamp` (string): ISO timestamp of the event
  - `source_type` (string): Event source type (endpoint, network, auth, cloud, other)
  - `message` (string): Event message/log entry
  - `host` (string): Hostname where event occurred
  - `username` (string): Username associated with event
  - `ip` (string): IP address
  - `process_name` (string): Process name
  - `file_hash` (string): File hash if applicable
  - `raw` (object): Raw event data from the SIEM

**Usage Example:**
```json
{
  "name": "get_siem_event_by_id",
  "arguments": {
    "event_id": "abc123def456"
  }
}
```

**Use Cases:**
- Retrieve exact event details by ID
- Get full context of a specific security event
- Access raw event data for deep analysis
- Verify event details during investigation
- Cross-reference events with known IDs

---

### `lookup_entity`

Look up an entity (IP address, domain, hash, user, etc.) in the SIEM for enrichment and context. This provides comprehensive information about an indicator.

**Parameters:**
- `entity_value` (string, required): Value to look up (e.g., IP address, domain name, file hash, username)
- `entity_type` (string, optional): Type of entity (ip, domain, hash, user, etc.). If not provided, will be auto-detected
- `hours_back` (integer, optional): How many hours of historical data to consider (default: 24)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `entity_value` (string): The entity that was looked up
- `entity_type` (string): Detected or specified entity type
- `summary` (string): Formatted summary of entity information
- `first_seen` (string): ISO timestamp when entity was first seen
- `last_seen` (string): ISO timestamp when entity was last seen
- `event_count` (integer): Number of events associated with entity
- `reputation` (string): Reputation score or status
- `related_alerts` (array): List of related security alerts
- `related_entities` (array): Other entities related to this one

**Usage Example:**
```json
{
  "name": "lookup_entity",
  "arguments": {
    "entity_value": "192.168.1.100",
    "entity_type": "ip",
    "hours_back": 72
  }
}
```

**Use Cases:**
- Enrich indicators with context
- Check entity reputation
- Find related events and alerts
- Investigate suspicious entities
- Build entity profiles
- Threat intelligence lookup

---

### `list_security_rules`

List all security detection rules configured in the SIEM platform. These are the rules that generate alerts and detections.

**Parameters:**
- `enabled_only` (boolean, optional): Only return enabled rules (default: false)
- `limit` (integer, optional): Maximum number of rules to return (default: 100)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `count` (integer): Number of rules returned
- `rules` (array): List of detection rules, each containing:
  - `id` (string): Rule identifier
  - `name` (string): Rule name
  - `description` (string): Rule description
  - `enabled` (boolean): Whether rule is enabled
  - `severity` (string): Default severity level
  - `category` (string): Rule category
  - `created_at` (string): ISO timestamp of creation
  - `updated_at` (string): ISO timestamp of last update

**Usage Example:**
```json
{
  "name": "list_security_rules",
  "arguments": {
    "enabled_only": true,
    "limit": 50
  }
}
```

**Use Cases:**
- Review detection rule inventory
- Check rule status
- Audit detection coverage
- Identify rule categories
- Plan rule improvements

---

### `search_security_rules`

Search for security detection rules by name, description, or other criteria.

**Parameters:**
- `query` (string, required): Search query (supports regex patterns)
- `category` (string, optional): Filter by rule category
- `enabled_only` (boolean, optional): Only search enabled rules (default: false)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `count` (integer): Number of matching rules
- `rules` (array): List of matching detection rules

**Usage Example:**
```json
{
  "name": "search_security_rules",
  "arguments": {
    "query": "malware.*ransomware",
    "category": "malware"
  }
}
```

**Use Cases:**
- Find specific detection rules
- Search rules by keywords
- Filter rules by category
- Review rule coverage for specific threats
- Identify duplicate or similar rules

---

### `get_rule_detections`

Retrieve historical detections generated by a specific security detection rule. This helps understand rule effectiveness and review past alerts.

**Parameters:**
- `rule_id` (string, required): Unique ID of the rule to list detections for
- `alert_state` (string, optional): Filter by alert state (open, closed, etc.)
- `hours_back` (integer, optional): How many hours back to look (default: 24)
- `limit` (integer, optional): Maximum number of detections to return (default: 50)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `rule_id` (string): The rule ID queried
- `count` (integer): Number of detections returned
- `detections` (array): List of detections, each containing:
  - `id` (string): Detection identifier
  - `alert_id` (string): Associated alert ID
  - `timestamp` (string): ISO timestamp of detection
  - `severity` (string): Severity level
  - `status` (string): Detection status
  - `description` (string): Detection description

**Usage Example:**
```json
{
  "name": "get_rule_detections",
  "arguments": {
    "rule_id": "rule-abc123",
    "hours_back": 168,
    "limit": 100
  }
}
```

**Use Cases:**
- Review rule performance
- Analyze detection history
- Tune rule thresholds
- Identify false positives
- Measure rule effectiveness
- Audit rule behavior

---

### `list_rule_errors`

List execution errors for a specific security detection rule. This helps identify and troubleshoot rule issues.

**Parameters:**
- `rule_id` (string, required): Unique ID of the rule to list errors for
- `hours_back` (integer, optional): How many hours back to look for errors (default: 24)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `rule_id` (string): The rule ID queried
- `error_count` (integer): Number of errors found
- `errors` (array): List of rule execution errors, each containing:
  - `timestamp` (string): ISO timestamp when error occurred
  - `error_type` (string): Type of error
  - `error_message` (string): Detailed error message
  - `severity` (string): Error severity

**Usage Example:**
```json
{
  "name": "list_rule_errors",
  "arguments": {
    "rule_id": "rule-abc123",
    "hours_back": 48
  }
}
```

**Use Cases:**
- Troubleshoot rule failures
- Identify rule configuration issues
- Monitor rule health
- Fix broken rules
- Ensure detection coverage

---

### `get_ioc_matches`

Get Indicators of Compromise (IoC) matches from the SIEM. This identifies when known malicious indicators appear in your environment.

**Parameters:**
- `hours_back` (integer, optional): How many hours back to look for IoC matches (default: 24)
- `max_matches` (integer, optional): Maximum number of matches to return (default: 20)
- `ioc_type` (string, optional): Filter by IoC type (ip, domain, hash, url, etc.)
- `severity` (string, optional): Filter by severity level

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `count` (integer): Number of IoC matches found
- `matches` (array): List of IoC matches, each containing:
  - `indicator` (string): The IoC value
  - `ioc_type` (string): Type of indicator
  - `first_seen` (string): ISO timestamp when first seen
  - `last_seen` (string): ISO timestamp when last seen
  - `match_count` (integer): Number of times matched
  - `severity` (string): Severity level
  - `source` (string): Threat intelligence source
  - `affected_hosts` (array): Hosts where IoC was seen

**Usage Example:**
```json
{
  "name": "get_ioc_matches",
  "arguments": {
    "hours_back": 48,
    "max_matches": 50,
    "ioc_type": "ip"
  }
}
```

**Use Cases:**
- Monitor IoC matches in environment
- Identify active threats
- Track known malicious indicators
- Correlate with threat intelligence
- Prioritize incident response
- Measure threat exposure

---

### `get_threat_intel`

Get answers to security questions using integrated threat intelligence and AI models. This provides contextual threat information and analysis.

**Parameters:**
- `query` (string, required): The security or threat intelligence question to ask
- `context` (object, optional): Additional context (indicators, events, etc.) to provide for better answers

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `query` (string): The question that was asked
- `answer` (string): Formatted answer with threat intelligence information
- `sources` (array): List of sources used for the answer
- `confidence` (string): Confidence level of the answer

**Usage Example:**
```json
{
  "name": "get_threat_intel",
  "arguments": {
    "query": "What is the threat profile of IP address 192.168.1.100?",
    "context": {
      "ip": "192.168.1.100"
    }
  }
}
```

**Use Cases:**
- Get threat intelligence context
- Understand threat actor TTPs
- Research malware families
- Get security recommendations
- Enrich investigation findings
- Answer security questions

---

### Additional SIEM Investigation Capabilities

While the core tools above provide essential functionality, here are additional SIEM capabilities that enhance investigations:

#### Time-Based Analysis
- **Time Range Queries**: Filter events by specific time windows (last hour, day, week, custom ranges)
- **Timeline Visualization**: View events chronologically to understand attack progression
- **Time Correlation**: Identify events that occurred within specific time windows of each other
- **Historical Comparison**: Compare current activity to historical baselines

#### Advanced Search & Filtering
- **Field-Specific Queries**: Search within specific log fields (source IP, destination IP, user, process, etc.)
- **Boolean Logic**: Combine multiple conditions with AND, OR, NOT operators
- **Regex Support**: Use regular expressions for pattern matching
- **Wildcard Queries**: Search with wildcards for partial matches
- **Nested Queries**: Create complex nested query structures

#### Alert & Detection Management
- **Alert Triage**: Review and prioritize security alerts
- **False Positive Management**: Mark and suppress false positives
- **Alert Correlation**: Group related alerts into incidents
- **Alert Enrichment**: Add context and threat intelligence to alerts
- **Alert Escalation**: Escalate critical alerts to appropriate teams

#### Threat Intelligence Integration
- **IOC Lookup**: Check indicators against threat intelligence feeds
- **Threat Actor Attribution**: Identify known threat actor TTPs
- **Malware Family Identification**: Classify malware based on behavior
- **Reputation Scoring**: Get reputation scores for IPs, domains, hashes
- **Threat Feed Correlation**: Match events against threat intelligence feeds

#### User & Entity Behavior Analytics (UEBA)
- **User Activity Timeline**: View complete user activity history
- **Anomalous User Behavior**: Detect unusual user activity patterns
- **Account Compromise Detection**: Identify potentially compromised accounts
- **Privilege Escalation Detection**: Detect unauthorized privilege changes
- **Lateral Movement Tracking**: Track user movement across systems

#### Network Analysis
- **Network Flow Analysis**: Analyze network traffic flows and connections
- **Port Analysis**: Identify unusual port usage and connections
- **Protocol Analysis**: Examine specific network protocols
- **Geographic Analysis**: Map network connections by geography
- **Bandwidth Analysis**: Identify unusual bandwidth consumption
- **Connection Duration**: Analyze connection lifetimes and patterns

#### File & Hash Analysis
- **Hash Reputation**: Check file hashes against reputation databases
- **File Prevalence**: Determine how widespread a file is
- **File Execution Chain**: Track file execution relationships
- **File Modification Tracking**: Monitor file system changes
- **Malware Detection**: Identify known malware signatures
- **File Metadata Analysis**: Extract and analyze file metadata

#### Endpoint Analysis
- **Endpoint Inventory**: List and manage endpoints
- **Endpoint Health Status**: Check endpoint security status
- **Process Execution**: Track process execution across endpoints
- **Registry Monitoring**: Monitor Windows registry changes
- **Memory Analysis**: Analyze memory dumps and processes
- **System Log Analysis**: Review system-level logs

#### Authentication & Access Analysis
- **Failed Login Analysis**: Identify brute force and credential stuffing
- **Multi-Factor Authentication Events**: Track MFA usage and failures
- **Account Lockout Analysis**: Review account lockout events
- **Privileged Access Monitoring**: Monitor administrative access
- **Session Analysis**: Analyze user session patterns
- **Access Pattern Anomalies**: Detect unusual access patterns

#### DNS & Domain Analysis
- **DNS Query Analysis**: Review DNS queries and resolutions
- **Domain Reputation**: Check domain reputation and categorization
- **DNS Tunneling Detection**: Identify potential DNS tunneling
- **Domain Generation Algorithm (DGA) Detection**: Detect DGA domains
- **Subdomain Enumeration**: Track subdomain access patterns
- **DNS Response Analysis**: Analyze DNS response patterns

#### Email Security Analysis
- **Email Header Analysis**: Examine email headers for anomalies
- **Attachment Analysis**: Analyze email attachments and hashes
- **Phishing Detection**: Identify phishing attempts
- **Email Flow Analysis**: Track email delivery paths
- **SPF/DKIM/DMARC Analysis**: Review email authentication records
- **Email Threat Correlation**: Correlate emails with other security events

#### Web & Proxy Analysis
- **URL Analysis**: Examine accessed URLs and domains
- **Web Category Analysis**: Review web browsing categories
- **Proxy Log Analysis**: Analyze proxy server logs
- **User-Agent Analysis**: Identify suspicious user agents
- **Download Tracking**: Monitor file downloads
- **Web Application Firewall (WAF) Events**: Review WAF blocks and alerts

#### Compliance & Reporting
- **Compliance Dashboards**: Generate compliance status reports
- **Audit Trail Generation**: Create detailed audit trails
- **Regulatory Reporting**: Generate reports for compliance requirements (PCI-DSS, HIPAA, GDPR, etc.)
- **Security Metrics**: Calculate security metrics and KPIs
- **Trend Analysis**: Identify security trends over time
- **Executive Reporting**: Create high-level executive summaries

#### Advanced Correlation
- **Multi-Event Correlation**: Correlate events across multiple sources
- **Attack Chain Reconstruction**: Reconstruct complete attack chains
- **Kill Chain Analysis**: Map events to MITRE ATT&CK framework
- **TTP Mapping**: Identify Tactics, Techniques, and Procedures
- **Campaign Detection**: Identify related attacks as campaigns
- **Cross-System Correlation**: Correlate events across different security tools

#### Investigation Workflow Support
- **Investigation Playbooks**: Execute predefined investigation workflows
- **Case Linking**: Link SIEM events to case management systems
- **Evidence Collection**: Collect and preserve investigation evidence
- **Investigation Notes**: Document investigation findings
- **Collaboration Tools**: Share findings with team members
- **Investigation Timeline**: Build chronological investigation timelines

#### Performance & Optimization
- **Query Performance**: Optimize search queries for performance
- **Index Management**: Manage log indices and retention
- **Data Archival**: Archive old logs for compliance
- **Search Optimization**: Use efficient search patterns
- **Result Caching**: Cache frequently accessed results
- **Batch Operations**: Perform bulk operations efficiently

---

## CTI Tools

CTI (Cyber Threat Intelligence) tools enable lookup of indicators in threat intelligence platforms to enrich security investigations with threat context.

### Supported CTI Platforms

The CTI integration supports multiple threat intelligence platforms:

- **Local TIP** (`local_tip`): A local threat intelligence platform for hash lookups
- **OpenCTI** (`opencti`): Open Cyber Threat Intelligence Platform with comprehensive threat intelligence data

The same tools work with both platforms - the platform is selected via configuration in `config.json`.

### CTI Capabilities

The following capabilities are available through the CTI integration:

1. **Hash Lookup** (`lookup_hash_ti`) - Look up file hashes (MD5, SHA1, SHA256, SHA512) in threat intelligence platforms to get threat context, reputation, and analysis results
   - Supports multiple hash algorithms (MD5, SHA1, SHA256, SHA512)
   - Works with both Local TIP and OpenCTI platforms
   - Returns threat intelligence data including:
     - Hash classification and metadata
     - Threat scores and reputation
     - Analysis results from multiple sources
     - Related indicators and context
     - Historical threat intelligence data

### `lookup_hash_ti`

Look up a file hash in the threat intelligence platform to get threat intelligence information. This tool works with both Local TIP and OpenCTI platforms - **it uses ONE platform at a time** based on your `config.json` configuration. The response format varies based on which platform is configured.

**How It Works:**
1. At startup, the MCP server reads `config.json` and initializes the CTI client based on `cti.cti_type`
2. If `cti_type` is `"local_tip"`, it initializes a Local TIP client
3. If `cti_type` is `"opencti"`, it initializes an OpenCTI client
4. When `lookup_hash_ti` is called, it uses the configured client to query the appropriate platform
5. Results are returned in a format specific to that platform

**Parameters:**
- `hash_value` (string, required): The hash value to look up (MD5, SHA1, SHA256, SHA512)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `hash_value` (string): The hash that was looked up
- `threat_intelligence` (object): Threat intelligence information about the hash (format depends on platform)

**Response Format - Local TIP:**
When using Local TIP, the `threat_intelligence` object contains:
- `value` (string): The hash value
- `type` (string): Hash algorithm type (MD5, SHA1, SHA256, SHA512)
- `threat_score` (integer): Threat score (0-100)
- `classification` (string): Threat classification (e.g., "malicious", "suspicious", "benign")

**Example Response - Local TIP:**
```json
{
  "success": true,
  "hash_value": "a1b2c3d4e5f6789012345678901234567890abcd",
  "threat_intelligence": {
    "value": "a1b2c3d4e5f6789012345678901234567890abcd",
    "type": "sha256",
    "threat_score": 85,
    "classification": "malicious"
  }
}
```

**Response Format - OpenCTI:**
When using OpenCTI, the `threat_intelligence` object contains:
- `value` (string): The hash value
- `algorithm` (string): Hash algorithm (MD5, SHA1, SHA256, SHA512)
- `id` (string): OpenCTI hash identifier
- `found` (boolean): Whether the hash was found in OpenCTI
- `indicators` (array): List of related threat indicators, each containing:
  - `id` (string): Indicator identifier
  - `pattern` (string): STIX pattern
  - `pattern_type` (string): Pattern type
  - `valid_from` (string): ISO timestamp when indicator becomes valid
  - `valid_until` (string): ISO timestamp when indicator expires (null if permanent)
  - `score` (integer): Threat score (x_opencti_score)
  - `detection` (boolean): Whether detection is enabled
  - `created_at` (string): ISO timestamp of creation
  - `updated_at` (string): ISO timestamp of last update
  - `labels` (array): List of threat labels
  - `kill_chain_phases` (array): MITRE ATT&CK kill chain phases, each containing:
    - `kill_chain_name` (string): Kill chain name (e.g., "mitre-attack")
    - `phase_name` (string): Phase name (e.g., "initial-access", "execution")

**Example Response - OpenCTI (Hash Found):**
```json
{
  "success": true,
  "hash_value": "a1b2c3d4e5f6789012345678901234567890abcd",
  "threat_intelligence": {
    "value": "a1b2c3d4e5f6789012345678901234567890abcd",
    "algorithm": "SHA256",
    "id": "hash-uuid-12345",
    "found": true,
    "indicators": [
      {
        "id": "indicator-uuid-67890",
        "pattern": "[file:hashes.'SHA-256' = 'a1b2c3d4e5f6789012345678901234567890abcd']",
        "pattern_type": "stix",
        "valid_from": "2024-01-01T00:00:00Z",
        "valid_until": null,
        "score": 85,
        "detection": true,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-15T10:30:00Z",
        "labels": ["malware", "trojan"],
        "kill_chain_phases": [
          {
            "kill_chain_name": "mitre-attack",
            "phase_name": "execution"
          },
          {
            "kill_chain_name": "mitre-attack",
            "phase_name": "persistence"
          }
        ]
      }
    ]
  }
}
```

**Example Response - OpenCTI (Hash Not Found):**
```json
{
  "success": true,
  "hash_value": "nonexistent-hash-value",
  "threat_intelligence": {
    "value": "nonexistent-hash-value",
    "found": false,
    "indicators": []
  }
}
```

**Usage Example:**
```json
{
  "name": "lookup_hash_ti",
  "arguments": {
    "hash_value": "a1b2c3d4e5f6789012345678901234567890abcd"
  }
}
```

**Use Cases:**
- Check file hash reputation
- Enrich file analysis with threat intelligence
- Identify known malicious files
- Correlate hashes with threat intelligence feeds
- Support incident investigation with threat context
- Map indicators to MITRE ATT&CK framework (OpenCTI)
- Access comprehensive threat intelligence data (OpenCTI)

**Platform Selection:**
The CTI platform is configured in `config.json`:
- For Local TIP: Set `cti_type` to `"local_tip"` and provide `base_url`
- For OpenCTI: Set `cti_type` to `"opencti"`, provide `base_url` and `api_key`

**Note:** This is the same tool for both platforms - no conflicts exist. The tool automatically uses the configured CTI platform backend.

---

## EDR Tools

EDR (Endpoint Detection and Response) tools enable interaction with endpoint security platforms to investigate and respond to threats on endpoints.

### `get_endpoint_summary`

Retrieve summary information about an endpoint including hostname, platform, last seen time, primary user, and isolation status.

**Parameters:**
- `endpoint_id` (string, required): The endpoint ID

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `endpoint` (object): Endpoint details including:
  - `id` (string): Endpoint identifier
  - `hostname` (string): Hostname
  - `platform` (string): Operating system platform
  - `last_seen` (string): ISO timestamp of last seen
  - `primary_user` (string): Primary user account
  - `is_isolated` (boolean): Whether endpoint is isolated

**Usage Example:**
```json
{
  "name": "get_endpoint_summary",
  "arguments": {
    "endpoint_id": "endpoint-12345"
  }
}
```

**Use Cases:**
- Get endpoint overview
- Check isolation status
- Verify endpoint details
- Monitor endpoint health

---

### `get_detection_details`

Retrieve detailed information about a specific detection including type, severity, description, associated file hash, and process.

**Parameters:**
- `detection_id` (string, required): The detection ID

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `detection` (object): Detection details including:
  - `id` (string): Detection identifier
  - `endpoint_id` (string): Associated endpoint
  - `created_at` (string): ISO timestamp of detection
  - `detection_type` (string): Type of detection
  - `severity` (string): Severity level
  - `description` (string): Detection description
  - `file_hash` (string): Associated file hash
  - `process` (object): Process details (if available)

**Usage Example:**
```json
{
  "name": "get_detection_details",
  "arguments": {
    "detection_id": "detection-67890"
  }
}
```

**Use Cases:**
- Analyze detection details
- Understand threat context
- Review detection metadata
- Investigate alerts

---

### `isolate_endpoint`

Isolate an endpoint from the network to prevent further compromise or lateral movement. **This is a critical response action.**

**Parameters:**
- `endpoint_id` (string, required): The endpoint ID to isolate

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `action` (object): Action details including:
  - `endpoint_id` (string): Endpoint identifier
  - `result` (string): Action result status
  - `requested_at` (string): ISO timestamp of request
  - `completed_at` (string): ISO timestamp of completion (if completed)
  - `message` (string): Status message

**Usage Example:**
```json
{
  "name": "isolate_endpoint",
  "arguments": {
    "endpoint_id": "endpoint-12345"
  }
}
```

**Use Cases:**
- Contain active threats
- Prevent lateral movement
- Isolate compromised systems
- Emergency response

**⚠️ Warning:** This is a disruptive action that will disconnect the endpoint from the network. Use with caution.

---

### `release_endpoint_isolation`

Release an endpoint from network isolation, restoring normal network connectivity.

**Parameters:**
- `endpoint_id` (string, required): The endpoint ID to release

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `action` (object): Action details including:
  - `endpoint_id` (string): Endpoint identifier
  - `result` (string): Action result status
  - `requested_at` (string): ISO timestamp of request
  - `completed_at` (string): ISO timestamp of completion (if completed)
  - `message` (string): Status message

**Usage Example:**
```json
{
  "name": "release_endpoint_isolation",
  "arguments": {
    "endpoint_id": "endpoint-12345"
  }
}
```

**Use Cases:**
- Restore endpoint connectivity
- Release after remediation
- Return endpoint to normal operations
- Post-incident recovery

---

### `kill_process_on_endpoint`

Terminate a specific process running on an endpoint by its process ID. **Use with caution as this is a disruptive action.**

**Parameters:**
- `endpoint_id` (string, required): The endpoint ID
- `pid` (integer, required): The process ID to kill

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `action` (object): Action details including:
  - `endpoint_id` (string): Endpoint identifier
  - `pid` (integer): Process ID
  - `result` (string): Action result status
  - `requested_at` (string): ISO timestamp of request
  - `completed_at` (string): ISO timestamp of completion (if completed)
  - `message` (string): Status message

**Usage Example:**
```json
{
  "name": "kill_process_on_endpoint",
  "arguments": {
    "endpoint_id": "endpoint-12345",
    "pid": 1234
  }
}
```

**Use Cases:**
- Stop malicious processes
- Terminate suspicious activity
- Kill malware processes
- Emergency response

**⚠️ Warning:** This will terminate the specified process immediately. Use with caution.

---

### `collect_forensic_artifacts`

Initiate collection of forensic artifacts from an endpoint, such as process lists, network connections, file system artifacts, etc.

**Parameters:**
- `endpoint_id` (string, required): The endpoint ID
- `artifact_types` (array, required): List of artifact types to collect. Common types:
  - `processes`: Running processes
  - `network`: Network connections
  - `filesystem`: File system artifacts
  - `registry`: Registry keys
  - `memory`: Memory dumps
  - `logs`: System logs

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `request` (object): Collection request details including:
  - `endpoint_id` (string): Endpoint identifier
  - `artifact_types` (array): Types requested
  - `result` (string): Request result status
  - `requested_at` (string): ISO timestamp of request
  - `completed_at` (string): ISO timestamp of completion (if completed)
  - `message` (string): Status message

**Usage Example:**
```json
{
  "name": "collect_forensic_artifacts",
  "arguments": {
    "endpoint_id": "endpoint-12345",
    "artifact_types": ["processes", "network", "filesystem"]
  }
}
```

**Use Cases:**
- Collect forensic evidence
- Gather investigation data
- Document endpoint state
- Support incident response

---

## Engineering Tools

Engineering tools enable creating and managing recommendations for fine-tuning detection rules and improving security visibility. These tools integrate with engineering platforms (ClickUp, Trello, GitHub) to track improvement tasks.

**Note:** Currently, only ClickUp is fully supported. Trello and GitHub support for listing and commenting is planned for future releases.

### `create_fine_tuning_recommendation`

Create a fine-tuning recommendation task on the fine-tuning board. This is used to track improvements needed to reduce false positives or enhance detection rules.

**Parameters:**
- `title` (string, required): Task/card title
- `description` (string, required): Task/card description
- `list_name` (string, optional): Optional list name (Trello only, defaults to first list on board)
- `labels` (array, optional): Optional list of label names (Trello only)
- `status` (string, optional): Optional status name (ClickUp only, defaults to first status in list)
- `tags` (array, optional): Optional list of tag names (ClickUp only)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `provider` (string): Platform provider (clickup, trello, github)
- `task`/`card`/`project_item` (object): Created task/card details including:
  - `id` (string): Task/card identifier
  - `name` (string): Task/card name
  - `url` (string): URL to view the task/card

**Usage Example:**
```json
{
  "name": "create_fine_tuning_recommendation",
  "arguments": {
    "title": "Reduce false positives for Elastic Agent alerts",
    "description": "Alert triggers frequently for Elastic Agent connections to Elastic Cloud. Consider adding whitelist or adjusting rule threshold.",
    "tags": ["false-positive", "elastic-agent"]
  }
}
```

**Use Cases:**
- Document detection rule improvements needed after false positive identification
- Track fine-tuning tasks for rule optimization
- Create tasks for reducing false positive rates
- Link fine-tuning needs to specific alert types

---

### `create_visibility_recommendation`

Create a visibility/engineering recommendation task on the engineering board. This is used to track improvements needed to enhance security visibility or detection capabilities.

**Parameters:**
- `title` (string, required): Task/card title
- `description` (string, required): Task/card description
- `list_name` (string, optional): Optional list name (Trello only, defaults to first list on board)
- `labels` (array, optional): Optional list of label names (Trello only)
- `status` (string, optional): Optional status name (ClickUp only, defaults to first status in list)
- `tags` (array, optional): Optional list of tag names (ClickUp only)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `provider` (string): Platform provider (clickup, trello, github)
- `task`/`card`/`project_item` (object): Created task/card details including:
  - `id` (string): Task/card identifier
  - `name` (string): Task/card name
  - `url` (string): URL to view the task/card

**Usage Example:**
```json
{
  "name": "create_visibility_recommendation",
  "arguments": {
    "title": "Add endpoint logging for PowerShell execution",
    "description": "PowerShell execution events are not being captured. Need to enable PowerShell logging on endpoints to improve detection capabilities.",
    "tags": ["visibility", "powershell"]
  }
}
```

**Use Cases:**
- Document visibility gaps identified during investigations
- Track engineering tasks for improving detection coverage
- Request logging enhancements
- Link visibility improvements to specific investigation needs

---

### `list_fine_tuning_recommendations`

List all fine-tuning recommendation tasks from the fine-tuning board. This allows checking if an existing task already exists before creating a new one.

**Note:** Currently only supports ClickUp. Trello and GitHub support will be added in future releases.

**Parameters:**
- `archived` (boolean, optional): Include archived tasks (default: false)
- `include_closed` (boolean, optional): Include closed tasks (default: true)
- `order_by` (string, optional): Order tasks by field (e.g., "created", "updated", "priority")
- `reverse` (boolean, optional): Reverse the order (default: false)
- `subtasks` (boolean, optional): Include subtasks (default: false)
- `statuses` (array, optional): Filter by status names
- `include_markdown_description` (boolean, optional): Include markdown in descriptions (default: false)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `provider` (string): Platform provider (clickup)
- `count` (integer): Number of tasks found
- `tasks` (array): List of tasks, each containing:
  - `id` (string): Task identifier
  - `name` (string): Task name
  - `url` (string): URL to view the task
  - `status` (string): Task status
  - `description` (string): Task description

**Usage Example:**
```json
{
  "name": "list_fine_tuning_recommendations",
  "arguments": {
    "include_closed": false,
    "order_by": "created"
  }
}
```

**Use Cases:**
- Check if a fine-tuning task already exists before creating a duplicate
- Review existing fine-tuning recommendations
- Find related tasks for a specific alert type
- Track fine-tuning task status

---

### `list_visibility_recommendations`

List all visibility/engineering recommendation tasks from the engineering board. This allows checking if an existing task already exists before creating a new one.

**Note:** Currently only supports ClickUp. Trello and GitHub support will be added in future releases.

**Parameters:**
- `archived` (boolean, optional): Include archived tasks (default: false)
- `include_closed` (boolean, optional): Include closed tasks (default: true)
- `order_by` (string, optional): Order tasks by field (e.g., "created", "updated", "priority")
- `reverse` (boolean, optional): Reverse the order (default: false)
- `subtasks` (boolean, optional): Include subtasks (default: false)
- `statuses` (array, optional): Filter by status names
- `include_markdown_description` (boolean, optional): Include markdown in descriptions (default: false)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `provider` (string): Platform provider (clickup)
- `count` (integer): Number of tasks found
- `tasks` (array): List of tasks, each containing:
  - `id` (string): Task identifier
  - `name` (string): Task name
  - `url` (string): URL to view the task
  - `status` (string): Task status
  - `description` (string): Task description

**Usage Example:**
```json
{
  "name": "list_visibility_recommendations",
  "arguments": {
    "include_closed": false,
    "order_by": "created"
  }
}
```

**Use Cases:**
- Check if a visibility task already exists before creating a duplicate
- Review existing visibility recommendations
- Find related tasks for a specific visibility gap
- Track visibility improvement task status

---

### `add_comment_to_fine_tuning_recommendation`

Add a comment to an existing fine-tuning recommendation task. This is used to add additional context, link to related alerts/cases, or update the status when closing false positives.

**Note:** Currently only supports ClickUp. Trello and GitHub support will be added in future releases.

**Parameters:**
- `task_id` (string, required): ClickUp task ID
- `comment_text` (string, required): Comment text/content

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `provider` (string): Platform provider (clickup)
- `comment` (object): Comment details including:
  - `id` (string): Comment identifier
  - `comment_text` (string): Comment text
  - `user` (string): Username who added the comment
- `task_id` (string): Task ID the comment was added to
- `message` (string): Success message

**Usage Example:**
```json
{
  "name": "add_comment_to_fine_tuning_recommendation",
  "arguments": {
    "task_id": "86evk2bcn",
    "comment_text": "Another false positive observed for this alert type. Alert ID: alert-12345, Case ID: CASE-2024-001. Total false positives for this pattern: 5 this week."
  }
}
```

**Use Cases:**
- Add context to existing fine-tuning tasks when closing additional false positives
- Link related alerts or cases to fine-tuning recommendations
- Update task status with investigation findings
- Document pattern observations

---

### `add_comment_to_visibility_recommendation`

Add a comment to an existing visibility/engineering recommendation task. This is used to add additional context, link to related investigations, or provide updates.

**Note:** Currently only supports ClickUp. Trello and GitHub support will be added in future releases.

**Parameters:**
- `task_id` (string, required): ClickUp task ID
- `comment_text` (string, required): Comment text/content

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `provider` (string): Platform provider (clickup)
- `comment` (object): Comment details including:
  - `id` (string): Comment identifier
  - `comment_text` (string): Comment text
  - `user` (string): Username who added the comment
- `task_id` (string): Task ID the comment was added to
- `message` (string): Success message

**Usage Example:**
```json
{
  "name": "add_comment_to_visibility_recommendation",
  "arguments": {
    "task_id": "86evk2bcv",
    "comment_text": "Investigation revealed this visibility gap during Case CASE-2024-001. Additional context: PowerShell execution was observed but not logged on endpoint 10.10.1.2."
  }
}
```

**Use Cases:**
- Add context to existing visibility tasks when gaps are discovered during investigations
- Link related cases or investigations to visibility recommendations
- Update task status with new findings
- Document impact of visibility gaps

---

## Rules Engine Tools

Rules engine tools enable execution of automated investigation workflows that chain together multiple skills.

### `list_rules`

List all available investigation rules/workflows.

**Parameters:**
None

**Returns:**
- `rules` (array): List of available rules, each containing:
  - `name` (string): Rule name
  - `description` (string): Rule description
  - `enabled` (boolean): Whether rule is enabled
  - `action_count` (integer): Number of actions in the rule

**Usage Example:**
```json
{
  "name": "list_rules",
  "arguments": {}
}
```

**Use Cases:**
- Discover available workflows
- Check rule status
- Plan automated investigations
- Review rule configurations

---

### `execute_rule`

Execute an investigation rule/workflow that chains together multiple skills.

**Parameters:**
- `rule_name` (string, required): Name of the rule to execute
- `context` (object, optional): Context variables to pass to the rule. Common variables:
  - `case_id`: Case identifier
  - `alert_id`: Alert identifier
  - `endpoint_id`: Endpoint identifier
  - `indicator`: IOC value
  - `search_query`: SIEM search query

**Returns:**
- `success` (boolean): Whether the rule executed successfully
- `rule_name` (string): Name of the executed rule
- `results` (array): List of action results, each containing:
  - `action` (string): Action name
  - `success` (boolean): Whether action succeeded
  - `result` (object): Action result data
  - `error` (string): Error message (if failed)
- `context` (object): Final context variables

**Usage Example:**
```json
{
  "name": "execute_rule",
  "arguments": {
    "rule_name": "automated_threat_investigation",
    "context": {
      "case_id": "CASE-2024-001",
      "indicator": "192.168.1.100"
    }
  }
}
```

**Use Cases:**
- Automate investigation workflows
- Chain multiple investigation steps
- Execute predefined playbooks
- Standardize response procedures

---

## Best Practices

### Tool Selection
- Use case management tools for incident tracking and management
- Use SIEM tools for log analysis and event correlation
- Use EDR tools for endpoint investigation and response
- Use rules engine for automated workflows

### Error Handling
- Always check the `success` field in responses
- Handle missing or invalid parameters gracefully
- Log errors for troubleshooting
- Provide meaningful error messages

### Performance
- Use appropriate `limit` parameters to avoid large result sets
- Combine tools efficiently to minimize API calls
- Cache results when appropriate
- Use rules engine for complex multi-step operations

### Security
- Validate all input parameters
- Sanitize user-provided data
- Use least privilege principles
- Log all critical actions (isolation, process termination, etc.)

### Workflow Examples

**Example 1: Investigate a Suspicious IP**
1. Use `pivot_on_indicator` to find all events related to the IP
2. Use `get_ip_address_report` to get reputation and context
3. Use `search_security_events` to find related events
4. Create or update a case with `attach_observable_to_case`
5. Document findings with `add_case_comment`

**Example 2: Respond to Endpoint Detection**
1. Use `get_detection_details` to understand the threat
2. Use `get_endpoint_summary` to check endpoint status
3. Use `isolate_endpoint` if threat is active
4. Use `collect_forensic_artifacts` to gather evidence
5. Use `get_file_report` to analyze associated files
6. Create case and document with case management tools

**Example 3: Automated Investigation Workflow**
1. Use `list_rules` to find appropriate workflow
2. Use `execute_rule` with context variables
3. Review results from automated actions
4. Follow up with manual investigation if needed

---

## Tool Availability

Tools are only available if the corresponding integration is configured:

- **Case Management Tools**: Available when TheHive or IRIS is configured
- **SIEM Tools**: Available when Elastic or other SIEM is configured
- **CTI Tools**: Available when CTI platform is configured (supports Local TIP or OpenCTI)
  - `lookup_hash_ti`: Available when any CTI platform (local_tip or opencti) is configured
- **EDR Tools**: Available when EDR platform is configured
- **Engineering Tools**: Available when engineering platform is configured (supports ClickUp, Trello, or GitHub)
  - Currently, `list_fine_tuning_recommendations`, `list_visibility_recommendations`, `add_comment_to_fine_tuning_recommendation`, and `add_comment_to_visibility_recommendation` only support ClickUp
- **Rules Engine Tools**: Always available

---

### `get_recent_alerts`

Summarize and smart-group recent SIEM alerts from the last N hours to help the AI decide what to investigate first.

**CRITICAL:** This tool automatically excludes alerts that have already been investigated (alerts with `verdict` field). It limits results to `max_alerts` uninvestigated alerts and always respects the specified timeframe. If no uninvestigated alerts are found, it returns an empty result with a message indicating there are no alerts to investigate.

**Parameters:**
- `hours_back` (integer, optional): How many hours to look back for alerts (default: `1`; typically used as "last 1 hour"). **The timeframe is always respected and never bypassed.**
- `max_alerts` (integer, optional): Maximum number of **uninvestigated** alerts to retrieve and process (default: `100`). The tool limits results to this number after filtering out investigated alerts.
- `status_filter` (string, optional): Filter by alert status (implementation-specific string that is passed through to the SIEM backend)
- `severity` (string, optional): Filter by severity (`low`, `medium`, `high`, `critical`)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `hours_back` (integer): Effective lookback window used
- `max_alerts` (integer): Effective max alerts used
- `status_filter` (string or null): Status filter used
- `severity` (string or null): Severity filter used
- `total_alerts` (integer): Number of alerts retrieved from the SIEM (may include investigated alerts)
- `uninvestigated_alerts` (integer): Number of uninvestigated alerts after filtering (limited to `max_alerts`)
- `group_count` (integer): Number of alert groups produced
- `message` (string, optional): Message indicating no uninvestigated alerts found (only present when `uninvestigated_alerts` is 0)
- `groups` (array): List of grouped alerts, **sorted from most recent to oldest** (by severity descending, count descending, then by latest_created_at descending). Each group contains:
  - `group_id` (string): Stable identifier for the group (e.g., `alert_group_1`)
  - `title` (string): Representative alert title for the group
  - `primary_severity` (string): Highest severity observed in the group
  - `primary_status` (string): Representative status for the group
  - `rule_id` (string or null): Detection/rule identifier when available
  - `alert_type` (string or null): Alert type / category when available
  - `count` (integer): Number of alerts in this group
  - `alert_ids` (array): List of alert IDs in this group
  - `statuses` (array): Unique statuses observed across the group
  - `severities` (array): Unique severities observed across the group
  - `earliest_created_at` (string or null): Oldest `created_at` / timestamp in the group
  - `latest_created_at` (string or null): Most recent `created_at` / timestamp in the group
  - `example_alerts` (array): Up to 3 representative alerts with key fields, **sorted from most recent to oldest**:
    - `id`, `title`, `severity`, `status`, `created_at`, `source`, `rule_id`, `type`, `description`

**Usage Example:**
```json
{
  "name": "get_recent_alerts",
  "arguments": {
    "hours_back": 1,
    "max_alerts": 100,
    "severity": "high"
  }
}
```

**Use Cases:**
- Quickly understand “what’s going on right now” in the last hour of alerts
- Group duplicate or very similar alerts (same title/rule/severity/status) into a single bucket
- Present a compact menu of alert groups to an AI agent so it can choose which group/alert ID to work on next
- Reduce noise when many similar alerts fire from the same rule or pattern

Use `list_rules` to check available rules, and check tool availability through the MCP client's tool discovery mechanism.

---

### `close_alert`

Close a security alert in the SIEM platform. Use this when an alert has been determined to be a false positive or benign true positive during triage.

**Parameters:**
- `alert_id` (string, required): The ID of the alert to close
- `reason` (string, optional): Reason for closing (e.g., "false_positive", "benign_true_positive")
- `comment` (string, optional): Comment explaining why the alert is being closed

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `alert_id` (string): The ID of the alert that was closed
- `status` (string): The new status of the alert (typically "closed")
- `reason` (string): Reason for closing
- `comment` (string): Comment provided
- `alert` (object): Updated alert details

**Usage Example:**
```json
{
  "name": "close_alert",
  "arguments": {
    "alert_id": "alert-123",
    "reason": "false_positive",
    "comment": "Verified as legitimate administrative activity"
  }
}
```

**Use Cases:**
- Close false positive alerts after investigation
- Mark benign true positives as resolved
- Document closure reasons for audit purposes
- Reduce alert noise in the SIEM

---

### `update_alert_verdict`

Update the verdict for a security alert. Use this to set or update the verdict field (e.g., "in-progress", "false_positive", "benign_true_positive", "true_positive"). This is the preferred method for setting verdicts as it clearly indicates the intent to update the verdict rather than close the alert.

**Note:** This tool operates on SIEM alerts (not cases). For case management operations, use the case management tools (e.g., `list_cases`, `review_case`).

**Parameters:**
- `alert_id` (string, required): The ID of the alert to update
- `verdict` (string, required): The verdict value. Valid values:
  - `in-progress`: Alert is being actively investigated
  - `false_positive`: Alert is not a real threat
  - `benign_true_positive`: Alert is a true positive but represents benign activity
  - `true_positive`: Alert is a confirmed security incident
  - `uncertain`: Alert legitimacy cannot be determined with available information
- `comment` (string, optional): Optional comment explaining the verdict

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `alert_id` (string): The ID of the alert that was updated
- `verdict` (string): The verdict that was set
- `comment` (string): Comment provided (if any)
- `alert` (object): Updated alert details

**Usage Example:**
```json
{
  "name": "update_alert_verdict",
  "arguments": {
    "alert_id": "alert-123",
    "verdict": "false_positive",
    "comment": "Verified as legitimate administrative activity after reviewing user permissions and activity logs"
  }
}
```

**Use Cases:**
- Set alert verdict during investigation
- Update verdict as investigation progresses
- Mark alerts as false positives without closing them
- Document verdict with explanatory comments
- Track investigation status through verdict field

**Note:** This is the preferred method for setting verdicts as it clearly indicates the intent to update the verdict rather than close the alert. Use `close_alert` when you want to close the alert entirely.

---

### `get_all_uncertain_alerts_for_host`

Retrieve all alerts with verdict="uncertain" for a specific host. This is useful for pattern analysis when investigating uncertain alerts to determine if multiple uncertain alerts on the same host indicate a broader issue requiring case creation and escalation.

**Parameters:**
- `hostname` (string, required): The hostname to search for
- `hours_back` (integer, optional): How many hours to look back (default: `168` = 7 days)
- `limit` (integer, optional): Maximum number of alerts to return (default: `100`)

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `hostname` (string): The hostname that was searched
- `hours_back` (integer): The lookback period used
- `total_count` (integer): Total number of uncertain alerts found for the host
- `returned_count` (integer): Number of alerts returned (limited by `limit`)
- `alerts` (array): List of uncertain alerts, each containing:
  - `id` (string): Alert identifier
  - `title` (string): Alert title/name
  - `severity` (string): Alert severity
  - `status` (string): Alert status
  - `created_at` (string): ISO timestamp when alert was created
  - `alert_type` (string): Alert type/category
  - `description` (string): Alert description
  - `verdict` (string): Verdict value (should be "uncertain")
  - `hostname` (string): Hostname where alert occurred
  - `related_entities` (array): Related entities (IPs, users, hashes, etc.)
  - `source` (string): SIEM source (e.g., "elastic")

**Usage Example:**
```json
{
  "name": "get_all_uncertain_alerts_for_host",
  "arguments": {
    "hostname": "workstation-01.example.com",
    "hours_back": 168,
    "limit": 100
  }
}
```

**Use Cases:**
- Pattern analysis for uncertain alerts on the same host
- Identify if multiple uncertain alerts indicate a broader threat
- Determine if case creation is needed based on uncertain alert patterns
- Correlate uncertain alerts to find common indicators
- Support SOC1 triage decision-making for uncertain alerts

**Note:** This tool is specifically designed for Step 8.6 of the initial alert triage runbook to help identify patterns when investigating uncertain alerts. If multiple uncertain alerts on the same host show patterns (same alert types, escalating frequency, related entities), this may indicate a real threat requiring case creation and escalation to SOC2.

---

### `tag_alert`

Tag a security alert in the SIEM platform with a classification. Use this to mark alerts as FP (False Positive), TP (True Positive), or NMI (Need More Investigation).

**Parameters:**
- `alert_id` (string, required): The ID of the alert to tag
- `tag` (string, required): The tag to apply. Must be one of:
  - `FP`: False Positive - Alert is not a real threat
  - `TP`: True Positive - Alert is a confirmed security incident
  - `NMI`: Need More Investigation - Requires additional analysis

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `alert_id` (string): The ID of the alert that was tagged
- `tag` (string): The tag that was applied
- `tags` (array): Complete list of tags on the alert after the operation
- `alert` (object): Updated alert details

**Usage Example:**
```json
{
  "name": "tag_alert",
  "arguments": {
    "alert_id": "alert-123",
    "tag": "FP"
  }
}
```

**Use Cases:**
- Classify alerts during triage
- Mark alerts for further investigation (NMI)
- Tag confirmed incidents (TP) for case creation
- Label false positives (FP) for tuning
- Track alert classification for analytics and reporting

**Note:** The tag_alert tool replaces any existing classification tags (FP, TP, NMI) with the new tag to ensure only one classification tag exists at a time.

---

### `add_alert_note`

Add a note or comment to a security alert in the SIEM platform. Use this to document investigation findings, recommendations for detection rule improvements, case numbers, or other relevant information about the alert.

**Parameters:**
- `alert_id` (string, required): The ID of the alert to add a note to
- `note` (string, required): The note/comment text to add. Should include investigation findings, case numbers (if applicable), and recommendations for detection rule improvements

**Returns:**
- `success` (boolean): Whether the operation succeeded
- `alert_id` (string): The ID of the alert that the note was added to
- `note` (string): The note that was added
- `alert` (object): Updated alert details

**Usage Example:**
```json
{
  "name": "add_alert_note",
  "arguments": {
    "alert_id": "alert-123",
    "note": "SOC1 Triage Note:\nAssessment: False Positive\nInvestigation: Verified source IP 10.10.20.2 against client KB - confirmed as VPN pool. User 'Administrator' has 'RDP' and 'vpn-rdp-expected' tags in KB. No IOC matches found.\nRecommendations for Detection Rule Improvement:\n1. Add exclusion for VPN pool IPs (10.10.20.0/24) when user has 'vpn-rdp-expected' tag\n2. Add KB tag check before alerting\n3. Reduce severity for expected RDP patterns from VPN pools"
  }
}
```

**Use Cases:**
- Document investigation findings during alert triage
- Add recommendations for detection rule improvements when closing false positives
- Reference case numbers when escalating alerts
- Document key findings and escalation reasons for true positives
- Provide context for future analysts reviewing the alert
- Track investigation steps and decisions
- Support detection rule fine-tuning with specific recommendations

**Note:** This tool is **mandatory** for SOC1 analysts when closing or escalating alerts per the initial alert triage runbook. Notes should include:
- Investigation summary (what was checked)
- Assessment (FP/BTP/TP/Suspicious/Uncertain)
- Case number (if a case was created)
- For FP/BTP: Specific recommendations for detection rule improvements (bullet points on how to fine-tune the rule)
- For TP/Suspicious: Key findings and escalation reason

---

## Support

For issues, questions, or feature requests related to these tools, please refer to the main SamiGPT documentation or contact your system administrator.

