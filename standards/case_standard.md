# Case Standard for SamiGPT Investigations

## Overview

This document defines the standard structure and format for cases created during security investigations. All cases must follow this standard to ensure consistency, traceability, and proper documentation.

## Case Structure

### 1. Case Metadata

#### Required Fields:
- **Title**: Descriptive title following format: `[Alert Type] - [Primary Entity] - [Date/Time]`
  - Example: `Malware Detection - 10.10.1.2 - 2025-11-18`
  - Example: `Suspicious Login - administrator@domain.com - 2025-11-18`
  
- **Description**: Comprehensive description including:
  - Alert source and ID
  - Initial assessment
  - Key entities involved
  - Severity and priority justification
  
- **Status**: One of: `open`, `in_progress`, `closed`
  - New cases start as `open`
  - Move to `in_progress` when investigation begins
  - Close when resolved or escalated
  
- **Priority**: One of: `low`, `medium`, `high`, `critical`
  - Based on severity, impact, and IOC matches
  
- **Tags**: Relevant tags for categorization
  - Examples: `malware`, `suspicious-login`, `network-alert`, `ioc-match`, `soc1-triage`, `soc2-investigation`

### 2. Case Timeline

The case timeline should document all activities chronologically:

#### Timeline Entry Format:
```
[Timestamp] [Action Type] - [Description]
```

#### Required Timeline Entries:
1. **Case Creation**
   - Document: Alert ID, source, initial assessment
   
2. **Triage Summary** (SOC1)
   - Document: Initial findings, IOC matches, related entities
   - Include: Assessment (FP/BTP/TP), escalation decision
   
3. **Investigation Updates** (SOC2+)
   - Document: Deep analysis findings, correlation results
   - Include: Threat intelligence, behavior analysis
   
4. **Response Actions** (SOC3)
   - Document: Containment actions, forensic collection
   - Include: Endpoints isolated, processes terminated
   
5. **Resolution**
   - Document: Final assessment, remediation steps
   - Include: Lessons learned, recommendations

### 3. Observables (IOCs)

All observables must be attached to the case with proper metadata:

#### Observable Types:
- **IP Address**: `ip`
- **Domain**: `domain`
- **File Hash**: `hash` (MD5, SHA1, SHA256, SHA512)
- **URL**: `url`
- **Email**: `email`
- **User**: `user`
- **Hostname**: `hostname`

#### Required Observable Metadata:
- **Type**: Observable type
- **Value**: The actual observable value
- **Description**: Context about the observable
- **Tags**: Relevant tags (e.g., `malicious`, `suspicious`, `ioc-match`)
- **First Seen**: Timestamp when first observed
- **Last Seen**: Timestamp when last observed
- **Source**: Where the observable was found (alert, SIEM, CTI)

#### Observable Priority:
- **Critical**: Known malicious IOCs, confirmed threats
- **High**: Suspicious indicators, IOC matches
- **Medium**: Unusual activity, requires investigation
- **Low**: Contextual information, related entities

### 4. Notes/Comments

All investigation findings must be documented as case notes:

#### Note Categories:

1. **Triage Notes** (SOC1)
   - Initial assessment
   - Duplicate check results
   - Basic enrichment findings
   - Escalation rationale

2. **Investigation Notes** (SOC2)
   - Deep analysis results
   - Correlation findings
   - Threat intelligence analysis
   - Behavior analysis

3. **Response Notes** (SOC3)
   - Containment actions taken
   - Forensic collection results
   - Remediation steps

4. **General Notes**
   - Analyst observations
   - Additional context
   - External references

#### Note Format:
```markdown
## [Category] - [Title]

**Timestamp**: [ISO 8601 format]
**Author**: [Agent/Analyst name]
**SOC Tier**: [SOC1/SOC2/SOC3]

### Findings
- Finding 1
- Finding 2

### Evidence
- Evidence reference 1
- Evidence reference 2

### Assessment
[Assessment summary]

### Next Steps
- Action item 1
- Action item 2
```

### 5. Tasks

Tasks represent actionable items for investigation and response:

#### Task Categories:

1. **Investigation Tasks** (SOC2)
   - Deep IOC analysis
   - Threat intelligence correlation
   - Behavior analysis
   - Network correlation

2. **Response Tasks** (SOC3)
   - Endpoint isolation
   - Process termination
   - Forensic collection
   - Evidence preservation

3. **Remediation Tasks**
   - System cleanup
   - Policy updates
   - User notification
   - Documentation

#### Task Format:
- **Title**: Clear, actionable task description
- **Description**: Detailed task requirements
- **Assignee**: SOC tier or analyst responsible
- **Status**: `pending`, `in_progress`, `completed`, `blocked`
- **Priority**: `low`, `medium`, `high`, `critical`
- **Due Date**: Target completion date
- **Dependencies**: Related tasks or prerequisites

### 6. Assets

Assets represent systems, endpoints, or resources involved in the case:

#### Asset Types:
- **Endpoint**: Individual host/device
- **Server**: Server system
- **Network**: Network segment or infrastructure
- **User Account**: User account or identity
- **Application**: Application or service

#### Asset Metadata:
- **Name**: Asset identifier
- **Type**: Asset type
- **Status**: `active`, `isolated`, `compromised`, `remediated`
- **IP Address**: Network address (if applicable)
- **Hostname**: System hostname (if applicable)
- **OS**: Operating system (if applicable)
- **First Seen**: When asset was first involved
- **Last Seen**: When asset was last involved
- **Tags**: Relevant tags

### 7. Evidence

Evidence includes files, logs, screenshots, and other artifacts:

#### Evidence Types:
- **File**: File artifacts (logs, executables, documents)
- **Screenshot**: Visual evidence
- **Log**: Log file or log excerpt
- **Network Capture**: PCAP or network traffic
- **Memory Dump**: Memory capture
- **Registry**: Registry entries
- **Other**: Other evidence types

#### Evidence Metadata:
- **Name**: Evidence file name
- **Type**: Evidence type
- **Description**: What the evidence shows
- **Source**: Where evidence was collected
- **Hash**: File hash (if applicable)
- **Size**: File size
- **Collected By**: Who collected the evidence
- **Collection Date**: When evidence was collected
- **Tags**: Relevant tags

### 8. Case Linking

Cases should be linked when they are related:

#### Link Types:
- **Related To**: General relationship
- **Duplicate Of**: Duplicate case
- **Escalated From**: Escalation relationship
- **Child Of**: Parent-child relationship
- **Blocked By**: Dependency relationship

## Case Creation Workflow

### Step 1: Initial Case Creation

When creating a new case from an alert:

1. **Extract Alert Information**
   - Alert ID
   - Alert type
   - Severity
   - Source system
   - Timestamp

2. **Create Case**
   - Generate title following standard format
   - Write comprehensive description
   - Set initial status: `open`
   - Set priority based on severity
   - Add initial tags

3. **Add Initial Note**
   - Document alert details
   - Record initial assessment
   - Note triage start

### Step 2: Triage Documentation (SOC1)

1. **Add Triage Note**
   - Document duplicate check
   - Record basic enrichment
   - Note IOC matches
   - Document assessment decision

2. **Attach Observables**
   - Attach all primary entities
   - Include metadata (description, tags)
   - Note IOC match status

3. **Update Case Status**
   - If FP/BTP: Set status to `closed`
   - If TP/Suspicious: Set status to `in_progress`

### Step 3: Investigation Documentation (SOC2)

1. **Add Investigation Notes**
   - Document deep analysis findings
   - Record correlation results
   - Note threat intelligence matches
   - Document behavior analysis

2. **Create Investigation Tasks**
   - Assign tasks to appropriate SOC tier
   - Set priorities and due dates
   - Link related tasks

3. **Attach Additional Observables**
   - Add newly discovered IOCs
   - Update observable metadata
   - Link related observables

### Step 4: Response Documentation (SOC3)

1. **Add Response Notes**
   - Document containment actions
   - Record forensic collection
   - Note remediation steps

2. **Attach Evidence**
   - Upload collected evidence
   - Document evidence metadata
   - Link evidence to observables

3. **Update Assets**
   - Mark assets as isolated/remediated
   - Document asset status changes
   - Record remediation actions

### Step 5: Case Resolution

1. **Final Assessment Note**
   - Document final findings
   - Record resolution steps
   - Note lessons learned

2. **Complete All Tasks**
   - Mark tasks as completed
   - Document task outcomes

3. **Close Case**
   - Set status to `closed`
   - Add resolution tags
   - Document closure reason

## Case Template

```markdown
# Case: [Title]

## Metadata
- **Case ID**: [ID]
- **Status**: [Status]
- **Priority**: [Priority]
- **Created**: [Timestamp]
- **Updated**: [Timestamp]
- **Assignee**: [Assignee]
- **Tags**: [Tags]

## Description
[Comprehensive case description]

## Timeline
[Chronological timeline of events]

## Observables
[List of IOCs with metadata]

## Notes
[Investigation notes by category]

## Tasks
[Actionable tasks with status]

## Assets
[Involved systems and resources]

## Evidence
[Collected evidence and artifacts]

## Related Cases
[Links to related cases]
```

## Best Practices

1. **Always Create Cases**: Never investigate without creating a case
2. **Document Everything**: All findings must be documented
3. **Attach Observables**: All IOCs must be attached with metadata
4. **Update Timeline**: Keep timeline current with all activities
5. **Use Tags**: Tag cases appropriately for filtering
6. **Link Related Cases**: Link cases that are related
7. **Preserve Evidence**: Always attach evidence with proper metadata
8. **Follow SOC Tiers**: Respect SOC tier responsibilities
9. **Document Decisions**: Always document why decisions were made
10. **Maintain Chain of Custody**: Document evidence collection properly

## Integration with IRIS API

When using IRIS as the case management system:

- **Cases**: Use `/manage/cases/add` to create cases
- **Notes**: Use `/comments/add` to add notes
- **IOCs**: Use `/case/ioc/add` to attach observables
- **Tasks**: Use IRIS task management endpoints
- **Assets**: Use IRIS asset management endpoints
- **Evidence**: Use IRIS file upload endpoints
- **Timeline**: Use `/comments/list` to retrieve timeline

## Compliance

This standard ensures:
- **Traceability**: All actions are documented
- **Accountability**: Clear assignment of responsibilities
- **Consistency**: Uniform case structure across investigations
- **Completeness**: All required information is captured
- **Auditability**: Full audit trail of investigation

