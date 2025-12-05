# Case Creation Implementation Summary

## ✅ Implementation Complete

### What Was Added

1. **Case Standard Document** (`standards/case_standard.md`)
   - Comprehensive case structure definition
   - Timeline, observables, notes, tasks, assets, evidence standards
   - Integration guidelines for IRIS API
   - Best practices and compliance requirements

2. **Create Case Tool** (`src/orchestrator/tools_case.py`)
   - New `create_case()` function
   - Follows case standard format
   - Automatically adds initial note
   - Supports all case metadata fields

3. **MCP Server Integration** (`src/mcp/mcp_server.py`)
   - Registered `create_case` tool
   - Automatic case creation in runbook execution
   - Case search before creation (prevents duplicates)
   - Follows case standard format

### Features

#### Automatic Case Creation
- When executing a runbook with an `alert_id` but no `case_id`, the system will:
  1. Search for existing cases with that alert ID
  2. If found, use the existing case
  3. If not found, create a new case following the standard format

#### Case Standard Compliance
- Title format: `[Alert Type] - [Primary Entity] - [Date/Time]`
- Comprehensive description with alert details
- Proper priority assignment based on alert severity
- Tags for categorization (SOC tier, runbook type)
- Initial note documenting case creation

#### IRIS API Integration
- Uses IRIS API endpoints:
  - `/manage/cases/add` - Create case
  - `/comments/add` - Add notes
  - `/case/ioc/add` - Attach observables
  - `/comments/list` - Get timeline

### Usage

#### Manual Case Creation
```python
create_case(
    title="Malware Detection - 10.10.1.2 - 2025-11-18",
    description="Comprehensive case description...",
    priority="high",
    status="open",
    tags=["malware", "ioc-match", "soc1-triage"],
    alert_id="ALERT-12345"
)
```

#### Automatic Case Creation
When executing a runbook:
```python
execute_runbook(
    runbook_name="initial_alert_triage",
    alert_id="949757cfd6451f4dd186b7b4101c6acaa258f6958ab53d54d34f140dd4b86420"
)
```

The system will automatically:
1. Check for existing case
2. Create case if needed
3. Add initial note
4. Provide case_id in execution context

### Case Standard Structure

All cases follow this structure:

1. **Metadata**: Title, description, status, priority, tags
2. **Timeline**: Chronological events and activities
3. **Observables**: IOCs with full metadata
4. **Notes**: Investigation findings by category
5. **Tasks**: Actionable items for SOC tiers
6. **Assets**: Involved systems and resources
7. **Evidence**: Collected artifacts and files

### Next Steps

To fully utilize IRIS API features:

1. **Tasks**: Implement task creation endpoints
   - Use IRIS task management API
   - Assign tasks to SOC tiers
   - Track task completion

2. **Assets**: Implement asset management
   - Use IRIS asset management API
   - Track endpoint status
   - Document asset involvement

3. **Evidence**: Implement evidence upload
   - Use IRIS file upload API
   - Attach evidence to cases
   - Maintain chain of custody

4. **Timeline**: Enhanced timeline support
   - Use IRIS timeline API
   - Include all case activities
   - Maintain chronological order

### Files Modified

- `src/orchestrator/tools_case.py` - Added `create_case()` function
- `src/mcp/mcp_server.py` - Registered tool, added auto-creation logic
- `standards/case_standard.md` - Case standard definition (NEW)

### Testing

After restarting MCP server, test with:

```
"Triage alert 949757cfd6451f4dd186b7b4101c6acaa258f6958ab53d54d34f140dd4b86420 using initial alert triage runbook"
```

Expected behavior:
1. System searches for existing case
2. Creates new case if not found
3. Follows case standard format
4. Adds initial note
5. Executes runbook with case_id

