# Agent Profiles (SOC1 only)

SamiGPT currently ships **SOC1 triage only**. SOC2/SOC3 agent profiles and runbooks are deferred.

## Active profile

Configured in `config/agent_profiles.json`:

| Agent ID | Tier | Starting runbook |
|---|---|---|
| `soc1_triage_agent` | soc1 | `soc1/triage/initial_alert_triage` |

### Runbooks available to SOC1

- `soc1/triage/initial_alert_triage`
- `soc1/enrichment/ioc_enrichment`
- `soc1/remediation/close_false_positive`
- Case-specific: `soc1/cases/suspicious_login_triage`, `soc1/cases/malware_initial_triage`

### Guidelines

- `run_books/soc1/guidelines.md` — SOC1 Triage Agent objectives and constraints

## MCP tools

- `list_agent_profiles` / `get_agent_profile` — inspect the SOC1 profile (includes the configured `tools` list)
- `route_case_to_agent` — currently routes to `soc1_triage_agent`
- `execute_as_agent` — loads the agent profile, selects a SOC1 runbook, returns runbook content for the model to follow
- `list_runbooks` / `get_runbook` / `execute_runbook` — discover and load markdown under `run_books/soc1/`

SOC1 SIEM query skills (also gated by the Elastic skill vector / UI): `search_security_events`, `search_kql_query`, `search_lucene_query`, `search_eql_query`, `search_dsl_query`, `search_esql_query`. Full catalog: `skills.md`.

After triage, if no case playbook under `soc1/cases` matched the alert type, file `create_runbook_recommendation` (informational Requests note) — never block investigation for it.

## Routing

```json
{
  "routing_rules": {
    "new_alert": "soc1_triage_agent",
    "review_cases": "soc1_triage_agent"
  }
}
```

## Escalation language in SOC1 runbooks

SOC1 runbooks may still say “escalate to SOC2/SOC3” as a **handoff instruction** (create case/tasks for humans). There are no SOC2/SOC3 runbooks or agent profiles in-tree to execute those tiers yet.
