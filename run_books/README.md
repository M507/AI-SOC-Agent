# SamiGPT Runbooks

Security operation runbooks for autonomous agent execution.

**Current scope: SOC1 only.** SOC2 and SOC3 runbooks are deferred.

## Quick Start

1. **Review Guidelines**: [SOC1 Guidelines](./soc1/guidelines.md) — initial triage and basic analysis
2. **Runbook Guidelines**: See [runbook_guidelines.md](./runbook_guidelines.md) for development standards

## Directory Structure

```
run_books/
├── soc1/                    # Tier 1 - Initial Triage
│   ├── triage/              # Alert triage workflows
│   │   ├── initial_alert_triage.md
│   │   └── flow_initial_alert_triage.py
│   ├── enrichment/          # IOC enrichment workflows
│   │   └── ioc_enrichment.md
│   ├── cases/               # Case-specific triage runbooks
│   │   ├── suspicious_login_triage.md
│   │   └── malware_initial_triage.md
│   ├── remediation/         # Remediation workflows
│   │   └── close_false_positive.md
│   └── guidelines.md
├── AGENT_PROFILES_IMPLEMENTATION.md
└── runbook_guidelines.md
```

## SOC1 - Initial Triage

- **Purpose**: Initial alert triage, basic analysis, false positive identification
- **Key Runbooks**:
  - `triage/initial_alert_triage.md` - Main triage workflow
  - `enrichment/ioc_enrichment.md` - IOC enrichment
  - `cases/suspicious_login_triage.md` - Suspicious login triage
  - `cases/malware_initial_triage.md` - Malware triage
  - `remediation/close_false_positive.md` - False positive closure

## Agent Execution Model

SOC1 has an autonomous agent with:
- **Specific runbooks** it can execute
- **Decision authority** for triage (close FP/BTP, escalate when needed)
- **Documentation requirements** for all actions

See [AGENT_PROFILES_IMPLEMENTATION.md](./AGENT_PROFILES_IMPLEMENTATION.md) for agent profile configuration.

## Escalation Flow

```
Alert → SOC1 (Triage)
```

SOC1 handles initial triage. Confirmed true positives that need deeper work are documented in cases/tasks for human or future higher-tier follow-up. SOC2/SOC3 runbooks are not present in this tree yet.

## References

- Original inspiration: [ADK Runbooks](https://github.com/dandye/adk_runbooks/tree/main)
- Skill catalog: [`skills.md`](../skills.md) — includes Elastic query skills (`search_kql_query`, `search_lucene_query`, `search_eql_query`, `search_dsl_query`, `search_esql_query`)
- Tool details: [`src/mcp/TOOLS.md`](../src/mcp/TOOLS.md)
