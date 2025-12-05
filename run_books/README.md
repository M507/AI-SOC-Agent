# SamiGPT Runbooks

This directory contains security operation runbooks organized by SOC tier levels for autonomous agent execution.

## Quick Start

1. **Review Guidelines**: Each SOC tier has its own guidelines:
   - [SOC1 Guidelines](./soc1/guidelines.md) - Initial triage and basic analysis
   - [SOC2 Guidelines](./soc2/guidelines.md) - Deep investigation and correlation
   - [SOC3 Guidelines](./soc3/guidelines.md) - Incident response and forensics

2. **Runbook Guidelines**: See [runbook_guidelines.md](./runbook_guidelines.md) for general runbook development standards.

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
├── soc2/                    # Tier 2 - Deep Investigation
│   ├── investigation/       # Investigation workflows
│   │   ├── case_analysis.md
│   │   └── flow_case_analysis.py
│   ├── correlation/         # Correlation analysis
│   │   └── multi_ioc_correlation.md
│   ├── cases/               # Case-specific investigation runbooks
│   │   ├── suspicious_login_investigation.md
│   │   └── malware_deep_analysis.md
│   ├── containment/         # Containment recommendations
│   └── guidelines.md
├── soc3/                    # Tier 3 - Incident Response
│   ├── response/            # Response actions
│   │   ├── endpoint_isolation.md
│   │   └── process_termination.md
│   ├── forensics/           # Forensic collection
│   │   └── artifact_collection.md
│   ├── reporting/           # Reporting workflows
│   └── guidelines.md
├── AGENT_PROFILES_IMPLEMENTATION.md
├── USAGE_EXAMPLES.md
├── runbook_guidelines.md
└── index.md
```

## SOC Tier Structure

### SOC1 - Initial Triage
- **Purpose**: Initial alert triage, basic analysis, false positive identification
- **Key Runbooks**:
  - `triage/initial_alert_triage.md` - Main triage workflow
  - `enrichment/ioc_enrichment.md` - IOC enrichment
  - `cases/suspicious_login_triage.md` - Suspicious login triage
  - `cases/malware_initial_triage.md` - Malware triage
  - `remediation/close_false_positive.md` - False positive closure

### SOC2 - Deep Investigation
- **Purpose**: Deep investigation, correlation, containment recommendations
- **Key Runbooks**:
  - `investigation/case_analysis.md` - Comprehensive case analysis
  - `correlation/multi_ioc_correlation.md` - Multi-IOC correlation
  - `cases/suspicious_login_investigation.md` - Suspicious login investigation
  - `cases/malware_deep_analysis.md` - Deep malware analysis

### SOC3 - Incident Response
- **Purpose**: Incident response, containment execution, forensics
- **Status**: ⚠️ **Incomplete** - SOC3 runbooks and workflows are still under development
- **Key Runbooks**:
  - `response/endpoint_isolation.md` - Endpoint isolation
  - `response/process_termination.md` - Process termination
  - `forensics/artifact_collection.md` - Forensic artifact collection

## Agent Execution Model

Each SOC tier has autonomous agents with:
- **Specific runbooks** they can execute
- **Decision authority** for their tier
- **Escalation paths** to higher tiers
- **Documentation requirements** for all actions

See [AGENT_PROFILES_IMPLEMENTATION.md](./AGENT_PROFILES_IMPLEMENTATION.md) for detailed agent profile configuration.

## Escalation Flow

```
Alert → SOC1 → SOC2 → SOC3
       (Triage) (Investigation) (Response)
```

- **SOC1** handles initial triage and can escalate to SOC2 for deep investigation
- **SOC2** performs correlation and can escalate to SOC3 for response actions
- **SOC3** executes containment and forensic collection

See [SOC_TIER_ORGANIZATION_PLAN.md](./SOC_TIER_ORGANIZATION_PLAN.md) for detailed escalation criteria and workflows.

## Usage Examples

See [USAGE_EXAMPLES.md](./USAGE_EXAMPLES.md) for practical examples of how to use these runbooks with the SamiGPT MCP server.

## References

- Original inspiration: [ADK Runbooks](https://github.com/dandye/adk_runbooks/tree/main)
