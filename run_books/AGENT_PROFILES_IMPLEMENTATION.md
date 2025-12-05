# Agent Profiles Implementation Guide

## Overview

The Agent Profiles approach allows you to configure multiple autonomous agents, each with a specific SOC tier profile. Agents automatically discover and use appropriate runbooks based on their tier and the type of case/alert they're investigating.

## Architecture

```
┌─────────────────┐
│   User/System   │
│   Request       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Agent Router   │  ← Routes to appropriate agent based on case/alert
└────────┬────────┘
         │
    ┌────┴────┬──────────┬──────────┐
    │         │          │          │
    ▼         ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
│ SOC1   │ │ SOC2   │ │ SOC3   │ │ Custom │
│ Agent  │ │ Agent  │ │ Agent  │ │ Agent  │
└────────┘ └────────┘ └────────┘ └────────┘
    │         │          │          │
    └─────────┴──────────┴──────────┘
              │
              ▼
    ┌─────────────────┐
    │  Runbook        │
    │  Execution      │
    └─────────────────┘
```

## Implementation Components

### 1. Agent Profile Configuration & Tier Guidelines

**File: `config/agent_profiles.json`**

```json
{
  "agents": {
    "soc1_triage_agent": {
      "name": "SOC1 Triage Agent",
      "tier": "soc1",
      "description": "Handles initial alert triage and false positive identification",
      "capabilities": [
        "initial_triage",
        "basic_enrichment",
        "false_positive_identification"
      ],
      "runbooks": [
        "soc1/triage/initial_alert_triage",
        "soc1/triage/suspicious_login_triage",
        "soc1/triage/malware_initial_triage",
        "soc1/enrichment/ioc_enrichment",
        "soc1/remediation/close_false_positive"
      ],
      "decision_authority": {
        "close_false_positives": true,
        "close_benign_true_positives": true,
        "escalate_to_soc2": true,
        "escalate_to_soc3": false,
        "containment_actions": false,
        "forensic_collection": false
      },
      "auto_select_runbook": true,
      "max_concurrent_cases": 10
    },
    "soc2_investigation_agent": {
      "name": "SOC2 Investigation Agent",
      "tier": "soc2",
      "description": "Performs deep investigation and correlation analysis",
      "capabilities": [
        "deep_investigation",
        "correlation_analysis",
        "threat_hunting",
        "containment_recommendations"
      ],
      "runbooks": [
        "soc2/investigation/malware_deep_analysis",
        "soc2/investigation/suspicious_login_investigation",
        "soc2/correlation/multi_ioc_correlation"
      ],
      "decision_authority": {
        "close_false_positives": true,
        "escalate_to_soc2": false,
        "escalate_to_soc3": true,
        "containment_actions": false,
        "forensic_collection": false
      },
      "auto_select_runbook": true,
      "max_concurrent_cases": 5
    },
    "soc3_response_agent": {
      "name": "SOC3 Response Agent",
      "tier": "soc3",
      "description": "Executes incident response and containment actions",
      "capabilities": [
        "incident_response",
        "containment_execution",
        "forensic_collection"
      ],
      "runbooks": [
        "soc3/response/endpoint_isolation",
        "soc3/response/process_termination",
        "soc3/forensics/artifact_collection"
      ],
      "decision_authority": {
        "close_false_positives": true,
        "escalate_to_soc2": false,
        "escalate_to_soc3": false,
        "containment_actions": true,
        "forensic_collection": true
      },
      "auto_select_runbook": true,
      "max_concurrent_cases": 3
    }
  },
  "routing_rules": {
    "new_alert": "soc1_triage_agent",
    "escalated_from_soc1": "soc2_investigation_agent",
    "requires_containment": "soc3_response_agent",
    "forensic_collection": "soc3_response_agent"
  }
}
```

In addition to the JSON configuration, **each SOC tier has a dedicated guidelines file** under `run_books/`:

- `run_books/soc1/guidelines.md` – Explains the SOC1 Triage Agent profile and its main objectives.
- `run_books/soc2/guidelines.md` – Explains the SOC2 Investigation Agent profile and its main objectives.
- `run_books/soc3/guidelines.md` – Explains the SOC3 Response Agent profile and its main objectives.

These guidelines:

- Describe **exactly** what the agent is expected to do (and not do).
- Summarize the **main objectives**, responsibilities, and limitations for the tier.
- List the **key runbooks** associated with that profile.

When `execute_as_agent` is used for a given agent **for the first time in an MCP server process**, the server will:

- Automatically load the corresponding `guidelines.md` for that agent’s tier.
- Include the guidelines content in the tool result under `profile_guidelines`, so MCP users see the profile description **before** following the runbook steps.

### 2. Agent Profile Manager

**File: `src/mcp/agent_profiles.py`**

```python
"""
Agent Profile Manager for SOC tier-based agent configuration.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..core.errors import IntegrationError


@dataclass
class DecisionAuthority:
    """Decision authority for an agent."""
    close_false_positives: bool = False
    close_benign_true_positives: bool = False
    escalate_to_soc2: bool = False
    escalate_to_soc3: bool = False
    containment_actions: bool = False
    forensic_collection: bool = False


@dataclass
class AgentProfile:
    """Represents an agent profile configuration."""
    name: str
    tier: str  # "soc1", "soc2", "soc3"
    description: str
    capabilities: List[str]
    runbooks: List[str]
    decision_authority: DecisionAuthority
    auto_select_runbook: bool = True
    max_concurrent_cases: int = 10

    def can_execute_runbook(self, runbook_name: str) -> bool:
        """Check if agent can execute a runbook."""
        # Check if runbook is in agent's runbook list
        if runbook_name in self.runbooks:
            return True
        
        # Check if runbook matches agent's tier
        if f"/{self.tier}/" in runbook_name:
            return True
        
        return False

    def select_runbook_for_alert(self, alert_type: str, alert_details: Dict[str, Any]) -> Optional[str]:
        """Auto-select appropriate runbook based on alert type."""
        if not self.auto_select_runbook:
            return None
        
        # Map alert types to runbooks
        alert_to_runbook = {
            "suspicious_login": "soc1/triage/suspicious_login_triage",
            "malware_detection": "soc1/triage/malware_initial_triage",
            "network_alert": "soc1/triage/initial_alert_triage",
            "default": "soc1/triage/initial_alert_triage"
        }
        
        # For SOC1
        if self.tier == "soc1":
            return alert_to_runbook.get(alert_type, alert_to_runbook["default"])
        
        # For SOC2 - select based on case type
        if self.tier == "soc2":
            if "malware" in alert_type.lower() or "file_hash" in alert_details:
                return "soc2/investigation/malware_deep_analysis"
            elif "login" in alert_type.lower() or "authentication" in alert_type.lower():
                return "soc2/investigation/suspicious_login_investigation"
            else:
                return "soc2/investigation/malware_deep_analysis"  # Default
        
        # For SOC3 - select based on required action
        if self.tier == "soc3":
            if "isolate" in alert_details.get("recommended_actions", []):
                return "soc3/response/endpoint_isolation"
            elif "terminate" in alert_details.get("recommended_actions", []):
                return "soc3/response/process_termination"
            elif "forensic" in alert_details.get("recommended_actions", []):
                return "soc3/forensics/artifact_collection"
        
        return None


class AgentProfileManager:
    """Manages agent profiles and routing."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize agent profile manager.
        
        Args:
            config_path: Path to agent profiles config file.
        """
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__),
                "..", "..", "config", "agent_profiles.json"
            )
        
        self.config_path = config_path
        self.profiles: Dict[str, AgentProfile] = {}
        self.routing_rules: Dict[str, str] = {}
        self._load_profiles()
    
    def _load_profiles(self) -> None:
        """Load agent profiles from config file."""
        if not os.path.exists(self.config_path):
            # Create default profiles
            self._create_default_profiles()
            return
        
        with open(self.config_path, "r") as f:
            config = json.load(f)
        
        # Load agent profiles
        for agent_id, agent_config in config.get("agents", {}).items():
            decision_auth = DecisionAuthority(
                **agent_config.get("decision_authority", {})
            )
            
            profile = AgentProfile(
                name=agent_config["name"],
                tier=agent_config["tier"],
                description=agent_config.get("description", ""),
                capabilities=agent_config.get("capabilities", []),
                runbooks=agent_config.get("runbooks", []),
                decision_authority=decision_auth,
                auto_select_runbook=agent_config.get("auto_select_runbook", True),
                max_concurrent_cases=agent_config.get("max_concurrent_cases", 10)
            )
            
            self.profiles[agent_id] = profile
        
        # Load routing rules
        self.routing_rules = config.get("routing_rules", {})
    
    def _create_default_profiles(self) -> None:
        """Create default agent profiles."""
        # SOC1 Profile
        soc1_profile = AgentProfile(
            name="SOC1 Triage Agent",
            tier="soc1",
            description="Handles initial alert triage",
            capabilities=["initial_triage", "basic_enrichment"],
            runbooks=[
                "soc1/triage/initial_alert_triage",
                "soc1/triage/suspicious_login_triage",
                "soc1/triage/malware_initial_triage"
            ],
            decision_authority=DecisionAuthority(
                close_false_positives=True,
                escalate_to_soc2=True
            )
        )
        self.profiles["soc1_triage_agent"] = soc1_profile
        
        # SOC2 Profile
        soc2_profile = AgentProfile(
            name="SOC2 Investigation Agent",
            tier="soc2",
            description="Performs deep investigation",
            capabilities=["deep_investigation", "correlation"],
            runbooks=[
                "soc2/investigation/malware_deep_analysis",
                "soc2/investigation/suspicious_login_investigation"
            ],
            decision_authority=DecisionAuthority(
                close_false_positives=True,
                escalate_to_soc3=True
            )
        )
        self.profiles["soc2_investigation_agent"] = soc2_profile
        
        # SOC3 Profile
        soc3_profile = AgentProfile(
            name="SOC3 Response Agent",
            tier="soc3",
            description="Executes incident response",
            capabilities=["incident_response", "containment"],
            runbooks=[
                "soc3/response/endpoint_isolation",
                "soc3/response/process_termination"
            ],
            decision_authority=DecisionAuthority(
                containment_actions=True,
                forensic_collection=True
            )
        )
        self.profiles["soc3_response_agent"] = soc3_profile
    
    def get_profile(self, agent_id: str) -> Optional[AgentProfile]:
        """Get agent profile by ID."""
        return self.profiles.get(agent_id)
    
    def list_profiles(self) -> List[Dict[str, Any]]:
        """List all agent profiles."""
        return [
            {
                "agent_id": agent_id,
                "name": profile.name,
                "tier": profile.tier,
                "description": profile.description,
                "capabilities": profile.capabilities,
                "runbook_count": len(profile.runbooks),
                "decision_authority": {
                    "close_false_positives": profile.decision_authority.close_false_positives,
                    "escalate_to_soc2": profile.decision_authority.escalate_to_soc2,
                    "escalate_to_soc3": profile.decision_authority.escalate_to_soc3,
                    "containment_actions": profile.decision_authority.containment_actions
                }
            }
            for agent_id, profile in self.profiles.items()
        ]
    
    def route_to_agent(
        self,
        case_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        alert_type: Optional[str] = None,
        case_status: Optional[str] = None
    ) -> Optional[str]:
        """
        Route a case/alert to appropriate agent.
        
        Args:
            case_id: Case ID
            alert_id: Alert ID
            alert_type: Type of alert
            case_status: Current case status
        
        Returns:
            Agent ID to handle the case/alert
        """
        # Check routing rules
        if case_status == "escalated_from_soc1":
            return self.routing_rules.get("escalated_from_soc1", "soc2_investigation_agent")
        
        if "containment" in (case_status or "").lower():
            return self.routing_rules.get("requires_containment", "soc3_response_agent")
        
        if "forensic" in (case_status or "").lower():
            return self.routing_rules.get("forensic_collection", "soc3_response_agent")
        
        # Default: route new alerts to SOC1
        return self.routing_rules.get("new_alert", "soc1_triage_agent")
    
    def get_agent_for_tier(self, tier: str) -> Optional[AgentProfile]:
        """Get agent profile for a specific SOC tier."""
        for profile in self.profiles.values():
            if profile.tier == tier:
                return profile
        return None
```

### 3. MCP Server Integration

**Add to `src/mcp/mcp_server.py`:**

```python
from .agent_profiles import AgentProfileManager

class MCPServer:
    def __init__(self, ...):
        # ... existing initialization ...
        self.agent_profile_manager = AgentProfileManager()
    
    def _load_runbook_tools(self):
        """Load runbook and agent profile tools."""
        
        # Agent Profile Tools
        self.tools["list_agent_profiles"] = {
            "name": "list_agent_profiles",
            "description": "List all configured agent profiles with their capabilities and runbooks",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }
        
        self.tools["get_agent_profile"] = {
            "name": "get_agent_profile",
            "description": "Get details of a specific agent profile",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Agent ID (e.g., 'soc1_triage_agent')"
                    }
                },
                "required": ["agent_id"]
            }
        }
        
        self.tools["route_case_to_agent"] = {
            "name": "route_case_to_agent",
            "description": "Route a case/alert to the appropriate agent based on routing rules",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "Case ID to route"
                    },
                    "alert_id": {
                        "type": "string",
                        "description": "Alert ID to route"
                    },
                    "alert_type": {
                        "type": "string",
                        "description": "Type of alert (e.g., 'suspicious_login', 'malware_detection')"
                    }
                }
            }
        }
        
        self.tools["execute_as_agent"] = {
            "name": "execute_as_agent",
            "description": "Execute an investigation as a specific agent. The agent will automatically select and execute the appropriate runbook based on its profile.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Agent ID to execute as (e.g., 'soc1_triage_agent')"
                    },
                    "case_id": {
                        "type": "string",
                        "description": "Case ID for investigation"
                    },
                    "alert_id": {
                        "type": "string",
                        "description": "Alert ID from SIEM"
                    },
                    "runbook_name": {
                        "type": "string",
                        "description": "Optional: Specific runbook to execute (overrides auto-selection)"
                    }
                },
                "required": ["agent_id"]
            }
        }
    
    async def _handle_agent_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle agent profile tool calls."""
        
        if tool_name == "list_agent_profiles":
            profiles = self.agent_profile_manager.list_profiles()
            return {"profiles": profiles, "count": len(profiles)}
        
        elif tool_name == "get_agent_profile":
            agent_id = arguments["agent_id"]
            profile = self.agent_profile_manager.get_profile(agent_id)
            if not profile:
                return {
                    "success": False,
                    "error": f"Agent profile not found: {agent_id}"
                }
            
            return {
                "success": True,
                "agent_id": agent_id,
                "name": profile.name,
                "tier": profile.tier,
                "description": profile.description,
                "capabilities": profile.capabilities,
                "runbooks": profile.runbooks,
                "decision_authority": {
                    "close_false_positives": profile.decision_authority.close_false_positives,
                    "escalate_to_soc2": profile.decision_authority.escalate_to_soc2,
                    "escalate_to_soc3": profile.decision_authority.escalate_to_soc3,
                    "containment_actions": profile.decision_authority.containment_actions,
                    "forensic_collection": profile.decision_authority.forensic_collection
                },
                "auto_select_runbook": profile.auto_select_runbook,
                "max_concurrent_cases": profile.max_concurrent_cases
            }
        
        elif tool_name == "route_case_to_agent":
            agent_id = self.agent_profile_manager.route_to_agent(
                case_id=arguments.get("case_id"),
                alert_id=arguments.get("alert_id"),
                alert_type=arguments.get("alert_type")
            )
            
            if agent_id:
                profile = self.agent_profile_manager.get_profile(agent_id)
                return {
                    "success": True,
                    "agent_id": agent_id,
                    "agent_name": profile.name if profile else None,
                    "tier": profile.tier if profile else None,
                    "routing_reason": "Based on routing rules and case/alert characteristics"
                }
            else:
                return {
                    "success": False,
                    "error": "Could not determine appropriate agent"
                }
        
        elif tool_name == "execute_as_agent":
            agent_id = arguments["agent_id"]
            profile = self.agent_profile_manager.get_profile(agent_id)
            
            if not profile:
                return {
                    "success": False,
                    "error": f"Agent profile not found: {agent_id}"
                }
            
            # Get alert/case details if provided
            alert_id = arguments.get("alert_id")
            case_id = arguments.get("case_id")
            alert_details = {}
            
            if alert_id:
                # Get alert details
                alert = self.siem_client.get_security_alert_by_id(alert_id)
                alert_details = {
                    "alert_type": alert.alert_type if hasattr(alert, 'alert_type') else None,
                    "severity": alert.severity if hasattr(alert, 'severity') else None
                }
            
            # Auto-select runbook if not specified
            runbook_name = arguments.get("runbook_name")
            if not runbook_name and profile.auto_select_runbook:
                runbook_name = profile.select_runbook_for_alert(
                    alert_type=alert_details.get("alert_type", ""),
                    alert_details=alert_details
                )
            
            if not runbook_name:
                return {
                    "success": False,
                    "error": "Could not determine appropriate runbook. Please specify runbook_name."
                }
            
            # Verify agent can execute this runbook
            if not profile.can_execute_runbook(runbook_name):
                return {
                    "success": False,
                    "error": f"Agent {agent_id} (tier: {profile.tier}) cannot execute runbook {runbook_name}"
                }
            
            # Execute runbook (use existing execute_runbook logic)
            runbook_result = self._execute_runbook(
                runbook_name=runbook_name,
                case_id=case_id,
                alert_id=alert_id,
                soc_tier=profile.tier,
                agent_id=agent_id,
                **{k: v for k, v in arguments.items() 
                   if k not in ["agent_id", "case_id", "alert_id", "runbook_name"]}
            )
            
            return {
                "success": True,
                "agent_id": agent_id,
                "agent_name": profile.name,
                "tier": profile.tier,
                "runbook_executed": runbook_name,
                "runbook_result": runbook_result
            }
```

## User Usage Examples

### Example 1: Automatic Routing (Recommended)

**User Request:**
```
"Triage alert ALERT-12345"
```

**System Flow:**
1. System calls `route_case_to_agent(alert_id="ALERT-12345")`
2. Router determines: "new_alert" → routes to `soc1_triage_agent`
3. System calls `execute_as_agent(agent_id="soc1_triage_agent", alert_id="ALERT-12345")`
4. SOC1 agent auto-selects runbook: `initial_alert_triage`
5. Agent executes runbook following all steps
6. If escalation needed, automatically routes to SOC2 agent

**What User Sees:**
```
> Triage alert ALERT-12345

[System] Routing to SOC1 Triage Agent...
[SOC1 Agent] Executing initial_alert_triage runbook...
[SOC1 Agent] Step 1: Gathering alert context...
[SOC1 Agent] Step 2: Checking for duplicates...
[SOC1 Agent] Step 3: Basic enrichment...
...
[SOC1 Agent] Assessment: Suspicious - Escalating to SOC2

[System] Routing to SOC2 Investigation Agent...
[SOC2 Agent] Executing malware_deep_analysis runbook...
...
```

### Example 2: Explicit Agent Selection

**User Request:**
```
"Have SOC2 agent investigate case CASE-001"
```

**System Flow:**
1. User explicitly requests SOC2 agent
2. System calls `execute_as_agent(agent_id="soc2_investigation_agent", case_id="CASE-001")`
3. SOC2 agent reviews case and auto-selects appropriate runbook
4. Agent executes deep investigation

**What User Sees:**
```
> Have SOC2 agent investigate case CASE-001

[SOC2 Agent] Reviewing case CASE-001...
[SOC2 Agent] Selected runbook: malware_deep_analysis
[SOC2 Agent] Executing comprehensive malware analysis...
[SOC2 Agent] Step 1: Comprehensive CTI analysis...
[SOC2 Agent] Step 2: Complete file behavior analysis...
...
```

### Example 3: Manual Runbook Selection

**User Request:**
```
"Execute malware deep analysis on case CASE-001 using SOC2 agent"
```

**System Flow:**
1. User specifies both agent and runbook
2. System calls `execute_as_agent(agent_id="soc2_investigation_agent", case_id="CASE-001", runbook_name="soc2/investigation/malware_deep_analysis")`
3. System verifies agent can execute runbook
4. Agent executes specified runbook

**What User Sees:**
```
> Execute malware deep analysis on case CASE-001 using SOC2 agent

[SOC2 Agent] Verifying runbook authorization...
[SOC2 Agent] Executing malware_deep_analysis runbook...
[SOC2 Agent] Performing comprehensive analysis...
...
```

### Example 4: List Available Agents

**User Request:**
```
"List available agents"
```

**System Flow:**
1. System calls `list_agent_profiles()`
2. Returns all configured agents with their capabilities

**What User Sees:**
```
> List available agents

Available Agents:
1. SOC1 Triage Agent (soc1_triage_agent)
   - Tier: SOC1
   - Capabilities: initial_triage, basic_enrichment
   - Runbooks: 5 available
   - Can: Close FPs, Escalate to SOC2

2. SOC2 Investigation Agent (soc2_investigation_agent)
   - Tier: SOC2
   - Capabilities: deep_investigation, correlation
   - Runbooks: 3 available
   - Can: Close FPs, Escalate to SOC3

3. SOC3 Response Agent (soc3_response_agent)
   - Tier: SOC3
   - Capabilities: incident_response, containment
   - Runbooks: 3 available
   - Can: Execute containment, Collect forensics
```

### Example 5: Check Agent Capabilities

**User Request:**
```
"Show me what SOC1 agent can do"
```

**System Flow:**
1. System calls `get_agent_profile(agent_id="soc1_triage_agent")`
2. Returns detailed profile information

**What User Sees:**
```
> Show me what SOC1 agent can do

SOC1 Triage Agent Profile:
- Tier: SOC1
- Description: Handles initial alert triage and false positive identification
- Capabilities:
  * initial_triage
  * basic_enrichment
  * false_positive_identification

- Available Runbooks:
  1. soc1/triage/initial_alert_triage
  2. soc1/triage/suspicious_login_triage
  3. soc1/triage/malware_initial_triage
  4. soc1/enrichment/ioc_enrichment
  5. soc1/remediation/close_false_positive

- Decision Authority:
  ✓ Can close false positives
  ✓ Can close benign true positives
  ✓ Can escalate to SOC2
  ✗ Cannot escalate to SOC3
  ✗ Cannot execute containment actions
  ✗ Cannot collect forensics

- Auto-selects runbooks: Yes
- Max concurrent cases: 10
```

## Escalation Flow with Agent Profiles

```
New Alert Created
    ↓
route_case_to_agent() → Routes to SOC1 Agent
    ↓
SOC1 Agent executes initial_alert_triage
    ↓
Assessment: Suspicious
    ↓
SOC1 Agent escalates (update_case_status + comment)
    ↓
System detects escalation → route_case_to_agent() → Routes to SOC2 Agent
    ↓
SOC2 Agent executes malware_deep_analysis
    ↓
Assessment: Requires Containment
    ↓
SOC2 Agent escalates to SOC3
    ↓
System detects containment requirement → route_case_to_agent() → Routes to SOC3 Agent
    ↓
SOC3 Agent executes endpoint_isolation
```

## Configuration File Location

**Default:** `config/agent_profiles.json`

You can customize:
- Agent capabilities
- Available runbooks per agent
- Decision authority
- Routing rules
- Max concurrent cases

## Benefits of Agent Profiles Approach

1. **Automatic Routing**: Cases automatically route to appropriate agents
2. **Tier Enforcement**: Agents can only execute runbooks for their tier
3. **Clear Responsibilities**: Each agent has well-defined capabilities
4. **Scalable**: Easy to add new agents or modify existing ones
5. **Multi-Agent Support**: Can run multiple agents simultaneously
6. **Auto-Selection**: Agents automatically select appropriate runbooks

## Comparison: Agent Profiles vs Tool-Based

| Feature | Agent Profiles | Tool-Based |
|---------|---------------|------------|
| **Automatic Routing** | ✅ Yes | ❌ Manual |
| **Tier Enforcement** | ✅ Built-in | ⚠️ Manual |
| **Multi-Agent** | ✅ Yes | ⚠️ Single context |
| **Runbook Selection** | ✅ Auto | ⚠️ Manual |
| **Configuration** | ⚠️ JSON config | ✅ Simple |
| **Flexibility** | ⚠️ Structured | ✅ High |

## Recommendation

**Use Agent Profiles if:**
- You want automatic routing and tier enforcement
- You plan to run multiple agents simultaneously
- You want structured, role-based investigation
- You need clear separation of responsibilities

**Use Tool-Based if:**
- You want maximum flexibility
- You prefer simpler implementation
- You want manual control over runbook selection
- You're using a single agent context

## Implementation Steps

1. Create `config/agent_profiles.json` with agent definitions
2. Implement `AgentProfileManager` class
3. Add agent profile tools to MCP server
4. Test routing and execution
5. Configure agents for your environment
6. Deploy and monitor

