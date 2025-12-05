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

    def get_starting_runbook(self) -> Optional[str]:
        """
        Get the starting runbook for this agent profile.
        
        Returns:
            Starting runbook path, or None if not defined
        """
        # Starting runbooks are the first/main runbook for each tier
        starting_runbooks = {
            "soc1": "soc1/triage/initial_alert_triage",
            "soc2": "soc2/investigation/case_analysis",
            # SOC3 doesn't have a single starting runbook - it's action-based
        }
        
        if self.tier in starting_runbooks:
            return starting_runbooks[self.tier]
        
        # For SOC3 or other tiers, return first runbook if available
        if self.runbooks:
            return self.runbooks[0]
        
        return None

    def can_execute_runbook(self, runbook_name: str) -> bool:
        """Check if agent can execute a runbook."""
        # Check if runbook is in agent's runbook list
        if runbook_name in self.runbooks:
            return True
        
        # Check if runbook matches agent's tier (includes case-specific runbooks like soc2/cases/malware_deep_analysis)
        if f"/{self.tier}/" in runbook_name:
            return True
        
        # Check case-specific runbooks (e.g., soc2/cases/malware_deep_analysis)
        # Case-specific runbooks are sub-runbooks that can be executed by the same tier
        if f"/{self.tier}/cases/" in runbook_name:
            return True
        
        return False

    def select_runbook_for_alert(self, alert_type: str, alert_details: Dict[str, Any]) -> Optional[str]:
        """
        Auto-select appropriate runbook based on alert type.
        
        For SOC1 and SOC2, returns the starting runbook.
        For SOC3, selects based on required action.
        """
        if not self.auto_select_runbook:
            return None
        
        # For SOC1 and SOC2, use the starting runbook
        if self.tier in ["soc1", "soc2"]:
            return self.get_starting_runbook()
        
        # For SOC3 - select based on required action
        if self.tier == "soc3":
            recommended_actions = alert_details.get("recommended_actions", [])
            if isinstance(recommended_actions, str):
                recommended_actions = [recommended_actions]
            
            if any("isolate" in str(action).lower() for action in recommended_actions):
                return "soc3/response/endpoint_isolation"
            elif any("terminate" in str(action).lower() for action in recommended_actions):
                return "soc3/response/process_termination"
            elif any("forensic" in str(action).lower() for action in recommended_actions):
                return "soc3/forensics/artifact_collection"
            
            # Default: return starting runbook (first runbook)
            return self.get_starting_runbook()
        
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
            # Default to config/agent_profiles.json relative to project root
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            config_path = os.path.join(project_root, "config", "agent_profiles.json")
        
        self.config_path = config_path
        self.profiles: Dict[str, AgentProfile] = {}
        self.routing_rules: Dict[str, str] = {}
        self._load_profiles()
    
    def _load_profiles(self) -> None:
        """Load agent profiles from config file."""
        if not os.path.exists(self.config_path):
            # Create default profiles
            self._create_default_profiles()
            # Save default config
            self._save_default_config()
            return
        
        try:
            with open(self.config_path, "r") as f:
                config = json.load(f)
        except Exception as e:
            raise IntegrationError(f"Failed to load agent profiles config: {e}")
        
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
            description="Handles initial alert triage and false positive identification",
            capabilities=["initial_triage", "basic_enrichment", "false_positive_identification"],
            runbooks=[
                "soc1/triage/initial_alert_triage",
                "soc1/enrichment/ioc_enrichment",
                "soc1/remediation/close_false_positive"
            ],
            decision_authority=DecisionAuthority(
                close_false_positives=True,
                close_benign_true_positives=True,
                escalate_to_soc2=True,
                escalate_to_soc3=False,
                containment_actions=False,
                forensic_collection=False
            ),
            auto_select_runbook=True,
            max_concurrent_cases=10
        )
        self.profiles["soc1_triage_agent"] = soc1_profile
        
        # SOC2 Profile
        soc2_profile = AgentProfile(
            name="SOC2 Investigation Agent",
            tier="soc2",
            description="Performs deep investigation and correlation analysis",
            capabilities=["deep_investigation", "correlation_analysis", "threat_hunting", "containment_recommendations"],
            runbooks=[
                "soc2/investigation/case_analysis"
            ],
            decision_authority=DecisionAuthority(
                close_false_positives=True,
                close_benign_true_positives=True,
                escalate_to_soc2=False,
                escalate_to_soc3=True,
                containment_actions=False,
                forensic_collection=False
            ),
            auto_select_runbook=True,
            max_concurrent_cases=5
        )
        self.profiles["soc2_investigation_agent"] = soc2_profile
        
        # SOC3 Profile
        soc3_profile = AgentProfile(
            name="SOC3 Response Agent",
            tier="soc3",
            description="Executes incident response and containment actions",
            capabilities=["incident_response", "containment_execution", "forensic_collection"],
            runbooks=[
                "soc3/response/endpoint_isolation",
                "soc3/response/process_termination",
                "soc3/forensics/artifact_collection"
            ],
            decision_authority=DecisionAuthority(
                close_false_positives=True,
                close_benign_true_positives=True,
                escalate_to_soc2=False,
                escalate_to_soc3=False,
                containment_actions=True,
                forensic_collection=True
            ),
            auto_select_runbook=True,
            max_concurrent_cases=3
        )
        self.profiles["soc3_response_agent"] = soc3_profile
    
    def _save_default_config(self) -> None:
        """Save default configuration to file."""
        config = {
            "agents": {
                "soc1_triage_agent": {
                    "name": "SOC1 Triage Agent",
                    "tier": "soc1",
                    "description": "Handles initial alert triage and false positive identification",
                    "capabilities": ["initial_triage", "basic_enrichment", "false_positive_identification"],
                    "runbooks": [
                        "soc1/triage/initial_alert_triage",
                        "soc1/enrichment/ioc_enrichment",
                        "soc1/remediation/close_false_positive"
                    ],
                    "case_runbooks": [
                        "soc1/cases/suspicious_login_triage",
                        "soc1/cases/malware_initial_triage"
                    ],
                    "decision_authority": {
                        "close_false_positives": True,
                        "close_benign_true_positives": True,
                        "escalate_to_soc2": True,
                        "escalate_to_soc3": False,
                        "containment_actions": False,
                        "forensic_collection": False
                    },
                    "auto_select_runbook": True,
                    "max_concurrent_cases": 10
                },
                "soc2_investigation_agent": {
                    "name": "SOC2 Investigation Agent",
                    "tier": "soc2",
                    "description": "Performs deep investigation and correlation analysis",
                    "capabilities": ["deep_investigation", "correlation_analysis", "threat_hunting", "containment_recommendations"],
                    "runbooks": [
                        "soc2/investigation/case_analysis"
                    ],
                    "case_runbooks": [
                        "soc2/cases/malware_deep_analysis",
                        "soc2/cases/suspicious_login_investigation"
                    ],
                    "decision_authority": {
                        "close_false_positives": True,
                        "close_benign_true_positives": True,
                        "escalate_to_soc2": False,
                        "escalate_to_soc3": True,
                        "containment_actions": False,
                        "forensic_collection": False
                    },
                    "auto_select_runbook": True,
                    "max_concurrent_cases": 5
                },
                "soc3_response_agent": {
                    "name": "SOC3 Response Agent",
                    "tier": "soc3",
                    "description": "Executes incident response and containment actions",
                    "capabilities": ["incident_response", "containment_execution", "forensic_collection"],
                    "runbooks": [
                        "soc3/response/endpoint_isolation",
                        "soc3/response/process_termination",
                        "soc3/forensics/artifact_collection"
                    ],
                    "decision_authority": {
                        "close_false_positives": True,
                        "close_benign_true_positives": True,
                        "escalate_to_soc2": False,
                        "escalate_to_soc3": False,
                        "containment_actions": True,
                        "forensic_collection": True
                    },
                    "auto_select_runbook": True,
                    "max_concurrent_cases": 3
                }
            },
            "routing_rules": {
                "new_alert": "soc1_triage_agent",
                "review_cases": "soc2_investigation_agent",
                "requires_containment": "soc3_response_agent",
                "forensic_collection": "soc3_response_agent"
            }
        }
        
        # Ensure config directory exists
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        
        with open(self.config_path, "w") as f:
            json.dump(config, f, indent=2)
    
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
                    "containment_actions": profile.decision_authority.containment_actions,
                    "forensic_collection": profile.decision_authority.forensic_collection
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
        # Priority 1: Response actions (SOC3) - containment and forensic collection
        if case_status and "containment" in case_status.lower():
            return self.routing_rules.get("requires_containment", "soc3_response_agent")
        
        if case_status and "forensic" in case_status.lower():
            return self.routing_rules.get("forensic_collection", "soc3_response_agent")
        
        # Priority 2: Case review (SOC2) - SOC2 always starts by reviewing cases
        if case_id:
            return self.routing_rules.get("review_cases", "soc2_investigation_agent")
        
        # Priority 3: New alerts (SOC1) - default for new alerts without cases
        return self.routing_rules.get("new_alert", "soc1_triage_agent")
    
    def get_agent_for_tier(self, tier: str) -> Optional[AgentProfile]:
        """Get agent profile for a specific SOC tier."""
        for profile in self.profiles.values():
            if profile.tier == tier:
                return profile
        return None
    
    def get_starting_runbook_for_tier(self, tier: str) -> Optional[str]:
        """
        Get the starting runbook for a specific SOC tier.
        
        Args:
            tier: SOC tier (soc1, soc2, soc3)
        
        Returns:
            Starting runbook path, or None if not found
        """
        profile = self.get_agent_for_tier(tier)
        if profile:
            return profile.get_starting_runbook()
        return None

