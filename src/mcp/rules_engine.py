"""
Rules engine for executing investigation workflows.

This module provides a rules engine that can chain together multiple
investigation skills to perform automated investigations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..api.case_management import CaseManagementClient
from ..api.edr import EDRClient
from ..api.siem import SIEMClient
from ..core.errors import IntegrationError
from ..orchestrator import incident_workflow


@dataclass
class Rule:
    """
    Represents an investigation rule/workflow.
    """

    name: str
    description: Optional[str] = None
    trigger: Optional[str] = None  # Condition that triggers the rule
    actions: List[str] = None  # type: ignore
    enabled: bool = True

    def __post_init__(self):
        if self.actions is None:
            self.actions = []


@dataclass
class RuleExecutionContext:
    """
    Execution context for a rule, containing variables and state.
    """

    rule_name: str
    variables: Dict[str, Any]
    results: Dict[str, Any]

    def __init__(self, rule_name: str):
        self.rule_name = rule_name
        self.variables = {}
        self.results = {}


class RulesEngine:
    """
    Engine for executing investigation rules/workflows.
    """

    def __init__(
        self,
        case_client: Optional[CaseManagementClient] = None,
        siem_client: Optional[SIEMClient] = None,
        edr_client: Optional[EDRClient] = None,
    ):
        """
        Initialize the rules engine with clients.

        Args:
            case_client: Case management client.
            siem_client: SIEM client.
            edr_client: EDR client.
        """
        self.case_client = case_client
        self.siem_client = siem_client
        self.edr_client = edr_client
        self.rules: Dict[str, Rule] = {}

    def load_rule(self, rule_dict: Dict[str, Any]) -> Rule:
        """
        Load a rule from a dictionary.

        Args:
            rule_dict: Dictionary containing rule definition.

        Returns:
            Rule object.

        Raises:
            IntegrationError: If rule definition is invalid.
        """
        try:
            rule = Rule(
                name=rule_dict["name"],
                description=rule_dict.get("description"),
                trigger=rule_dict.get("trigger"),
                actions=rule_dict.get("actions", []),
                enabled=rule_dict.get("enabled", True),
            )
            return rule
        except KeyError as e:
            raise IntegrationError(f"Invalid rule definition: missing {e}") from e

    def add_rule(self, rule: Rule) -> None:
        """
        Add a rule to the engine.

        Args:
            rule: Rule to add.
        """
        self.rules[rule.name] = rule

    def list_rules(self) -> List[Dict[str, Any]]:
        """
        List all registered rules.

        Returns:
            List of rule metadata dictionaries.
        """
        return [
            {
                "name": rule.name,
                "description": rule.description,
                "enabled": rule.enabled,
                "action_count": len(rule.actions),
            }
            for rule in self.rules.values()
        ]

    def execute_rule(
        self,
        rule_name: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a rule by name.

        Args:
            rule_name: Name of the rule to execute.
            context: Optional context variables to pass to the rule.

        Returns:
            Dictionary containing execution results.

        Raises:
            IntegrationError: If rule not found or execution fails.
        """
        if rule_name not in self.rules:
            raise IntegrationError(f"Rule not found: {rule_name}")

        rule = self.rules[rule_name]
        if not rule.enabled:
            raise IntegrationError(f"Rule is disabled: {rule_name}")

        # Create execution context
        exec_context = RuleExecutionContext(rule_name)
        if context:
            exec_context.variables.update(context)

        # Check trigger condition if present
        if rule.trigger:
            if not self._evaluate_trigger(rule.trigger, exec_context):
                # Return a human-readable explanation that the rule was not executed
                message = (
                    f"Automated rule '{rule_name}' was **not executed** because the "
                    f"trigger condition was not met.\n\n"
                    f"- Trigger condition: `{rule.trigger}`\n"
                    f"- Context variables at evaluation time: "
                    f"{json.dumps(exec_context.variables, default=str)}\n\n"
                    "You can adjust the context variables or the trigger condition and "
                    "call `execute_rule` again if you want this workflow to run."
                )
                return {
                    "success": False,
                    "rule_name": rule_name,
                    "summary": message,
                    "details": {
                        "reason": "trigger_not_met",
                        "trigger": rule.trigger,
                        "context": exec_context.variables,
                    },
                }

        # Execute actions and capture low-level results
        results: List[Dict[str, Any]] = []
        for action in rule.actions:
            try:
                result = self._execute_action(action, exec_context)
                results.append({"action": action, "success": True, "result": result})
            except Exception as e:
                results.append(
                    {
                        "action": action,
                        "success": False,
                        "error": str(e),
                    }
                )
                # Optionally continue or stop on error
                # For now, we'll continue but log the error

        # Build an AI-friendly, playbook-style narrative around the execution
        narrative = self._format_execution_narrative(
            rule=rule,
            exec_context=exec_context,
            results=results,
        )

        # Return both the human-readable narrative and the structured data
        return {
            "success": True,
            "rule_name": rule_name,
            "playbook": narrative,
            "summary": narrative.split("\n\n")[0] if "\n\n" in narrative else narrative,
            "actions": results,
            "final_context": exec_context.variables,
        }

    def _evaluate_trigger(self, trigger: str, context: RuleExecutionContext) -> bool:
        """
        Evaluate a trigger condition.

        Args:
            trigger: Trigger condition string.
            context: Execution context.

        Returns:
            True if trigger condition is met, False otherwise.
        """
        # Simple trigger evaluation - can be extended with more sophisticated logic
        # For now, support simple variable comparisons
        try:
            # Replace variables in trigger with values from context
            evaluated = trigger
            for key, value in context.variables.items():
                evaluated = evaluated.replace(f"${key}", str(value))
                evaluated = evaluated.replace(f"{{key}}", str(value))

            # Simple evaluation (can be made more sophisticated)
            # For now, just check if it's a boolean expression
            return eval(evaluated, {"__builtins__": {}}, {})
        except Exception:
            # If evaluation fails, assume trigger is not met
            return False

    def _execute_action(self, action: str, context: RuleExecutionContext) -> Any:
        """
        Execute a single action.

        Args:
            action: Action name or action definition.
            context: Execution context.

        Returns:
            Action result.
        """
        # Parse action (can be a string name or a dict with parameters)
        if isinstance(action, dict):
            action_name = action.get("name") or action.get("action")
            action_params = action.get("params", {})
        else:
            action_name = action
            action_params = {}

        # Map action names to functions
        action_map = {
            "create_case_from_alert": self._create_case_from_alert,
            "search_siem_for_related_events": self._search_siem_for_related_events,
            "enrich_case_from_siem": self._enrich_case_from_siem,
            "enrich_case_from_edr": self._enrich_case_from_edr,
            "close_incident": self._close_incident,
            "assign_case": self._assign_case,
        }

        if action_name not in action_map:
            raise IntegrationError(f"Unknown action: {action_name}")

        # Execute the action
        return action_map[action_name](action_params, context)

    def _format_execution_narrative(
        self,
        rule: Rule,
        exec_context: RuleExecutionContext,
        results: List[Dict[str, Any]],
    ) -> str:
        """
        Build a human-readable, playbook-style narrative of a rule execution.

        This is optimized for MCP/LLM usage: it reads like a mini runbook the
        AI agent can follow, while still reflecting the concrete actions taken
        and their outcomes.
        """

        lines: List[str] = []

        # Header / objective
        lines.append(f"Automated investigation rule executed: **{rule.name}**")
        if rule.description:
            lines.append(f"Description: {rule.description}")

        # Context snapshot
        if exec_context.variables:
            lines.append("")
            lines.append("Initial context provided to this workflow:")
            for key, value in exec_context.variables.items():
                try:
                    encoded = json.dumps(value, default=str)
                except TypeError:
                    encoded = str(value)
                # Keep very long values readable by truncating
                if len(encoded) > 300:
                    encoded = encoded[:297] + "..."
                lines.append(f"- **{key}**: {encoded}")

        # Executed steps
        lines.append("")
        lines.append("Execution steps and outcomes:")
        if not results:
            lines.append("- No actions were defined for this rule.")
        else:
            for idx, step in enumerate(results, start=1):
                action = step.get("action")
                success = step.get("success", False)
                status = "SUCCESS" if success else "FAILED"

                # Map internal action names to friendly labels
                friendly_names = {
                    "create_case_from_alert": "Create case from alert",
                    "search_siem_for_related_events": "Search SIEM for related events",
                    "enrich_case_from_siem": "Enrich case with SIEM data",
                    "enrich_case_from_edr": "Enrich case with EDR data",
                    "close_incident": "Close incident in case management",
                    "assign_case": "Assign case to analyst",
                }
                friendly_action = friendly_names.get(str(action), str(action))

                lines.append(f"{idx}. **{friendly_action}** — {status}")

                if success and "result" in step:
                    result = step["result"]
                    if isinstance(result, dict):
                        for k, v in result.items():
                            try:
                                v_str = json.dumps(v, default=str)
                            except TypeError:
                                v_str = str(v)
                            if len(v_str) > 200:
                                v_str = v_str[:197] + "..."
                            lines.append(f"   - {k}: {v_str}")
                    else:
                        lines.append(f"   - Result: {result}")
                elif not success:
                    error = step.get("error", "Unknown error")
                    lines.append(f"   - Error: {error}")

        # Final state / follow-up guidance
        lines.append("")
        lines.append("Final investigation state and guidance for the AI agent:")

        # Highlight a few commonly important context variables if present
        key_hints = []
        if "case_id" in exec_context.variables:
            key_hints.append(
                f"- Review and continue work on case **{exec_context.variables['case_id']}** "
                "in the case management system."
            )
        if "siem_search_results" in exec_context.variables:
            key_hints.append(
                "- Use the stored `siem_search_results` (in context) to reason about "
                "related events, time ranges, and entities."
            )

        if key_hints:
            lines.extend(key_hints)
        else:
            lines.append(
                "- Use the context variables and step outcomes above to decide on the "
                "next manual investigation or response actions."
            )

        lines.append(
            "- Treat this output as a high-level playbook: you can reference the "
            "steps and their results when planning further tool calls."
        )

        return "\n".join(lines)

    def _create_case_from_alert(
        self, params: Dict[str, Any], context: RuleExecutionContext
    ) -> Any:
        """Create a case from an alert."""
        if not self.case_client:
            raise IntegrationError("Case management client not configured")
        if not self.siem_client:
            raise IntegrationError("SIEM client not configured")

        # This would need the actual alert object - simplified for now
        # In practice, you'd get the alert from context or params
        raise IntegrationError("create_case_from_alert requires alert object")

    def _search_siem_for_related_events(
        self, params: Dict[str, Any], context: RuleExecutionContext
    ) -> Any:
        """Search SIEM for related events."""
        if not self.siem_client:
            raise IntegrationError("SIEM client not configured")

        query = params.get("query") or context.variables.get("search_query", "")
        limit = params.get("limit", 100)

        result = self.siem_client.search_security_events(query=query, limit=limit)
        context.variables["siem_search_results"] = result
        return {"event_count": len(result.events), "total_count": result.total_count}

    def _enrich_case_from_siem(
        self, params: Dict[str, Any], context: RuleExecutionContext
    ) -> Any:
        """Enrich a case from SIEM data."""
        if not self.case_client:
            raise IntegrationError("Case management client not configured")
        if not self.siem_client:
            raise IntegrationError("SIEM client not configured")

        case_id = params.get("case_id") or context.variables.get("case_id")
        if not case_id:
            raise IntegrationError("case_id required for enrich_case_from_siem")

        observables = incident_workflow.enrich_case_from_siem(
            case_id=case_id,
            case_client=self.case_client,
            siem_client=self.siem_client,
        )
        return {"observables_added": len(observables)}

    def _enrich_case_from_edr(
        self, params: Dict[str, Any], context: RuleExecutionContext
    ) -> Any:
        """Enrich a case from EDR data."""
        if not self.case_client:
            raise IntegrationError("Case management client not configured")
        if not self.edr_client:
            raise IntegrationError("EDR client not configured")

        case_id = params.get("case_id") or context.variables.get("case_id")
        endpoint_id = params.get("endpoint_id")

        observables = incident_workflow.enrich_case_from_edr(
            case_id=case_id,
            case_client=self.case_client,
            edr_client=self.edr_client,
            endpoint_id=endpoint_id,
        )
        return {"observables_added": len(observables)}

    def _close_incident(
        self, params: Dict[str, Any], context: RuleExecutionContext
    ) -> Any:
        """Close an incident."""
        if not self.case_client:
            raise IntegrationError("Case management client not configured")

        case_id = params.get("case_id") or context.variables.get("case_id")
        if not case_id:
            raise IntegrationError("case_id required for close_incident")

        resolution_notes = params.get("resolution_notes")
        case = incident_workflow.close_incident(
            case_id=case_id,
            case_client=self.case_client,
            resolution_notes=resolution_notes,
        )
        return {"case_id": case.id, "status": case.status.value}

    def _assign_case(
        self, params: Dict[str, Any], context: RuleExecutionContext
    ) -> Any:
        """Assign a case to an analyst."""
        if not self.case_client:
            raise IntegrationError("Case management client not configured")

        case_id = params.get("case_id") or context.variables.get("case_id")
        assignee = params.get("assignee")
        if not case_id or not assignee:
            raise IntegrationError("case_id and assignee required for assign_case")

        assignment = self.case_client.assign_case(case_id, assignee)
        return {"case_id": assignment.case_id, "assignee": assignment.assignee}

