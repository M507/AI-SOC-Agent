#!/usr/bin/env python3
"""
Script to generate an execution flow diagram for agent profiles defined in
`config/agent_profiles.json` (as used by `agent_profiles.py`).

The script creates Graphviz DOT and SVG files that visualize:
- The overall Agent Profile Manager
- Each agent profile, grouped by SOC tier
- Each agent's starting runbook and additional runbooks
- Case-specific sub-runbooks that can be called from starting runbooks
- Routing rules that map events/states to specific agents
- Example CLI output so an AI can easily understand how the script behaves

Output files are written to the top-level `execution_flow/` directory:
- `execution_flow/agent_profiles_flow.dot`
- `execution_flow/agent_profiles_flow.svg`
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, Any, List


def get_project_root() -> Path:
    """Return the project root based on this file location."""
    # This file lives at: <project_root>/src/mcp/flow_agent_profiles.py
    return Path(__file__).resolve().parents[2]


def load_agent_profiles_config() -> Dict[str, Any]:
    """
    Load the agent profiles configuration.

    This mirrors the default behavior of `AgentProfileManager`:
    - If `config/agent_profiles.json` exists, load it.
    - Otherwise, fall back to the baked-in default configuration.
    """
    project_root = get_project_root()
    config_path = project_root / "config" / "agent_profiles.json"

    if config_path.exists():
        import json

        with config_path.open("r", encoding="utf-8") as f:
            config = json.load(f)

        return config

    # Fallback: mirror `_save_default_config` from `agent_profiles.py`
    return {
        "agents": {
            "soc1_triage_agent": {
                "name": "SOC1 Triage Agent",
                "tier": "soc1",
                "description": "Handles initial alert triage and false positive identification",
                "capabilities": [
                    "initial_triage",
                    "basic_enrichment",
                    "false_positive_identification",
                ],
                "runbooks": [
                    "soc1/triage/initial_alert_triage",
                    "soc1/enrichment/ioc_enrichment",
                    "soc1/remediation/close_false_positive",
                ],
                "case_runbooks": [
                    "soc1/cases/suspicious_login_triage",
                    "soc1/cases/malware_initial_triage",
                ],
                "decision_authority": {
                    "close_false_positives": True,
                    "close_benign_true_positives": True,
                    "escalate_to_soc2": True,
                    "escalate_to_soc3": False,
                    "containment_actions": False,
                    "forensic_collection": False,
                },
                "auto_select_runbook": True,
                "max_concurrent_cases": 10,
            },
            "soc2_investigation_agent": {
                "name": "SOC2 Investigation Agent",
                "tier": "soc2",
                "description": "Performs deep investigation and correlation analysis",
                "capabilities": [
                    "deep_investigation",
                    "correlation_analysis",
                    "threat_hunting",
                    "containment_recommendations",
                ],
                "runbooks": [
                    "soc2/investigation/case_analysis",
                ],
                "case_runbooks": [
                    "soc2/cases/malware_deep_analysis",
                    "soc2/cases/suspicious_login_investigation",
                ],
                "decision_authority": {
                    "close_false_positives": True,
                    "close_benign_true_positives": True,
                    "escalate_to_soc2": False,
                    "escalate_to_soc3": True,
                    "containment_actions": False,
                    "forensic_collection": False,
                },
                "auto_select_runbook": True,
                "max_concurrent_cases": 5,
            },
            "soc3_response_agent": {
                "name": "SOC3 Response Agent",
                "tier": "soc3",
                "description": "Executes incident response and containment actions",
                "capabilities": [
                    "incident_response",
                    "containment_execution",
                    "forensic_collection",
                ],
                "runbooks": [
                    "soc3/response/endpoint_isolation",
                    "soc3/response/process_termination",
                    "soc3/forensics/artifact_collection",
                ],
                "decision_authority": {
                    "close_false_positives": True,
                    "close_benign_true_positives": True,
                    "escalate_to_soc2": False,
                    "escalate_to_soc3": False,
                    "containment_actions": True,
                    "forensic_collection": True,
                },
                "auto_select_runbook": True,
                "max_concurrent_cases": 3,
            },
        },
        "routing_rules": {
            "new_alert": "soc1_triage_agent",
            "review_cases": "soc2_investigation_agent",
            "requires_containment": "soc3_response_agent",
            "forensic_collection": "soc3_response_agent",
        },
    }


def sanitize_id(prefix: str, value: str) -> str:
    """Return a Graphviz-safe node ID based on a prefix and raw value."""
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", value)
    return f"{prefix}_{safe}"


def build_example_output_lines(
    output_dir: Path, dot_file: Path, svg_file: Path, config_source: str
) -> List[str]:
    """
    Build example CLI output lines to embed in the DOT/SVG for AI consumption.

    These are examples of what the script prints when run, not necessarily an
    exact capture of any particular execution.
    """
    rel_output_dir = os.path.relpath(str(output_dir), str(get_project_root()))
    rel_dot = os.path.relpath(str(dot_file), str(get_project_root()))
    rel_svg = os.path.relpath(str(svg_file), str(get_project_root()))

    return [
        "python src/mcp/flow_agent_profiles.py",
        f"Reading agent profiles config from: {config_source}",
        "✓ Loaded 3 agent profiles",
        "✓ Loaded 4 routing rules",
        f"Generating DOT and SVG in: {rel_output_dir}",
        f"✓ DOT file created: {rel_dot}",
        f"✓ SVG file created: {rel_svg}",
        "✓ Agent profiles flow diagram generation complete!",
    ]


def create_dot_file(config: Dict[str, Any], output_dir: Path) -> Path:
    """Create a Graphviz DOT file that visualizes the agent profiles flow."""
    agents = config.get("agents", {})
    routing_rules = config.get("routing_rules", {})

    dot_file = output_dir / "agent_profiles_flow.dot"
    svg_file = output_dir / "agent_profiles_flow.svg"

    # Determine where config came from (for example output text)
    project_root = get_project_root()
    real_config_path = project_root / "config" / "agent_profiles.json"
    if real_config_path.exists():
        config_source = os.path.relpath(str(real_config_path), str(project_root))
    else:
        config_source = "<default in code (no config/agent_profiles.json found)>"

    example_output_lines = build_example_output_lines(
        output_dir=output_dir,
        dot_file=dot_file,
        svg_file=svg_file,
        config_source=config_source,
    )

    dot_lines: List[str] = [
        "digraph AgentProfilesFlow {",
        '    rankdir=LR;',
        '    node [shape=box, style=rounded, fontname="Arial"];',
        '    edge [fontname="Arial"];',
        "",
        "    // Agent Profile Manager entry point",
        '    manager [label="AgentProfileManager\\n(loads config, routes cases)", '
        'shape=ellipse, style=filled, fillcolor=lightgreen];',
        "",
        "    // Example CLI output for AI understanding of this script",
    ]

    # Embed example CLI output as comments (these are preserved in the DOT and SVG)
    for line in example_output_lines:
        dot_lines.append(f"    // {line}")

    dot_lines.extend(
        [
            "",
            "    // Also expose example CLI output as a dedicated node for visualization",
        ]
    )
    example_label = "\\n".join(example_output_lines).replace('"', '\\"')
    dot_lines.extend(
        [
            "    subgraph cluster_example_output {",
            '        label="Example CLI Output (for AI)";',
            "        style=dashed;",
            "        color=gray;",
            '        fontname="Arial";',
            f'        example_output [shape=note, style=filled, fillcolor=lightgray, '
            f'fontname="Courier New", label="{example_label}"];',
            "    }",
            "",
            "    // Agent profiles grouped by SOC tier",
        ]
    )

    # Group agents by tier and create nodes
    tier_colors = {
        "soc1": "lightblue",
        "soc2": "lightyellow",
        "soc3": "lightcoral",
    }

    agent_node_ids: Dict[str, str] = {}

    for agent_id, agent_cfg in agents.items():
        tier = agent_cfg.get("tier", "unknown")
        color = tier_colors.get(tier, "white")
        name = agent_cfg.get("name", agent_id)
        description = agent_cfg.get("description", "")
        runbooks = agent_cfg.get("runbooks", [])

        label_lines = [
            f"{agent_id}",
            f"{name}",
            f"[{tier.upper()}]",
        ]
        if description:
            label_lines.append(description)
        label = "\\n".join(label_lines).replace('"', '\\"')

        node_id = sanitize_id("agent", agent_id)
        agent_node_ids[agent_id] = node_id

        dot_lines.append(
            f'    {node_id} [label="{label}", style=filled, fillcolor={color}];'
        )
        dot_lines.append(f"    manager -> {node_id};")

        # Main runbooks as separate nodes (connected directly to agent)
        for rb in runbooks:
            rb_id = sanitize_id("runbook", rb)
            rb_label = rb.replace('"', '\\"')
            dot_lines.append(
                f'    {rb_id} [label="{rb_label}", shape=note, style=filled, '
                f'fillcolor=white];'
            )
            dot_lines.append(f"    {node_id} -> {rb_id};")

        # Case runbooks as sub-runbooks (connected to main runbooks, shown with different style)
        case_runbooks = agent_cfg.get("case_runbooks", [])
        if case_runbooks:
            # For SOC1, case runbooks connect to initial_alert_triage (the starting runbook)
            # For SOC2, case runbooks connect to case_analysis (the starting runbook)
            main_runbook_id = None
            if tier == "soc1":
                # Find initial_alert_triage runbook (SOC1 starting runbook)
                for rb in runbooks:
                    if "initial_alert_triage" in rb:
                        main_runbook_id = sanitize_id("runbook", rb)
                        break
            elif tier == "soc2":
                # Find case_analysis runbook (SOC2 starting runbook)
                for rb in runbooks:
                    if "case_analysis" in rb:
                        main_runbook_id = sanitize_id("runbook", rb)
                        break
            
            if main_runbook_id:
                for case_rb in case_runbooks:
                    case_rb_id = sanitize_id("case_runbook", case_rb)
                    case_rb_label = case_rb.replace('"', '\\"')
                    # Show case runbooks with different style (smaller, different color)
                    dot_lines.append(
                        f'    {case_rb_id} [label="{case_rb_label}", shape=note, '
                        f'style=filled, fillcolor=lightcyan, fontsize=10];'
                    )
                    # Connect case runbook to main runbook with dashed line to show hierarchy
                    dot_lines.append(
                        f"    {main_runbook_id} -> {case_rb_id} [style=dashed, color=gray, "
                        f'label="can call"];'
                    )

        dot_lines.append("")  # spacing between agents

    # Routing rules section
    if routing_rules:
        dot_lines.append("    // Routing rules -> agents")
        for rule_name, target_agent in routing_rules.items():
            rule_id = sanitize_id("route", rule_name)
            rule_label = rule_name.replace("_", " ").title().replace('"', '\\"')
            dot_lines.append(
                f'    {rule_id} [label="Routing Rule\\n{rule_label}", '
                f'shape=diamond, style=filled, fillcolor=lightgray];'
            )
            dot_lines.append(f"    manager -> {rule_id};")

            target_node = agent_node_ids.get(target_agent)
            if target_node:
                dot_lines.append(f"    {rule_id} -> {target_node};")
            else:
                # Fallback if config references an unknown agent
                unknown_id = sanitize_id("agent_missing", target_agent)
                dot_lines.append(
                    f'    {unknown_id} [label="Missing Agent\\n{target_agent}", '
                    f'shape=box, style=filled, fillcolor=red];'
                )
                dot_lines.append(f"    {rule_id} -> {unknown_id};")

    dot_lines.append("}")

    dot_file.write_text("\n".join(dot_lines), encoding="utf-8")
    return dot_file


def generate_svg(dot_file: Path, output_dir: Path) -> Path | None:
    """Generate an SVG file from a DOT file using Graphviz."""
    svg_file = output_dir / "agent_profiles_flow.svg"

    try:
        subprocess.run(
            ["dot", "-Tsvg", "-o", str(svg_file), str(dot_file)],
            capture_output=True,
            text=True,
            check=True,
        )
        print(f"✓ SVG file generated: {svg_file}")
        return svg_file
    except subprocess.CalledProcessError as e:
        print(f"✗ Error generating SVG: {e.stderr}")
        print(
            "Make sure Graphviz is installed: "
            "brew install graphviz (macOS) or apt-get install graphviz (Linux)"
        )
        return None
    except FileNotFoundError:
        print("✗ Graphviz 'dot' command not found.")
        print(
            "Install Graphviz: "
            "brew install graphviz (macOS) or apt-get install graphviz (Linux)"
        )
        return None


def main() -> int:
    """Main entry point to generate the agent profiles flow diagram."""
    project_root = get_project_root()
    output_dir = project_root / "execution_flow"
    output_dir.mkdir(parents=True, exist_ok=True)

    config_path = project_root / "config" / "agent_profiles.json"
    if config_path.exists():
        print(f"Reading agent profiles config: {config_path}")
    else:
        print(
            "No config/agent_profiles.json found – using default in-code profiles "
            "(as defined in src/mcp/agent_profiles.py)."
        )

    config = load_agent_profiles_config()
    agents = config.get("agents", {})
    routing_rules = config.get("routing_rules", {})

    print(f"✓ Loaded {len(agents)} agent profiles")
    print(f"✓ Loaded {len(routing_rules)} routing rules")
    print(f"Generating DOT and SVG files in: {output_dir}")

    dot_file = create_dot_file(config, output_dir)
    print(f"✓ DOT file created: {dot_file}")

    svg_file = generate_svg(dot_file, output_dir)

    if svg_file:
        print("\n✓ Agent profiles flow diagram generation complete!")
        print(f"  - DOT file: {dot_file}")
        print(f"  - SVG file: {svg_file}")
        return 0

    print(
        "\n⚠ DOT file created but SVG generation failed. "
        "You can manually convert it using:"
    )
    print(f"  dot -Tsvg {dot_file} -o {output_dir / 'agent_profiles_flow.svg'}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())


