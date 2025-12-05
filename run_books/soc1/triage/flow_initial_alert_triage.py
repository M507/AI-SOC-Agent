#!/usr/bin/env python3
"""
Script to generate execution flow diagram for initial_alert_triage.md runbook.
Creates a parallel investigation flow diagram showing SIEM tools vs Case Management tools.
"""

import re
import os
from pathlib import Path


def parse_runbook(markdown_file):
    """Parse the runbook markdown file to extract workflow steps and decision points."""
    
    with open(markdown_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract workflow steps section
    workflow_match = re.search(r'## Workflow Steps\n(.*?)(?=\n## |$)', content, re.DOTALL)
    if not workflow_match:
        return None
    
    workflow_section = workflow_match.group(1)
    
    # Parse steps - look for "### Step X:" format
    steps = []
    
    lines = workflow_section.split('\n')
    current_step = None
    
    for i, line in enumerate(lines):
        step_header_match = re.match(r'^###\s+Step\s+(\d+):\s*(.+)$', line)
        if step_header_match:
            step_num = step_header_match.group(1)
            step_title = step_header_match.group(2).strip()
            
            if current_step:
                steps.append(current_step)
            
            current_step = {
                'number': step_num,
                'title': step_title,
                'content': ''
            }
        elif current_step:
            if not re.match(r'^###\s+Step\s+\d+:', line):
                if current_step['content']:
                    current_step['content'] += '\n' + line
                else:
                    current_step['content'] = line
    
    if current_step:
        steps.append(current_step)
    
    return steps


def create_parallel_flow(steps, decisions, output_path):
    """Create Parallel Investigation Flow - Shows SIEM tools vs Case Management tools clearly."""
    
    dot_lines = [
        'digraph InitialAlertTriage {',
        '    rankdir=LR;',
        '    node [fontname="Arial", fontsize=9];',
        '    edge [fontname="Arial", fontsize=8];',
        '',
        '    START [label="START\\nGet Recent Alerts", shape=ellipse, style=filled, fillcolor=lightgreen];',
        '',
        '    // Initial sequence',
        '    STEP1 [label="Step 1\\nGet Recent Alerts\\n[SIEM] get_recent_alerts", shape=box, style=rounded, fillcolor=lightblue];',
        '    STEP2 [label="Step 2\\nRetrieve Alert Details\\n[SIEM] get_security_alert_by_id\\nCRITICAL: Examine events field\\n(actual triggering events)", shape=box, style=rounded, fillcolor=lightblue];',
        '    STEP3 [label="Step 3\\nSet Verdict in-progress\\n[SIEM] update_alert_verdict", shape=box, style=rounded, fillcolor=lightblue];',
        '    QUICK_ASSESS [label="Step 4\\nQuick Assessment\\n[KB] kb_list_clients\\n[KB] kb_get_client_infra\\n[SIEM] get_ioc_matches", shape=diamond, style=filled, fillcolor=lightyellow];',
        '',
        '    // Direct closure path with tools',
        '    STEP4_CLOSE [label="Step 4.3\\nDirect Closure Actions\\n[SIEM] add_alert_note\\n[SIEM] update_alert_verdict", shape=box, style=rounded, fillcolor=lightcyan];',
        '',
        '    // Case Strategy',
        '    CASE_STRATEGY [label="Step 5\\nCase Strategy\\n[CM] search_cases\\nPrefer Existing Related Cases\\n(Host/User/Type/Time)", shape=diamond, style=filled, fillcolor=lightyellow];',
        '',
        '    // Exact duplicate path',
        '    STEP5_DUP [label="Step 5.3\\nHandle Exact Duplicate\\n[CM] add_case_comment\\n[SIEM] add_alert_note\\n[SIEM] update_alert_verdict", shape=box, style=rounded, fillcolor=lightpink];',
        '',
        '    // Parallel investigation lanes - SIEM Tools',
        '    subgraph cluster_siem_investigation {',
        '        label="Step 8: Parallel Investigation - SIEM Tools";',
        '        style=filled;',
        '        fillcolor=lightcyan;',
        '        fontsize=11;',
        '',
        '        KB_CHECK [label="Step 8.1\\nKB Verification\\nExtract entities from\\nevents field (Step 2)\\n[KB] kb_list_clients\\n[KB] kb_get_client_infra", shape=box, style=rounded, fillcolor=white];',
        '        IOC_CHECK [label="Step 8.2\\nIOC Check\\n[SIEM] get_ioc_matches", shape=box, style=rounded, fillcolor=white];',
        '        SIEM_SEARCH [label="Step 8.3\\nSIEM Search\\nCRITICAL: Use events from\\nStep 2 first\\n[SIEM] get_siem_event_by_id\\n[SIEM] search_security_events\\n[SIEM] get_network_events\\n[SIEM] get_dns_events\\n[SIEM] get_email_events\\n[SIEM] get_alerts_by_entity\\n[SIEM] get_alerts_by_time_window\\n[SIEM] lookup_entity", shape=box, style=rounded, fillcolor=white];',
        '        ENRICHMENT [label="Step 8.4\\nEntity Enrichment\\n[CTI] lookup_hash_ti\\n[SIEM] get_file_report\\n[SIEM] get_ip_address_report\\n[SIEM] lookup_entity\\n[SIEM] get_ioc_matches", shape=box, style=rounded, fillcolor=white];',
        '        UNCERTAIN_SEARCH [label="Step 8.6\\nFind Uncertain Alerts\\nSame Host Pattern\\n[SIEM] get_all_uncertain_alerts_for_host", shape=box, style=rounded, fillcolor=white];',
        '    }',
        '',
        '    // Case Management investigation',
        '    subgraph cluster_case_mgmt {',
        '        label="Step 8: Case Management Investigation";',
        '        style=filled;',
        '        fillcolor=lightpink;',
        '        fontsize=11;',
        '',
        '        CASE_SEARCH [label="Step 8.5\\nFind & Group Related Cases\\nGroup by Host/User/Threat Type\\n[CM] list_cases\\n[CM] search_cases", shape=box, style=rounded, fillcolor=white];',
        '    }',
        '',
        '    // Convergence point',
        '    CONVERGE [label="Step 8.7\\nConvergence\\nCombine All Results", shape=box, style=rounded, fillcolor=lightgreen];',
        '',
        '    // Assessment and recommendations',
        '    ASSESSMENT [label="Step 9\\nAssessment\\nEvaluate All Results", shape=box, style=rounded, fillcolor=lightpink];',
        '    RECOMMENDATIONS [label="Step 10\\nRecommendations\\n[ENG] list_visibility_recommendations\\n[ENG] create_visibility_recommendation\\n[ENG] add_comment_to_visibility_recommendation", shape=box, style=rounded, fillcolor=lightcyan];',
        '    FINAL_ACTION [label="Step 11\\nFinal Action", shape=diamond, style=filled, fillcolor=lightyellow];',
        '',
        '    // Final action branches with tools',
        '    STEP11_FP [label="Step 11.2\\nIf FP/BTP\\n[SIEM] add_alert_note\\n[CM] add_case_comment (if case)\\n[CM] update_case_status (if case)\\n[SIEM] update_alert_verdict\\n[ENG] list_fine_tuning_recommendations\\n[ENG] create_fine_tuning_recommendation\\n[ENG] add_comment_to_fine_tuning_recommendation", shape=box, style=rounded, fillcolor=lightgreen];',
        '',
        '    STEP11_TP [label="Step 11.3\\nIf Confirmed TP\\nPrefer Existing Case When Related\\n[CM] create_case (if new)\\n[SIEM] add_alert_note\\n[CM] add_case_comment\\n[CM] attach_observable_to_case\\n[CM] update_case_status\\n[SIEM] update_alert_verdict\\n[CM] add_case_task", shape=box, style=rounded, fillcolor=lightcoral];',
        '',
        '    STEP11_TP_UNCERTAIN [label="Step 11.3.0\\nUpdate Related\\nUncertain Alerts\\n(If Any)\\n[SIEM] update_alert_verdict\\n(uncertain -> TP)\\n[SIEM] add_alert_note\\n(Link to case)", shape=diamond, style=filled, fillcolor=lightyellow];',
        '',
        '    STEP11_TP_UPDATE_ALERTS [label="Step 11.3.0\\nUpdate Uncertain Alerts\\nFor each uncertain alert:\\n[SIEM] update_alert_verdict\\n(uncertain -> TP)\\n[SIEM] add_alert_note\\n(Link to Case ${CASE_ID})", shape=box, style=rounded, fillcolor=lightcoral];',
        '',
        '    STEP11_TP_TASKS [label="Step 11.3.1\\nTask Management\\n[CM] list_case_tasks\\n[CM] update_case_task_status\\n(Mark completed tasks)\\n[CM] add_case_task\\n(Add SOC2 tasks based on\\nSOC1 analysis findings)", shape=box, style=rounded, fillcolor=lightcoral];',
        '',
        '    STEP11_UNCERTAIN [label="Step 11.4\\nIf Uncertain\\n[SIEM] add_alert_note\\n[SIEM] update_alert_verdict\\n(verdict=\\"uncertain\\")", shape=box, style=rounded, fillcolor=lightyellow];',
        '',
        '    // Flow',
        '    START -> STEP1;',
        '    STEP1 -> STEP2;',
        '    STEP2 -> END_VERDICT [label="Verdict\\nExists", style=dashed, color=orange, penwidth=2];',
        '    STEP2 -> STEP3 [label="No Verdict"];',
        '    STEP3 -> QUICK_ASSESS;',
        '    QUICK_ASSESS -> STEP4_CLOSE [label="FP/BTP\\nClose Directly", style=dashed, color=green, penwidth=2];',
        '    STEP4_CLOSE -> END_FP_DIRECT;',
        '    QUICK_ASSESS -> CASE_STRATEGY [label="Needs\\nInvestigation"];',
        '    CASE_STRATEGY -> STEP5_DUP [label="Exact\\nDuplicate", style=dashed, color=orange, penwidth=2];',
        '    STEP5_DUP -> END_DUP;',
        '    CASE_STRATEGY -> KB_CHECK [label="Investigate", style=bold];',
        '    CASE_STRATEGY -> IOC_CHECK [label="Investigate", style=bold];',
        '    CASE_STRATEGY -> SIEM_SEARCH [label="Investigate", style=bold];',
        '    CASE_STRATEGY -> ENRICHMENT [label="Investigate", style=bold];',
        '    CASE_STRATEGY -> CASE_SEARCH [label="Investigate", style=bold, color=red];',
        '    CASE_STRATEGY -> UNCERTAIN_SEARCH [label="Investigate", style=bold];',
        '',
        '    // All investigation steps converge',
        '    KB_CHECK -> CONVERGE;',
        '    IOC_CHECK -> CONVERGE;',
        '    SIEM_SEARCH -> CONVERGE;',
        '    ENRICHMENT -> CONVERGE;',
        '    CASE_SEARCH -> CONVERGE;',
        '    UNCERTAIN_SEARCH -> CONVERGE;',
        '',
        '    CONVERGE -> ASSESSMENT;',
        '    ASSESSMENT -> RECOMMENDATIONS;',
        '    RECOMMENDATIONS -> FINAL_ACTION;',
        '',
        '    // Final action branches',
        '    FINAL_ACTION -> STEP11_FP [label="FP/BTP", style=dashed, color=green, penwidth=2];',
        '    FINAL_ACTION -> STEP11_TP [label="TP", style=dashed, color=red, penwidth=2];',
        '    FINAL_ACTION -> STEP11_UNCERTAIN [label="Uncertain", style=dashed, color=orange, penwidth=2];',
        '',
        '    STEP11_FP -> END_CLOSE;',
        '    STEP11_TP -> STEP11_TP_UNCERTAIN;',
        '    STEP11_TP_UNCERTAIN -> STEP11_TP_UPDATE_ALERTS [label="Uncertain\\nAlerts Found", style=dashed, color=orange, penwidth=2];',
        '    STEP11_TP_UNCERTAIN -> STEP11_TP_TASKS [label="No Uncertain\\nAlerts", style=dashed, color=green, penwidth=2];',
        '    STEP11_TP_UPDATE_ALERTS -> STEP11_TP_TASKS;',
        '    STEP11_TP_TASKS -> END_ESCALATE;',
        '    STEP11_UNCERTAIN -> END_UNCERTAIN;',
        '',
        '    // End nodes',
        '    END_VERDICT [label="END\\nAlready Investigated\\n[SIEM] get_security_alert_by_id\\n(check verdict field)", shape=ellipse, style=filled, fillcolor=lightgray];',
        '    END_FP_DIRECT [label="END\\nClosed Directly\\n(No Case)\\n[SIEM] add_alert_note\\n[SIEM] update_alert_verdict\\n[ENG] Recommendations", shape=ellipse, style=filled, fillcolor=lightgreen];',
        '    END_DUP [label="END\\nDuplicate Noted\\n[CM] add_case_comment\\n[SIEM] add_alert_note\\n[SIEM] update_alert_verdict", shape=ellipse, style=filled, fillcolor=lightgreen];',
        '    END_CLOSE [label="END\\nCase Closed\\n[CM] add_case_comment\\n[CM] update_case_status\\n[SIEM] add_alert_note\\n[SIEM] update_alert_verdict", shape=ellipse, style=filled, fillcolor=lightgreen];',
        '    END_ESCALATE [label="END\\nCase Used (Existing or New)\\nEscalated to SOC2\\n[CM] create_case (if needed)\\n[CM] add_case_comment\\n[CM] attach_observable_to_case\\n[CM] update_case_status\\n[CM] add_case_task\\n[CM] list_case_tasks\\n[CM] update_case_task_status\\n[SIEM] add_alert_note\\n[SIEM] update_alert_verdict\\n(Updated related uncertain alerts)", shape=ellipse, style=filled, fillcolor=lightcoral];',
        '    END_UNCERTAIN [label="END\\nUncertain\\nNo Case Created\\n[SIEM] add_alert_note\\n[SIEM] update_alert_verdict\\n(verdict=\\"uncertain\\")", shape=ellipse, style=filled, fillcolor=lightyellow];',
        '',
        '    // Legend',
        '    subgraph cluster_legend {',
        '        label="Legend - Tool Categories";',
        '        style=dashed;',
        '        fillcolor=white;',
        '        fontsize=11;',
        '',
        '        LEGEND_SIEM [label="[SIEM] SIEM Tools\\nInvestigation & Alert Management", shape=box, style=rounded, fillcolor=lightcyan];',
        '        LEGEND_CASE [label="[CM] Case Management Tools\\nCase Operations & Tracking", shape=box, style=rounded, fillcolor=lightpink];',
        '        LEGEND_KB [label="[KB] KB Tools\\nKnowledge Base", shape=box, style=rounded, fillcolor=lightblue];',
        '        LEGEND_CTI [label="[CTI] CTI Tools\\nThreat Intelligence", shape=box, style=rounded, fillcolor=lightyellow];',
        '        LEGEND_ENG [label="[ENG] Engineering Tools\\nRecommendations", shape=box, style=rounded, fillcolor=lightgreen];',
        '        LEGEND_DECISION [label="Decision Point", shape=diamond, style=filled, fillcolor=lightyellow];',
        '',
        '        LEGEND_SIEM -> LEGEND_CASE [style=invis];',
        '        LEGEND_CASE -> LEGEND_KB [style=invis];',
        '        LEGEND_KB -> LEGEND_CTI [style=invis];',
        '        LEGEND_CTI -> LEGEND_ENG [style=invis];',
        '        LEGEND_ENG -> LEGEND_DECISION [style=invis];',
        '    }',
        '}',
    ]
    
    dot_content = '\n'.join(dot_lines)
    dot_file = os.path.join(output_path, 'initial_alert_triage.dot')
    with open(dot_file, 'w', encoding='utf-8') as f:
        f.write(dot_content)
    
    return dot_file


def generate_svg(dot_file, output_path):
    """Generate SVG file from DOT file using graphviz."""
    
    try:
        import subprocess
        
        svg_file = dot_file.replace('.dot', '.svg')
        result = subprocess.run(
            ['dot', '-Tsvg', '-o', svg_file, dot_file],
            capture_output=True,
            text=True,
            check=True
        )
        
        print(f"✓ SVG file generated: {svg_file}")
        return svg_file
    except subprocess.CalledProcessError as e:
        print(f"✗ Error generating SVG: {e.stderr}")
        return None
    except FileNotFoundError:
        print("✗ Graphviz 'dot' command not found.")
        return None


def main():
    """Main function to generate parallel investigation flow diagram."""
    
    script_dir = Path(__file__).parent
    runbook_file = script_dir / 'initial_alert_triage.md'
    output_dir = Path(__file__).parent.parent.parent.parent / 'execution_flow'
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Reading runbook: {runbook_file}")
    
    if not runbook_file.exists():
        print(f"✗ Error: Runbook file not found: {runbook_file}")
        return 1
    
    # Parse runbook
    steps = parse_runbook(runbook_file)
    if not steps:
        # Do not fail hard here: the current flow diagram is largely static and
        # not dependent on successfully parsing individual workflow steps.
        # Continue and generate the diagram using the predefined flow instead.
        print("! Warning: Could not parse workflow steps from runbook; continuing with static flow definition\n")
        steps = []
    
    print(f"✓ Parsed {len(steps)} workflow steps (0 is OK for static flow)\n")
    
    # Generate parallel flow
    print("=" * 60)
    print("Generating Parallel Investigation Flow")
    print("=" * 60)
    print("\nFlow Design:")
    print("  - Shows parallel investigation activities")
    print("  - Clearly distinguishes SIEM tools vs Case Management tools")
    print("  - Horizontal layout emphasizes parallel processing")
    print("  - All investigation activities converge to assessment\n")
    
    parallel_dot = create_parallel_flow(steps, {}, output_dir)
    print(f"✓ Created: {parallel_dot}")
    parallel_svg = generate_svg(parallel_dot, output_dir)
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"\nFlow diagram generated:")
    print(f"  - DOT: {parallel_dot}")
    if parallel_svg:
        print(f"  - SVG: {parallel_svg}")
    
    print("\n" + "=" * 60)
    print("Key Features:")
    print("=" * 60)
    print("\n1. Parallel Investigation:")
    print("   - KB Verification (KB tools)")
    print("   - IOC Check (SIEM tools)")
    print("   - SIEM Search (SIEM tools)")
    print("   - Entity Enrichment (CTI + SIEM tools)")
    print("   - Case Search (Case Management tools)")
    print("\n2. Tool Categories:")
    print("   - SIEM Tools: Investigation and data gathering")
    print("   - Case Management Tools: Case operations and tracking")
    print("\n3. Convergence:")
    print("   - All parallel activities converge to Assessment")
    print("   - Assessment leads to Final Action (Case Management)")
    
    return 0


if __name__ == '__main__':
    exit(main())
