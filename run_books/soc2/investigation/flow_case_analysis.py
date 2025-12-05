#!/usr/bin/env python3
"""
Script to generate execution flow diagram for case_analysis.md runbook.
Creates a comprehensive SOC2 investigation flow diagram emphasizing deep SIEM analysis.
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
    
    # Parse steps - look for numbered list format
    steps = []
    
    lines = workflow_section.split('\n')
    current_step = None
    
    for i, line in enumerate(lines):
        step_header_match = re.match(r'^(\d+)\.\s+\*\*(.+?)\*\*', line)
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
            if not re.match(r'^\d+\.\s+\*\*', line):
                if current_step['content']:
                    current_step['content'] += '\n' + line
                else:
                    current_step['content'] = line
    
    if current_step:
        steps.append(current_step)
    
    return steps


def create_soc2_flow(steps, decisions, output_path):
    """Create SOC2 Deep Investigation Flow - Emphasizes advanced SIEM analysis and comprehensive investigation."""
    
    dot_lines = [
        'digraph SOC2CaseAnalysis {',
        '    rankdir=TB;',
        '    node [fontname="Arial", fontsize=9];',
        '    edge [fontname="Arial", fontsize=8];',
        '',
        '    START [label="START\\nSOC2 Case Analysis\\n[CM] review_case\\n(case_id=${CASE_ID})", shape=ellipse, style=filled, fillcolor=lightgreen];',
        '',
        '    // Initial case review',
        '    STEP1 [label="Step 1\\nReview Case\\n[CM] review_case\\nRead ALL case details\\nExtract alert details\\nStore in ${CASE_CONTEXT}", shape=box, style=rounded, fillcolor=lightblue];',
        '',
        '    STEP2 [label="Step 2\\nReview Tasks & Timeline\\n[CM] list_case_tasks\\n[CM] list_case_timeline_events\\nIdentify pending tasks", shape=box, style=rounded, fillcolor=lightblue];',
        '',
        '    STEP3 [label="Step 3\\nComplete Pending Tasks\\n[CM] update_case_task_status\\n(in_progress -> completed)\\nPerform analysis\\n[CM] add_case_comment\\nDocument findings\\nMark completed", shape=box, style=rounded, fillcolor=lightcyan];',
        '',
        '    STEP4 [label="Step 4\\nInitial Case Assessment\\nAnalyze case data\\nDetermine threat type\\nIdentify analysis gaps\\nDecide on case-specific runbooks", shape=diamond, style=filled, fillcolor=lightyellow];',
        '',
        '    // Deep SIEM Analysis - SOC2 Core Strength',
        '    subgraph cluster_deep_siem {',
        '        label="Step 5: Deep SIEM Analysis (SOC2 Core)";',
        '        style=filled;',
        '        fillcolor=lightcoral;',
        '        fontsize=12;',
        '        fontweight=bold;',
        '',
        '        SIEM_KQL [label="Advanced KQL Queries\\n[SIEM] search_kql_query\\nComplex Elastic queries\\nCross-index searches\\nTime-based analysis (7-30 days)\\nAggregations, joins\\nField-level analysis", shape=box, style=rounded, fillcolor=white];',
        '        SIEM_PIVOT [label="Entity Pivoting\\n[SIEM] pivot_on_indicator\\nPivot on ALL entities\\nHosts, users, IPs, domains\\nHashes, processes, registry\\nPorts, timelines", shape=box, style=rounded, fillcolor=white];',
        '        SIEM_SEARCH [label="Security Event Search\\n[SIEM] search_security_events\\nDeep event analysis\\nPattern detection", shape=box, style=rounded, fillcolor=white];',
        '        SIEM_NETWORK [label="Network Deep Analysis\\n[SIEM] get_network_events\\nFull traffic analysis\\nConnection patterns\\nData transfer analysis\\nC2 detection", shape=box, style=rounded, fillcolor=white];',
        '        SIEM_DNS [label="DNS Deep Analysis\\n[SIEM] get_dns_events\\nQuery patterns\\nDomain resolution\\nC2 detection\\nDGA identification", shape=box, style=rounded, fillcolor=white];',
        '        SIEM_EMAIL [label="Email Deep Analysis\\n[SIEM] get_email_events\\nPhishing patterns\\nAttachment analysis\\nHeader analysis\\nCampaign correlation", shape=box, style=rounded, fillcolor=white];',
        '        SIEM_ALERT_CORR [label="Alert Correlation\\n[SIEM] get_alerts_by_entity\\n[SIEM] get_alerts_by_time_window\\n[SIEM] get_security_alert_by_id\\nMulti-alert correlation\\nExtended time windows", shape=box, style=rounded, fillcolor=white];',
        '    }',
        '',
        '    // CTI and Enrichment',
        '    subgraph cluster_cti_enrichment {',
        '        label="Step 6: CTI & Entity Enrichment";',
        '        style=filled;',
        '        fillcolor=lightyellow;',
        '        fontsize=11;',
        '',
        '        CTI_HASH [label="Hash Enrichment\\n[CTI] lookup_hash_ti\\n[CTI] get_file_report\\n[CTI] get_file_behavior_summary\\n[CTI] get_entities_related_to_file\\n[SIEM] get_ioc_matches", shape=box, style=rounded, fillcolor=white];',
        '        CTI_IP [label="IP Enrichment\\n[CTI] get_ip_address_report\\n[SIEM] lookup_entity\\n[SIEM] get_ioc_matches", shape=box, style=rounded, fillcolor=white];',
        '        CTI_DOMAIN [label="Domain Enrichment\\n[SIEM] lookup_entity\\n[CTI] get_threat_intel\\n[SIEM] get_ioc_matches", shape=box, style=rounded, fillcolor=white];',
        '        CTI_USER [label="User Activity\\n[SIEM] search_user_activity\\n[SIEM] lookup_entity\\nAccount analysis", shape=box, style=rounded, fillcolor=white];',
        '        CTI_THREAT [label="Threat Intelligence\\n[CTI] get_threat_intel\\nThreat actors\\nCampaigns\\nTTPs\\nHistorical data", shape=box, style=rounded, fillcolor=white];',
        '    }',
        '',
        '    // KB Verification',
        '    STEP7 [label="Step 7\\nClient Infrastructure\\n[KB] kb_get_client_infra\\nVerify entities\\nUnderstand attack scope", shape=box, style=rounded, fillcolor=lightcyan];',
        '',
        '    // Correlation',
        '    STEP8 [label="Step 8\\nCorrelation Analysis\\n[CM] link_cases\\n[SIEM] get_security_alert_by_id\\n[SIEM] get_alerts_by_entity\\nEvidence-based connections", shape=box, style=rounded, fillcolor=lightpink];',
        '',
        '    // Attack Chain',
        '    STEP9 [label="Step 9\\nAttack Chain Reconstruction\\nMap to MITRE ATT&CK\\nReconstruct lifecycle\\nDocument attack chain", shape=box, style=rounded, fillcolor=lightcoral];',
        '',
        '    // Timeline Events',
        '    STEP10 [label="Step 10\\nAdd Timeline Events\\n[CM] add_case_timeline_event\\nAdd ALL events chronologically\\nFrom SIEM, CTI, Correlation\\nAttack chain stages\\nLink to IOCs/Assets", shape=box, style=rounded, fillcolor=lightyellow];',
        '',
        '    // IOCs, Assets, Notes, Evidences, Tasks',
        '    STEP11 [label="Step 11\\nAdd IOCs, Assets, Notes\\nEvidences, Tasks\\n[CM] attach_observable_to_case\\n(hashes, IPs, domains, URLs)\\n[CM] add_case_asset\\n(endpoints, servers, users)\\n[CM] add_case_comment\\n[CM] add_case_evidence\\n[CM] add_case_task\\n(AI + Human tasks)", shape=box, style=rounded, fillcolor=lightpink];',
        '',
        '    // Containment',
        '    STEP12 [label="Step 12\\nContainment Recommendations\\n[CM] add_case_task\\n(SOC3 containment task)\\nEndpoint isolation\\nProcess termination\\nNetwork blocking\\nForensic priorities", shape=box, style=rounded, fillcolor=lightgreen];',
        '',
        '    // Final Update',
        '    STEP13 [label="Step 13\\nFinal Case Update\\n[CM] update_case_status\\n(Update status & priority)\\n[CM] add_case_comment\\n(Investigation summary)\\n[CM] attach_observable_to_case\\n[CM] add_case_asset\\nReady for SOC3 escalation", shape=box, style=rounded, fillcolor=lightblue];',
        '',
        '    END [label="END\\nCase Ready for SOC3\\nAll tasks completed\\nComprehensive documentation", shape=ellipse, style=filled, fillcolor=lightgreen];',
        '',
        '    // Flow',
        '    START -> STEP1;',
        '    STEP1 -> STEP2;',
        '    STEP2 -> STEP3;',
        '    STEP3 -> STEP4;',
        '    STEP4 -> SIEM_KQL [label="Deep Investigation", style=bold, color=red, penwidth=2];',
        '    STEP4 -> SIEM_PIVOT [label="Deep Investigation", style=bold, color=red, penwidth=2];',
        '    STEP4 -> SIEM_SEARCH [label="Deep Investigation", style=bold, color=red, penwidth=2];',
        '    STEP4 -> SIEM_NETWORK [label="Deep Investigation", style=bold, color=red, penwidth=2];',
        '    STEP4 -> SIEM_DNS [label="Deep Investigation", style=bold, color=red, penwidth=2];',
        '    STEP4 -> SIEM_EMAIL [label="Deep Investigation", style=bold, color=red, penwidth=2];',
        '    STEP4 -> SIEM_ALERT_CORR [label="Deep Investigation", style=bold, color=red, penwidth=2];',
        '',
        '    // SIEM analysis converges',
        '    SIEM_KQL -> CTI_HASH;',
        '    SIEM_PIVOT -> CTI_HASH;',
        '    SIEM_SEARCH -> CTI_HASH;',
        '    SIEM_NETWORK -> CTI_IP;',
        '    SIEM_DNS -> CTI_DOMAIN;',
        '    SIEM_EMAIL -> CTI_DOMAIN;',
        '    SIEM_ALERT_CORR -> CTI_THREAT;',
        '',
        '    // CTI enrichment converges',
        '    CTI_HASH -> STEP7;',
        '    CTI_IP -> STEP7;',
        '    CTI_DOMAIN -> STEP7;',
        '    CTI_USER -> STEP7;',
        '    CTI_THREAT -> STEP7;',
        '',
        '    STEP7 -> STEP8;',
        '    STEP8 -> STEP9;',
        '    STEP9 -> STEP10;',
        '    STEP10 -> STEP11;',
        '    STEP11 -> STEP12;',
        '    STEP12 -> STEP13;',
        '    STEP13 -> END;',
        '',
        '    // Legend',
        '    subgraph cluster_legend {',
        '        label="Legend - Tool Categories";',
        '        style=dashed;',
        '        fillcolor=white;',
        '        fontsize=11;',
        '',
        '        LEGEND_SIEM [label="[SIEM] SIEM Tools\\nAdvanced Elastic Querying\\nDeep Event Analysis", shape=box, style=rounded, fillcolor=lightcoral];',
        '        LEGEND_CASE [label="[CM] Case Management Tools\\nCase Operations & Tracking", shape=box, style=rounded, fillcolor=lightpink];',
        '        LEGEND_CTI [label="[CTI] CTI Tools\\nThreat Intelligence", shape=box, style=rounded, fillcolor=lightyellow];',
        '        LEGEND_KB [label="[KB] KB Tools\\nKnowledge Base", shape=box, style=rounded, fillcolor=lightcyan];',
        '',
        '        LEGEND_SIEM -> LEGEND_CASE [style=invis];',
        '        LEGEND_CASE -> LEGEND_CTI [style=invis];',
        '        LEGEND_CTI -> LEGEND_KB [style=invis];',
        '    }',
        '}',
    ]
    
    dot_content = '\n'.join(dot_lines)
    dot_file = os.path.join(output_path, 'case_analysis.dot')
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
    """Main function to generate SOC2 case analysis flow diagram."""
    
    script_dir = Path(__file__).parent
    runbook_file = script_dir / 'case_analysis.md'
    output_dir = Path(__file__).parent.parent.parent.parent / 'execution_flow'
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Reading runbook: {runbook_file}")
    
    if not runbook_file.exists():
        print(f"✗ Error: Runbook file not found: {runbook_file}")
        return 1
    
    # Parse runbook
    steps = parse_runbook(runbook_file)
    if not steps:
        print("✗ Error: Could not parse workflow steps from runbook")
        return 1
    
    print(f"✓ Parsed {len(steps)} workflow steps\n")
    
    # Generate flow
    print("=" * 60)
    print("Generating SOC2 Deep Investigation Flow")
    print("=" * 60)
    print("\nFlow Design:")
    print("  - Emphasizes deep SIEM analysis (SOC2 core strength)")
    print("  - Shows advanced Elastic querying capabilities")
    print("  - Comprehensive investigation beyond SOC1 scope")
    print("  - Parallel SIEM analysis activities\n")
    
    flow_dot = create_soc2_flow(steps, {}, output_dir)
    print(f"✓ Created: {flow_dot}")
    flow_svg = generate_svg(flow_dot, output_dir)
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"\nFlow diagram generated:")
    print(f"  - DOT: {flow_dot}")
    if flow_svg:
        print(f"  - SVG: {flow_svg}")
    
    print("\n" + "=" * 60)
    print("Key Features:")
    print("=" * 60)
    print("\n1. Deep SIEM Analysis (SOC2 Core):")
    print("   - Advanced KQL queries (Elastic)")
    print("   - Entity pivoting on all indicators")
    print("   - Network, DNS, Email deep analysis")
    print("   - Alert correlation")
    print("\n2. Comprehensive Investigation:")
    print("   - CTI enrichment for all entities")
    print("   - Attack chain reconstruction")
    print("   - Multi-case correlation")
    print("\n3. SOC2 Advantages Over SOC1:")
    print("   - Deep Elastic querying (not basic searches)")
    print("   - Comprehensive entity pivoting")
    print("   - Advanced correlation and analysis")
    print("   - Attack chain reconstruction")
    
    return 0


if __name__ == '__main__':
    exit(main())

