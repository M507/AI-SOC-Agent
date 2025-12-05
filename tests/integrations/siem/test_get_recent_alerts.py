#!/usr/bin/env python3
"""
Standalone test script for get_recent_alerts function.
Executes get_recent_alerts and prints the results.
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# Add project root to path
# File is at: tests/integrations/siem/test_get_recent_alerts.py
# Need to go up 4 levels: siem -> integrations -> tests -> project root
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from src.core.config_storage import load_config_from_file
from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient
from src.orchestrator.tools_siem import get_recent_alerts


def list_alert_ids(results: dict, siem_client=None):
    """Extract and return all alert IDs from results."""
    alert_ids = []
    
    # Extract IDs from grouped alerts
    if "groups" in results and results["groups"]:
        for group in results["groups"]:
            group_ids = group.get("alert_ids", [])
            alert_ids.extend(group_ids)
    
    # If we have uninvestigated alerts but no groups, try to get raw alerts
    uninvestigated_count = results.get("uninvestigated_alerts", 0)
    if uninvestigated_count > 0 and len(alert_ids) == 0 and siem_client:
        try:
            # Fetch raw alerts directly to get IDs that couldn't be grouped
            raw_alerts = siem_client.get_security_alerts(
                hours_back=results.get("hours_back", 1),
                max_alerts=results.get("max_alerts", 100),
                status_filter=results.get("status_filter"),
                severity=results.get("severity"),
                hostname=results.get("hostname"),
            )
            for alert in raw_alerts:
                alert_id = alert.get("id")
                if alert_id and alert_id not in alert_ids:
                    alert_ids.append(alert_id)
        except Exception as e:
            print(f"\nWarning: Could not fetch raw alerts for ID listing: {e}")
    
    if alert_ids:
        print("\n" + "="*80)
        print(f"ALL ALERT IDs ({len(alert_ids)} total)")
        print("="*80)
        for alert_id in alert_ids:
            print(alert_id)
        print("="*80)
    else:
        uninvestigated = results.get("uninvestigated_alerts", 0)
        if uninvestigated > 0:
            print(f"\nNo alert IDs found in groups (but {uninvestigated} uninvestigated alerts exist - they may lack titles)")
        else:
            print("\nNo alert IDs found in results")
    
    return alert_ids


def show_sample_alert(alert_id: str, siem_client, show_raw=False):
    """Fetch and display the JSON of a sample alert by ID."""
    if not siem_client:
        print("\nError: SIEM client not available to fetch sample alert")
        return
    
    if not alert_id:
        print("\nError: No alert ID provided for sample")
        return
    
    try:
        print("\n" + "="*80)
        print(f"SAMPLE ALERT JSON (ID: {alert_id})")
        print("="*80)
        alert = siem_client.get_security_alert_by_id(alert_id, include_detections=True)
        print(json.dumps(alert, indent=2, default=str))
        print("="*80)
        
        # If show_raw is True, also show the raw Elasticsearch document
        if show_raw:
            try:
                raw_source = siem_client.get_raw_alert_document(alert_id)
                print("\n" + "="*80)
                print(f"RAW ELASTICSEARCH DOCUMENT (ID: {alert_id})")
                print("="*80)
                print(json.dumps(raw_source, indent=2, default=str))
                print("="*80)
                
                # Show specific title-related fields
                print("\n" + "="*80)
                print("TITLE-RELATED FIELDS INVESTIGATION")
                print("="*80)
                signal = raw_source.get("signal", {})
                rule = signal.get("rule", {}) if isinstance(signal.get("rule"), dict) else {}
                
                print(f"signal.rule.name: {rule.get('name', 'NOT FOUND')}")
                print(f"kibana.alert.rule.name: {raw_source.get('kibana.alert.rule.name', 'NOT FOUND')}")
                print(f"event.reason: {raw_source.get('event', {}).get('reason', 'NOT FOUND')}")
                print(f"signal.rule.id: {rule.get('id', 'NOT FOUND')}")
                print(f"signal.rule.description: {rule.get('description', 'NOT FOUND')}")
                print(f"kibana.alert.rule.description: {raw_source.get('kibana.alert.rule.description', 'NOT FOUND')}")
                
                # Show all keys in signal.rule if it exists
                if rule:
                    print(f"\nsignal.rule keys: {list(rule.keys())}")
                
                # Show all keys starting with 'kibana.alert.rule'
                kibana_rule_keys = [k for k in raw_source.keys() if k.startswith('kibana.alert.rule')]
                if kibana_rule_keys:
                    print(f"\nkibana.alert.rule.* keys: {kibana_rule_keys}")
                
                # Show all top-level keys for reference
                print(f"\nTop-level document keys (first 20): {list(raw_source.keys())[:20]}")
                
                print("="*80)
            except Exception as e:
                print(f"\nWarning: Could not fetch raw document: {e}")
                import traceback
                traceback.print_exc()
    except Exception as e:
        print(f"\nError fetching sample alert {alert_id}: {e}")
        import traceback
        traceback.print_exc()


def print_results(results: dict):
    """Print results in a readable format."""
    print("\n" + "="*80)
    print("GET_RECENT_ALERTS RESULTS")
    print("="*80)
    
    if not results:
        print("No results returned")
        return
    
    # Print success status
    if "success" in results:
        print(f"Success: {results['success']}")
    
    # Print summary statistics
    if "summary" in results:
        summary = results["summary"]
        print(f"\nSummary:")
        print(f"  Total alerts found: {summary.get('total_alerts', 0)}")
        print(f"  Total groups: {summary.get('total_groups', 0)}")
        print(f"  Time range: {summary.get('earliest_time', 'N/A')} to {summary.get('latest_time', 'N/A')}")
    
    # Print alert groups
    if "groups" in results and results["groups"]:
        print(f"\nAlert Groups ({len(results['groups'])}):")
        print("-" * 80)
        for i, group in enumerate(results["groups"], 1):
            print(f"\nGroup {i}:")
            print(f"  Group ID: {group.get('group_id', 'N/A')}")
            print(f"  Title: {group.get('title', 'N/A')}")
            print(f"  Primary Severity: {group.get('primary_severity', 'N/A')}")
            print(f"  Count: {group.get('count', 0)} alerts")
            print(f"  Alert IDs: {', '.join(group.get('alert_ids', [])[:5])}")
            if len(group.get('alert_ids', [])) > 5:
                print(f"    ... and {len(group.get('alert_ids', [])) - 5} more")
            print(f"  Statuses: {', '.join(group.get('statuses', []))}")
            print(f"  Severities: {', '.join(group.get('severities', []))}")
            print(f"  Time range: {group.get('earliest_created_at', 'N/A')} to {group.get('latest_created_at', 'N/A')}")
            
            # Print example alerts
            if "example_alerts" in group and group["example_alerts"]:
                print(f"  Example Alerts ({len(group['example_alerts'])}):")
                for j, alert in enumerate(group["example_alerts"], 1):
                    print(f"    {j}. ID: {alert.get('id', 'N/A')}")
                    print(f"       Title: {alert.get('title', 'N/A')}")
                    print(f"       Severity: {alert.get('severity', 'N/A')}")
                    print(f"       Status: {alert.get('status', 'N/A')}")
                    print(f"       Created: {alert.get('created_at', 'N/A')}")
    else:
        print("\nNo alert groups found")
    
    # Print full JSON if requested or if there are errors
    if "error" in results:
        print(f"\nError: {results['error']}")
    
    # Print full JSON output
    print("\n" + "="*80)
    print("FULL JSON OUTPUT")
    print("="*80)
    print(json.dumps(results, indent=2, default=str))


def main():
    """Execute get_recent_alerts and print results."""
    parser = argparse.ArgumentParser(description="Test get_recent_alerts function")
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all alert IDs found in the results"
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Show the JSON of the last alert ID as a sample"
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Show the raw Elasticsearch document when using --sample (for debugging)"
    )
    args = parser.parse_args()
    
    print("="*80)
    print("GET_RECENT_ALERTS TEST")
    print("="*80)
    print(f"Started at: {datetime.now().isoformat()}")
    
    # Load configuration
    print("\nLoading configuration...")
    try:
        config = load_config_from_file()
        print("✓ Configuration loaded")
    except Exception as e:
        print(f"✗ Failed to load configuration: {e}")
        return 1
    
    # Check if Elastic is configured
    if not config.elastic:
        print("✗ ERROR: Elastic configuration not found")
        print("Please configure Elastic in config.json or .env file")
        return 1
    
    # Initialize Elastic SIEM client
    print("\nInitializing Elastic SIEM client...")
    try:
        siem_client = ElasticSIEMClient.from_config(config)
        print("✓ Elastic SIEM client initialized")
    except Exception as e:
        print(f"✗ Failed to initialize Elastic SIEM client: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Execute get_recent_alerts - Test 1: Without hostname filter
    print("\n" + "="*80)
    print("TEST 1: get_recent_alerts (without hostname filter)")
    print("="*80)
    print("Parameters:")
    print("  hours_back: 1")
    print("  max_alerts: 100")
    
    try:
        results = get_recent_alerts(
            hours_back=1,
            max_alerts=100,
            client=siem_client
        )
        print("✓ get_recent_alerts executed successfully")
        
        # Print results
        print_results(results)
        
        # List alert IDs if --list flag is set
        alert_ids = []
        if args.list or args.sample:
            alert_ids = list_alert_ids(results, siem_client)
        
        # Show sample alert if --sample flag is set
        if args.sample and alert_ids:
            show_sample_alert(alert_ids[-1], siem_client, show_raw=args.raw)
        
    except Exception as e:
        print(f"✗ Failed to execute get_recent_alerts: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Execute get_recent_alerts - Test 2: With hostname filter
    print("\n" + "="*80)
    print("TEST 2: get_recent_alerts (with hostname filter)")
    print("="*80)
    print("Parameters:")
    print("  hours_back: 1")
    print("  max_alerts: 100")
    print("  hostname: win10-stand-alone-test-3")
    
    try:
        results = get_recent_alerts(
            hours_back=1,
            max_alerts=100,
            hostname="win10-stand-alone-test-3",
            client=siem_client
        )
        print("✓ get_recent_alerts executed successfully")
        
        # Print results
        print_results(results)
        
        # List alert IDs if --list flag is set
        alert_ids = []
        if args.list or args.sample:
            alert_ids = list_alert_ids(results, siem_client)
        
        # Show sample alert if --sample flag is set
        if args.sample and alert_ids:
            show_sample_alert(alert_ids[-1], siem_client, show_raw=args.raw)
        
        return 0
    except Exception as e:
        print(f"✗ Failed to execute get_recent_alerts: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

