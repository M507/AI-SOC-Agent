#!/usr/bin/env python3
"""
Standalone test script for list_cases function.
Executes list_cases and prints the results.
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
# File is at: tests/integrations/case_management/iris/test_list_cases.py
# Need to go up 5 levels: iris -> case_management -> integrations -> tests -> project root
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from src.core.config_storage import load_config_from_file
from src.integrations.case_management.iris.iris_client import IRISCaseManagementClient
from src.orchestrator.tools_case import list_cases


def print_results(results: dict):
    """Print results in a readable format."""
    print("\n" + "="*80)
    print("LIST_CASES RESULTS")
    print("="*80)
    
    if not results:
        print("No results returned")
        return
    
    # Print success status
    if "success" in results:
        print(f"Success: {results['success']}")
    
    # Print count
    if "count" in results:
        print(f"\nTotal cases found: {results['count']} (demo case ID 1 automatically excluded)")
    
    # Print cases
    if "cases" in results and results["cases"]:
        print(f"\nCases ({len(results['cases'])}):")
        print("-" * 80)
        for i, case in enumerate(results["cases"], 1):
            print(f"\nCase {i}:")
            print(f"  ID: {case.get('id', 'N/A')}")
            print(f"  Title: {case.get('title', 'N/A')}")
            print(f"  Status: {case.get('status', 'N/A')}")
            print(f"  Priority: {case.get('priority', 'N/A')}")
            print(f"  Assignee: {case.get('assignee', 'N/A')}")
            print(f"  Created: {case.get('created_at', 'N/A')}")
    else:
        print("\nNo cases found")
    
    # Print error if present
    if "error" in results:
        print(f"\nError: {results['error']}")
    
    # Print full JSON output
    print("\n" + "="*80)
    print("FULL JSON OUTPUT")
    print("="*80)
    print(json.dumps(results, indent=2, default=str))


def main():
    """Execute list_cases and print results."""
    print("="*80)
    print("LIST_CASES TEST")
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
    
    # Check if IRIS is configured
    if not config.iris:
        print("✗ ERROR: IRIS configuration not found")
        print("Please configure IRIS in config.json or .env file")
        return 1
    
    # Initialize IRIS case management client
    print("\nInitializing IRIS case management client...")
    try:
        case_client = IRISCaseManagementClient.from_config(config)
        print("✓ IRIS case management client initialized")
    except Exception as e:
        print(f"✗ Failed to initialize IRIS case management client: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Execute list_cases with different parameters
    test_cases = [
        {"status": None, "limit": 50, "description": "All cases (no filter)"},
        {"status": "open", "limit": 50, "description": "Open cases only"},
        {"status": "in_progress", "limit": 50, "description": "In-progress cases only"},
        {"status": "closed", "limit": 20, "description": "Closed cases (limit 20)"},
    ]
    
    for test_case in test_cases:
        status = test_case["status"]
        limit = test_case["limit"]
        description = test_case["description"]
        
        print(f"\n{'='*80}")
        print(f"Executing list_cases: {description}")
        print(f"Parameters:")
        print(f"  status: {status if status else 'None (all statuses)'}")
        print(f"  limit: {limit}")
        print(f"{'='*80}")
        
        try:
            results = list_cases(
                status=status,
                limit=limit,
                client=case_client
            )
            print("✓ list_cases executed successfully")
            
            # Print results
            print_results(results)
            
        except Exception as e:
            print(f"✗ Failed to execute list_cases: {e}")
            import traceback
            traceback.print_exc()
            return 1
    
    print("\n" + "="*80)
    print("ALL TESTS COMPLETED")
    print("="*80)
    return 0


if __name__ == "__main__":
    sys.exit(main())

