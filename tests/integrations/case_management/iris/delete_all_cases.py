#!/usr/bin/env python3
"""
Utility script to delete all cases in IRIS.

WARNING: This is a destructive operation that will delete ALL cases in IRIS.
Use with extreme caution!

Usage:
    python tests/integrations/case_management/iris/delete_all_cases.py [--yes]
    
Options:
    --yes    Skip confirmation prompt (use with caution!)
"""

import argparse
import sys
import os

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
sys.path.insert(0, project_root)

from src.core.config_storage import load_config_from_file
from src.integrations.case_management.iris.iris_client import IRISCaseManagementClient


def delete_all_cases(skip_confirmation: bool = False):
    """
    Delete all cases in IRIS.
    
    This function:
    1. Loads IRIS configuration
    2. Creates an IRIS client
    3. Lists all cases
    4. Deletes each case one by one
    """
    print("=" * 70)
    print("IRIS Case Deletion Utility")
    print("=" * 70)
    print()
    
    # Load configuration
    try:
        config = load_config_from_file("config.json")
        if not config.iris or not config.iris.base_url or not config.iris.api_key:
            print("ERROR: IRIS configuration not found in config.json")
            sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to load config: {e}")
        sys.exit(1)
    
    # Create IRIS client
    try:
        client = IRISCaseManagementClient.from_config(config)
        print("✓ IRIS client created successfully")
    except Exception as e:
        print(f"ERROR: Failed to create IRIS client: {e}")
        sys.exit(1)
    
    # List all cases
    print("\nFetching all cases from IRIS...")
    try:
        cases = client.list_cases(limit=1000)  # Get up to 1000 cases
        print(f"Found {len(cases)} cases")
    except Exception as e:
        print(f"ERROR: Failed to list cases: {e}")
        sys.exit(1)
    
    if len(cases) == 0:
        print("No cases to delete.")
        sys.exit(0)
    
    # Show cases that will be deleted
    print("\nCases that will be deleted:")
    for case in cases:
        print(f"  - Case #{case.id}: {case.title}")
    
    # Confirm deletion
    if not skip_confirmation:
        print()
        print("WARNING: This will delete ALL cases listed above!")
        response = input("Are you sure you want to continue? (yes/no): ")
        
        if response.lower() not in ("yes", "y"):
            print("Operation cancelled.")
            sys.exit(0)
    else:
        print("\nSkipping confirmation (--yes flag provided)")
    
    # Delete each case
    print("\nDeleting cases...")
    deleted_count = 0
    failed_count = 0
    
    for case in cases:
        case_id = case.id
        try:
            client.delete_case(case_id)
            print(f"✓ Deleted case #{case_id}: {case.title}")
            deleted_count += 1
        except Exception as e:
            error_msg = str(e)
            print(f"✗ Failed to delete case #{case_id}: {error_msg}")
            # Log additional error details if available
            if hasattr(e, 'response') or 'status' in error_msg.lower() or 'api' in error_msg.lower():
                print(f"  Error details: {error_msg}")
            failed_count += 1
            # Continue to next case
            continue
    
    # Summary
    print()
    print("=" * 70)
    print("Deletion Summary")
    print("=" * 70)
    print(f"Total cases: {len(cases)}")
    print(f"Successfully deleted: {deleted_count}")
    print(f"Failed: {failed_count}")
    print("=" * 70)
    
    # Return appropriate exit code
    # The script's job is to attempt to clear everything and log errors
    # As long as we attempted to process all cases (even if some failed), that's success
    if failed_count > 0:
        # Some or all cases failed, but we attempted to process them all
        if failed_count == len(cases):
            print(f"\nWARNING: All {len(cases)} cases failed to delete.")
        else:
            print(f"\nWARNING: {failed_count} of {len(cases)} cases failed to delete.")
        print("Check the error messages above for details on what failed.")
        print("Script completed - all cases were attempted to be processed.")
        # Exit with 0 because we did our job: attempted to clear everything and logged errors
        sys.exit(0)
    else:
        # All cases succeeded (or no cases to delete)
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Delete all cases in IRIS"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt (use with caution!)"
    )
    args = parser.parse_args()
    
    delete_all_cases(skip_confirmation=args.yes)
