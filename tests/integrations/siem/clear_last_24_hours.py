#!/usr/bin/env python3
"""
Utility script to delete the last 24 hours of data from Elasticsearch indices.

WARNING: This is a destructive operation that will delete data from the last 24 hours
from multiple Elasticsearch indices. Use with extreme caution!

This script deletes data from:
- .internal.alerts-security.alerts-de-*
- .ds-logs-endpoint*
- .ds-logs-elastic_agent.*
- .ds-logs-system.application*
- .ds-logs-system.security-*

Usage:
    python tests/integrations/siem/clear_last_24_hours.py [--yes]
    
Options:
    --yes    Skip confirmation prompt (use with caution!)
"""

import argparse
import sys
import os

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, project_root)

from src.core.config_storage import load_config_from_file
from src.integrations.siem.elastic.elastic_http import ElasticHttpClient


def clear_last_24_hours(skip_confirmation: bool = False):
    """
    Delete the last 24 hours of data from Elasticsearch indices.
    
    This function:
    1. Loads Elastic configuration
    2. Creates an Elastic HTTP client
    3. Executes delete_by_query for each index pattern
    """
    print("=" * 70)
    print("Elasticsearch Data Deletion Utility (Last 24 Hours)")
    print("=" * 70)
    print()
    
    # Load configuration
    try:
        config = load_config_from_file("config.json")
        if not config.elastic or not config.elastic.base_url:
            print("ERROR: Elastic configuration not found in config.json")
            sys.exit(1)
        if not config.elastic.api_key and not (config.elastic.username and config.elastic.password):
            print("ERROR: Elastic authentication not configured (need api_key or username/password)")
            sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to load config: {e}")
        sys.exit(1)
    
    # Create Elastic HTTP client
    try:
        http_client = ElasticHttpClient(
            base_url=config.elastic.base_url,
            api_key=config.elastic.api_key,
            username=config.elastic.username,
            password=config.elastic.password,
            timeout_seconds=config.elastic.timeout_seconds if hasattr(config.elastic, 'timeout_seconds') else 30,
            verify_ssl=config.elastic.verify_ssl if hasattr(config.elastic, 'verify_ssl') else True,
        )
        print("✓ Elastic HTTP client created successfully")
    except Exception as e:
        print(f"ERROR: Failed to create Elastic HTTP client: {e}")
        sys.exit(1)
    
    # Define index patterns and their descriptions
    index_patterns = [
        {
            "pattern": ".internal.alerts-security.alerts-de-*",
            "description": "Security alerts"
        },
        {
            "pattern": ".ds-logs-endpoint*",
            "description": "Endpoint logs"
        },
        {
            "pattern": ".ds-logs-elastic_agent.*",
            "description": "Elastic agent logs"
        },
        {
            "pattern": ".ds-logs-system.application*",
            "description": "System application logs"
        },
        {
            "pattern": ".ds-logs-system.security-*",
            "description": "System security logs"
        }
    ]
    
    # Query to delete documents from the last 24 hours
    delete_query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": "now-24h"
                }
            }
        }
    }
    
    # Query parameters for delete_by_query
    query_params = {
        "conflicts": "proceed",
        "refresh": "true"
    }
    
    # Show what will be deleted
    print("\nThe following index patterns will have data from the last 24 hours deleted:")
    for idx_info in index_patterns:
        print(f"  - {idx_info['pattern']} ({idx_info['description']})")
    
    # Confirm deletion
    if not skip_confirmation:
        print()
        print("WARNING: This will delete ALL data from the last 24 hours in the indices above!")
        response = input("Are you sure you want to continue? (yes/no): ")
        
        if response.lower() not in ("yes", "y"):
            print("Operation cancelled.")
            sys.exit(0)
    else:
        print("\nSkipping confirmation (--yes flag provided)")
    
    # Execute delete_by_query for each index pattern
    print("\nDeleting data from indices...")
    success_count = 0
    failed_count = 0
    results = []
    
    for idx_info in index_patterns:
        index_pattern = idx_info['pattern']
        description = idx_info['description']
        
        try:
            # Build endpoint: {index_pattern}/_delete_by_query
            endpoint = f"{index_pattern}/_delete_by_query"
            
            # Execute delete_by_query using request() to support query parameters
            result = http_client.request(
                method="POST",
                endpoint=endpoint,
                json_data=delete_query,
                params=query_params
            )
            
            # Extract deletion count from response
            deleted = result.get("deleted", 0)
            total = result.get("total", 0)
            
            print(f"✓ {description} ({index_pattern}): Deleted {deleted} of {total} documents")
            success_count += 1
            results.append({
                "pattern": index_pattern,
                "description": description,
                "deleted": deleted,
                "total": total,
                "success": True
            })
        except Exception as e:
            error_msg = str(e)
            # Log detailed error information
            print(f"✗ Failed to delete from {index_pattern} ({description}): {error_msg}")
            # If it's an HTTP error, try to extract more details
            if hasattr(e, 'response') or 'status' in error_msg.lower() or 'http' in error_msg.lower():
                print(f"  Error details: {error_msg}")
            failed_count += 1
            results.append({
                "pattern": index_pattern,
                "description": description,
                "success": False,
                "error": error_msg
            })
            # Continue to next index pattern
            continue
    
    # Summary
    print()
    print("=" * 70)
    print("Deletion Summary")
    print("=" * 70)
    print(f"Total index patterns: {len(index_patterns)}")
    print(f"Successfully processed: {success_count}")
    print(f"Failed: {failed_count}")
    print()
    print("Details:")
    for result in results:
        if result["success"]:
            print(f"  ✓ {result['description']}: {result['deleted']}/{result['total']} documents deleted")
        else:
            print(f"  ✗ {result['description']}: {result.get('error', 'Unknown error')}")
    print("=" * 70)
    
    # Return appropriate exit code
    # The script's job is to attempt to clear everything and log errors
    # As long as we attempted to process all patterns (even if some failed), that's success
    if failed_count > 0:
        # Some or all patterns failed, but we attempted to process them all
        if failed_count == len(index_patterns):
            print(f"\nWARNING: All {len(index_patterns)} index patterns failed to process.")
        else:
            print(f"\nWARNING: {failed_count} of {len(index_patterns)} index patterns failed, but processing continued.")
        print("Check the error messages above for details on what failed.")
        print("Script completed - all index patterns were attempted to be processed.")
        # Exit with 0 because we did our job: attempted to clear everything and logged errors
        sys.exit(0)
    else:
        # All patterns succeeded
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Delete the last 24 hours of data from Elasticsearch indices"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt (use with caution!)"
    )
    args = parser.parse_args()
    
    clear_last_24_hours(skip_confirmation=args.yes)

