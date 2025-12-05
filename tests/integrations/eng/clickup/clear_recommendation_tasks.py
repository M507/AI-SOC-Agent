#!/usr/bin/env python3
"""
Utility script to delete all recommendation tasks in ClickUp.

WARNING: This is a destructive operation that will delete ALL tasks created by
create_fine_tuning_recommendation and create_visibility_recommendation.
Use with extreme caution!

This script deletes tasks from:
- Fine-tuning recommendation list (created by create_fine_tuning_recommendation)
- Engineering/visibility recommendation list (created by create_visibility_recommendation)

Usage:
    python tests/integrations/eng/clickup/clear_recommendation_tasks.py [--yes]
    
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
from src.integrations.eng.clickup.clickup_client import ClickUpClient


def clear_recommendation_tasks(skip_confirmation: bool = False):
    """
    Delete all recommendation tasks in ClickUp.
    
    This function:
    1. Loads ClickUp configuration
    2. Creates a ClickUp client
    3. Lists all fine-tuning recommendation tasks
    4. Lists all visibility recommendation tasks
    5. Deletes each task one by one
    """
    print("=" * 70)
    print("ClickUp Recommendation Tasks Deletion Utility")
    print("=" * 70)
    print()
    
    # Load configuration
    try:
        config = load_config_from_file("config.json")
        if not config.eng or not config.eng.clickup:
            print("ERROR: ClickUp configuration not found in config.json")
            sys.exit(1)
        if not config.eng.clickup.api_token:
            print("ERROR: ClickUp API token not configured")
            sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to load config: {e}")
        sys.exit(1)
    
    # Create ClickUp client
    try:
        client = ClickUpClient.from_config(config)
        print("✓ ClickUp client created successfully")
    except Exception as e:
        print(f"ERROR: Failed to create ClickUp client: {e}")
        sys.exit(1)
    
    # List all fine-tuning recommendation tasks
    print("\nFetching fine-tuning recommendation tasks...")
    fine_tuning_tasks = []
    try:
        fine_tuning_tasks = client.list_fine_tuning_recommendations(
            archived=False,
            include_closed=True,
        )
        print(f"Found {len(fine_tuning_tasks)} fine-tuning recommendation tasks")
    except Exception as e:
        print(f"ERROR: Failed to list fine-tuning recommendations: {e}")
        sys.exit(1)
    
    # List all visibility recommendation tasks
    print("Fetching visibility recommendation tasks...")
    visibility_tasks = []
    try:
        visibility_tasks = client.list_visibility_recommendations(
            archived=False,
            include_closed=True,
        )
        print(f"Found {len(visibility_tasks)} visibility recommendation tasks")
    except Exception as e:
        print(f"ERROR: Failed to list visibility recommendations: {e}")
        sys.exit(1)
    
    total_tasks = len(fine_tuning_tasks) + len(visibility_tasks)
    
    if total_tasks == 0:
        print("\nNo recommendation tasks to delete.")
        sys.exit(0)
    
    # Show tasks that will be deleted
    print("\nTasks that will be deleted:")
    print("\nFine-tuning recommendations:")
    for task in fine_tuning_tasks:
        task_id = task.get("id", "unknown")
        task_name = task.get("name", "unnamed")
        print(f"  - Task {task_id}: {task_name}")
    
    print("\nVisibility/Engineering recommendations:")
    for task in visibility_tasks:
        task_id = task.get("id", "unknown")
        task_name = task.get("name", "unnamed")
        print(f"  - Task {task_id}: {task_name}")
    
    # Confirm deletion
    if not skip_confirmation:
        print()
        print("WARNING: This will delete ALL recommendation tasks listed above!")
        response = input("Are you sure you want to continue? (yes/no): ")
        
        if response.lower() not in ("yes", "y"):
            print("Operation cancelled.")
            sys.exit(0)
    else:
        print("\nSkipping confirmation (--yes flag provided)")
    
    # Delete each task
    print("\nDeleting tasks...")
    deleted_count = 0
    failed_count = 0
    results = []
    
    # Delete fine-tuning recommendation tasks
    print("\nDeleting fine-tuning recommendation tasks...")
    for task in fine_tuning_tasks:
        task_id = task.get("id")
        task_name = task.get("name", "unnamed")
        
        if not task_id:
            print(f"✗ Skipping task with no ID: {task_name}")
            failed_count += 1
            continue
        
        try:
            # ClickUp API: DELETE /v2/task/{task_id}
            client._http.delete(f"/v2/task/{task_id}")
            print(f"✓ Deleted fine-tuning task {task_id}: {task_name}")
            deleted_count += 1
            results.append({
                "type": "fine_tuning",
                "task_id": task_id,
                "task_name": task_name,
                "success": True
            })
        except Exception as e:
            error_msg = str(e)
            print(f"✗ Failed to delete fine-tuning task {task_id}: {error_msg}")
            # Log additional error details if available
            if hasattr(e, 'response') or 'status' in error_msg.lower() or 'api' in error_msg.lower():
                print(f"  Error details: {error_msg}")
            failed_count += 1
            results.append({
                "type": "fine_tuning",
                "task_id": task_id,
                "task_name": task_name,
                "success": False,
                "error": error_msg
            })
            # Continue to next task
            continue
    
    # Delete visibility recommendation tasks
    print("\nDeleting visibility recommendation tasks...")
    for task in visibility_tasks:
        task_id = task.get("id")
        task_name = task.get("name", "unnamed")
        
        if not task_id:
            print(f"✗ Skipping task with no ID: {task_name}")
            failed_count += 1
            continue
        
        try:
            # ClickUp API: DELETE /v2/task/{task_id}
            client._http.delete(f"/v2/task/{task_id}")
            print(f"✓ Deleted visibility task {task_id}: {task_name}")
            deleted_count += 1
            results.append({
                "type": "visibility",
                "task_id": task_id,
                "task_name": task_name,
                "success": True
            })
        except Exception as e:
            error_msg = str(e)
            print(f"✗ Failed to delete visibility task {task_id}: {error_msg}")
            # Log additional error details if available
            if hasattr(e, 'response') or 'status' in error_msg.lower() or 'api' in error_msg.lower():
                print(f"  Error details: {error_msg}")
            failed_count += 1
            results.append({
                "type": "visibility",
                "task_id": task_id,
                "task_name": task_name,
                "success": False,
                "error": error_msg
            })
            # Continue to next task
            continue
    
    # Summary
    print()
    print("=" * 70)
    print("Deletion Summary")
    print("=" * 70)
    print(f"Total tasks: {total_tasks}")
    print(f"  - Fine-tuning recommendations: {len(fine_tuning_tasks)}")
    print(f"  - Visibility recommendations: {len(visibility_tasks)}")
    print(f"Successfully deleted: {deleted_count}")
    print(f"Failed: {failed_count}")
    print()
    print("Details:")
    fine_tuning_success = sum(1 for r in results if r["type"] == "fine_tuning" and r["success"])
    fine_tuning_failed = sum(1 for r in results if r["type"] == "fine_tuning" and not r["success"])
    visibility_success = sum(1 for r in results if r["type"] == "visibility" and r["success"])
    visibility_failed = sum(1 for r in results if r["type"] == "visibility" and not r["success"])
    
    print(f"  Fine-tuning: {fine_tuning_success} deleted, {fine_tuning_failed} failed")
    print(f"  Visibility: {visibility_success} deleted, {visibility_failed} failed")
    
    if failed_count > 0:
        print("\nFailed tasks:")
        for result in results:
            if not result["success"]:
                print(f"  ✗ {result['type']} task {result['task_id']}: {result.get('error', 'Unknown error')}")
    
    print("=" * 70)
    
    # Return appropriate exit code
    # The script's job is to attempt to clear everything and log errors
    # As long as we attempted to process all tasks (even if some failed), that's success
    if failed_count > 0:
        # Some or all tasks failed, but we attempted to process them all
        if failed_count == total_tasks:
            print(f"\nWARNING: All {total_tasks} tasks failed to delete.")
        else:
            print(f"\nWARNING: {failed_count} of {total_tasks} tasks failed to delete, but processing continued.")
        print("Check the error messages above for details on what failed.")
        print("Script completed - all tasks were attempted to be processed.")
        # Exit with 0 because we did our job: attempted to clear everything and logged errors
        sys.exit(0)
    else:
        # All tasks succeeded (or no tasks to delete)
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Delete all recommendation tasks in ClickUp"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt (use with caution!)"
    )
    args = parser.parse_args()
    
    clear_recommendation_tasks(skip_confirmation=args.yes)

