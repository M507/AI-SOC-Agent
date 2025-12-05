"""
Test script for ClickUp client.

Tests the following operations:
1. create_fine_tuning_recommendation() - creates cards on the fine-tuning board
2. create_visibility_recommendation() - creates cards on the engineering board
3. list_fine_tuning_recommendations() - lists tasks on the fine-tuning board
4. list_visibility_recommendations() - lists tasks on the engineering board
5. add_comment_to_fine_tuning_recommendation() - adds comment to a fine-tuning task
6. add_comment_to_visibility_recommendation() - adds comment to a visibility task

All operations use the Python functions directly from src/integrations/eng/clickup/*
"""

import os
import sys

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../.."))
sys.path.insert(0, project_root)

from src.core.config_storage import load_config_from_file
from src.integrations.eng.clickup.clickup_client import ClickUpClient


def main():
    """Run all test operations."""
    print("=" * 70)
    print("ClickUp Client Test")
    print("=" * 70)
    
    # Load configuration
    try:
        config = load_config_from_file("config.json")
        if not config.eng or not config.eng.clickup:
            print("ERROR: ClickUp configuration not found in config.json")
            print("Please add 'eng' section with 'clickup' configuration:")
            print("""
{
  "eng": {
    "provider": "clickup",
    "clickup": {
      "api_token": "your-clickup-api-token",
      "fine_tuning_list_id": "your-fine-tuning-list-id",
      "engineering_list_id": "your-engineering-list-id",
      "timeout_seconds": 30,
      "verify_ssl": true
    }
  }
}
""")
            return
    except Exception as e:
        print(f"ERROR: Failed to load config: {e}")
        return
    
    # Create ClickUp client
    try:
        client = ClickUpClient.from_config(config)
        print("✓ ClickUp client created successfully")
    except Exception as e:
        print(f"ERROR: Failed to create ClickUp client: {e}")
        return
    
    # Test create fine-tuning recommendation
    print("\n" + "-" * 70)
    print("Test 1: create_fine_tuning_recommendation() - creates cards on the fine-tuning board")
    print("-" * 70)
    try:
        task = client.create_fine_tuning_recommendation(
            title="Test Fine-Tuning Recommendation",
            description="This is a test recommendation for fine-tuning improvements.",
            tags=["test", "recommendation"]
        )
        print(f"✓ Fine-tuning recommendation task created successfully")
        print(f"  Task ID: {task.get('id')}")
        print(f"  Task Name: {task.get('name')}")
        print(f"  Task URL: {task.get('url')}")
    except Exception as e:
        print(f"✗ Failed to create fine-tuning recommendation: {e}")
        import traceback
        traceback.print_exc()
    
    # Test create visibility recommendation
    print("\n" + "-" * 70)
    print("Test 2: create_visibility_recommendation() - creates cards on the engineering board")
    print("-" * 70)
    try:
        task = client.create_visibility_recommendation(
            title="Test Visibility Recommendation",
            description="This is a test recommendation for visibility improvements.",
            tags=["test", "recommendation"]
        )
        print(f"✓ Visibility recommendation task created successfully")
        print(f"  Task ID: {task.get('id')}")
        print(f"  Task Name: {task.get('name')}")
        print(f"  Task URL: {task.get('url')}")
    except Exception as e:
        print(f"✗ Failed to create visibility recommendation: {e}")
        import traceback
        traceback.print_exc()
    
    # Test list fine-tuning recommendations
    print("\n" + "-" * 70)
    print("Test 3: list_fine_tuning_recommendations() - lists tasks on the fine-tuning board")
    print("-" * 70)
    try:
        tasks = client.list_fine_tuning_recommendations()
        print(f"✓ Fine-tuning recommendations listed successfully")
        print(f"  Found {len(tasks)} tasks")
        if tasks:
            print(f"  First task ID: {tasks[0].get('id')}")
            print(f"  First task Name: {tasks[0].get('name')}")
    except Exception as e:
        print(f"✗ Failed to list fine-tuning recommendations: {e}")
        import traceback
        traceback.print_exc()
    
    # Test list visibility recommendations
    print("\n" + "-" * 70)
    print("Test 4: list_visibility_recommendations() - lists tasks on the engineering board")
    print("-" * 70)
    try:
        tasks = client.list_visibility_recommendations()
        print(f"✓ Visibility recommendations listed successfully")
        print(f"  Found {len(tasks)} tasks")
        if tasks:
            print(f"  First task ID: {tasks[0].get('id')}")
            print(f"  First task Name: {tasks[0].get('name')}")
    except Exception as e:
        print(f"✗ Failed to list visibility recommendations: {e}")
        import traceback
        traceback.print_exc()
    
    # Test add comment to fine-tuning recommendation
    print("\n" + "-" * 70)
    print("Test 5: add_comment_to_fine_tuning_recommendation() - adds comment to a fine-tuning task")
    print("-" * 70)
    try:
        # First, list tasks to get a task ID
        tasks = client.list_fine_tuning_recommendations()
        if not tasks:
            print("  ⚠ No tasks found, skipping comment test. Create a task first.")
        else:
            task_id = tasks[0].get('id')
            comment = client.add_comment_to_fine_tuning_recommendation(
                task_id=task_id,
                comment_text="Test comment added by test script"
            )
            print(f"✓ Comment added to fine-tuning recommendation task successfully")
            print(f"  Task ID: {task_id}")
            print(f"  Comment ID: {comment.get('id')}")
    except Exception as e:
        print(f"✗ Failed to add comment to fine-tuning recommendation: {e}")
        import traceback
        traceback.print_exc()
    
    # Test add comment to visibility recommendation
    print("\n" + "-" * 70)
    print("Test 6: add_comment_to_visibility_recommendation() - adds comment to a visibility task")
    print("-" * 70)
    try:
        # First, list tasks to get a task ID
        tasks = client.list_visibility_recommendations()
        if not tasks:
            print("  ⚠ No tasks found, skipping comment test. Create a task first.")
        else:
            task_id = tasks[0].get('id')
            comment = client.add_comment_to_visibility_recommendation(
                task_id=task_id,
                comment_text="Test comment added by test script"
            )
            print(f"✓ Comment added to visibility recommendation task successfully")
            print(f"  Task ID: {task_id}")
            print(f"  Comment ID: {comment.get('id')}")
    except Exception as e:
        print(f"✗ Failed to add comment to visibility recommendation: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 70)
    print("All tests completed!")
    print("=" * 70)


if __name__ == "__main__":
    main()

