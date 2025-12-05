"""
Test script for GitHub client.

Tests the following operations:
1. Create a fine-tuning recommendation project item
2. Create a visibility recommendation project item

All operations use the Python functions directly from src/integrations/eng/github/*
"""

import os
import sys

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../.."))
sys.path.insert(0, project_root)

from src.core.config_storage import load_config_from_file
from src.integrations.eng.github.github_client import GitHubClient


def main():
    """Run all test operations."""
    print("=" * 70)
    print("GitHub Client Test")
    print("=" * 70)
    
    # Load configuration
    try:
        config = load_config_from_file("config.json")
        if not config.eng or not config.eng.github:
            print("ERROR: GitHub configuration not found in config.json")
            print("Please add 'eng' section with 'github' configuration:")
            print("""
{
  "eng": {
    "provider": "github",
    "github": {
      "api_token": "your-github-personal-access-token",
      "fine_tuning_project_id": "your-fine-tuning-project-id",
      "engineering_project_id": "your-engineering-project-id",
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
    
    # Create GitHub client
    try:
        client = GitHubClient.from_config(config)
        print("✓ GitHub client created successfully")
    except Exception as e:
        print(f"ERROR: Failed to create GitHub client: {e}")
        return
    
    # Test ping
    print("\n" + "-" * 70)
    print("Test 1: Ping GitHub API")
    print("-" * 70)
    try:
        if client.ping():
            print("✓ GitHub API is reachable")
        else:
            print("✗ GitHub API is not reachable")
            return
    except Exception as e:
        print(f"✗ Ping failed: {e}")
        return
    
    # Test create fine-tuning recommendation
    print("\n" + "-" * 70)
    print("Test 2: Create Fine-Tuning Recommendation")
    print("-" * 70)
    try:
        item = client.create_fine_tuning_recommendation(
            title="Test Fine-Tuning Recommendation",
            description="This is a test recommendation for fine-tuning improvements."
        )
        print(f"✓ Fine-tuning recommendation project item created successfully")
        print(f"  Item ID: {item.get('id')}")
        print(f"  Item URL: {item.get('url')}")
    except Exception as e:
        print(f"✗ Failed to create fine-tuning recommendation: {e}")
        import traceback
        traceback.print_exc()
    
    # Test create visibility recommendation
    print("\n" + "-" * 70)
    print("Test 3: Create Visibility Recommendation")
    print("-" * 70)
    try:
        item = client.create_visibility_recommendation(
            title="Test Visibility Recommendation",
            description="This is a test recommendation for visibility improvements."
        )
        print(f"✓ Visibility recommendation project item created successfully")
        print(f"  Item ID: {item.get('id')}")
        print(f"  Item URL: {item.get('url')}")
    except Exception as e:
        print(f"✗ Failed to create visibility recommendation: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 70)
    print("All tests completed!")
    print("=" * 70)


if __name__ == "__main__":
    main()

