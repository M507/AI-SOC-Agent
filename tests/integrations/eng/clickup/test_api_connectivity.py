"""
Simple test to verify ClickUp API connectivity and token validity.
"""

import os
import sys

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../.."))
sys.path.insert(0, project_root)

from src.core.config_storage import load_config_from_file
from src.integrations.eng.clickup.clickup_http import ClickUpHttpClient


def main():
    """Test ClickUp API connectivity."""
    print("=" * 70)
    print("ClickUp API Connectivity Test")
    print("=" * 70)
    
    # Load configuration
    try:
        config = load_config_from_file("config.json")
        if not config.eng or not config.eng.clickup:
            print("ERROR: ClickUp configuration not found")
            return
    except Exception as e:
        print(f"ERROR: Failed to load config: {e}")
        return
    
    clickup_config = config.eng.clickup
    http_client = ClickUpHttpClient(
        api_token=clickup_config.api_token,
        timeout_seconds=clickup_config.timeout_seconds,
        verify_ssl=clickup_config.verify_ssl,
    )
    
    # Test 1: Try to get teams (this is a common endpoint that should work)
    print("\nTest 1: Get teams")
    print("-" * 70)
    try:
        response = http_client.get("/v2/team")
        teams = response.get("teams", [])
        print(f"✓ Successfully connected to ClickUp API")
        print(f"  Found {len(teams)} team(s)")
        if teams:
            print(f"  First team: {teams[0].get('name', 'N/A')} (ID: {teams[0].get('id', 'N/A')})")
    except Exception as e:
        print(f"✗ Failed to get teams: {e}")
        print("  This might indicate an API token issue")
        return
    
    # Test 2: Try to access the configured lists
    print("\nTest 2: Access configured lists")
    print("-" * 70)
    
    # Test fine-tuning list
    print(f"\n  Testing fine-tuning list ID: {clickup_config.fine_tuning_list_id}")
    try:
        response = http_client.get(f"/v2/list/{clickup_config.fine_tuning_list_id}")
        print(f"  ✓ Fine-tuning list accessible")
        print(f"    List name: {response.get('name', 'N/A')}")
        print(f"    List ID: {response.get('id', 'N/A')}")
    except Exception as e:
        print(f"  ✗ Fine-tuning list not accessible: {e}")
        print(f"    Make sure the list ID is correct")
    
    # Test engineering list
    print(f"\n  Testing engineering list ID: {clickup_config.engineering_list_id}")
    try:
        response = http_client.get(f"/v2/list/{clickup_config.engineering_list_id}")
        print(f"  ✓ Engineering list accessible")
        print(f"    List name: {response.get('name', 'N/A')}")
        print(f"    List ID: {response.get('id', 'N/A')}")
    except Exception as e:
        print(f"  ✗ Engineering list not accessible: {e}")
        print(f"    Make sure the list ID is correct")
    
    print("\n" + "=" * 70)
    print("Connectivity test completed!")
    print("=" * 70)


if __name__ == "__main__":
    main()

