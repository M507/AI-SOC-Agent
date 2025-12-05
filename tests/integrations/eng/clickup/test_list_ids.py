"""
Test potential list IDs extracted from URLs.
"""

import os
import sys

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../.."))
sys.path.insert(0, project_root)

from src.core.config_storage import load_config_from_file, save_config_to_file
from src.integrations.eng.clickup.clickup_http import ClickUpHttpClient


def test_list_id(http_client, list_id, list_name):
    """Test if a list ID is valid."""
    print(f"\nTesting {list_name}...")
    print(f"  List ID: {list_id}")
    try:
        response = http_client.get(f"/v2/list/{list_id}")
        print(f"  ✓ Valid list ID!")
        print(f"    List Name: {response.get('name', 'Unknown')}")
        print(f"    Space ID: {response.get('space_id', response.get('space', {}).get('id', 'Not found'))}")
        return {
            "list_id": list_id,
            "list_name": response.get("name"),
            "space_id": response.get("space_id") or response.get("space", {}).get("id"),
            "valid": True
        }
    except Exception as e:
        print(f"  ✗ Invalid list ID: {e}")
        return {"list_id": list_id, "valid": False}


def main():
    """Test potential list IDs."""
    print("=" * 70)
    print("Testing Potential List IDs")
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
    
    # From the URLs provided:
    # Visibility: https://app.clickup.com/90182069588/v/b/2kzmabam-198
    # Fine-tuning: https://app.clickup.com/90182069588/v/b/4-90188208260-2
    
    # Potential list IDs to test:
    # From fine-tuning URL "4-90188208260-2", the middle part "90188208260" looks like a list ID
    potential_ids = {
        "Fine-tuning": "90188208260",  # Extracted from "4-90188208260-2"
        "Visibility": None,  # Can't extract from "2kzmabam-198" easily
    }
    
    results = {}
    
    # Test fine-tuning ID
    if potential_ids["Fine-tuning"]:
        result = test_list_id(http_client, potential_ids["Fine-tuning"], "Fine-tuning Tasks")
        if result.get("valid"):
            results["fine_tuning"] = result
    
    # For visibility, we need the user to provide the actual list ID
    # or we can try some variations
    print("\n" + "-" * 70)
    print("Note: For the Visibility board, the view ID '2kzmabam-198' doesn't")
    print("contain an obvious list ID. You may need to:")
    print("  1. Click on the actual list in ClickUp")
    print("  2. The URL will change to: https://app.clickup.com/.../v/li/{LIST_ID}")
    print("  3. Extract the LIST_ID from that URL")
    print("-" * 70)
    
    # Update config if we found valid IDs
    if results:
        print("\n" + "=" * 70)
        print("Updating config.json...")
        print("=" * 70)
        
        updated = False
        
        if results.get("fine_tuning"):
            fine_tuning = results["fine_tuning"]
            if clickup_config.fine_tuning_list_id != fine_tuning["list_id"]:
                clickup_config.fine_tuning_list_id = fine_tuning["list_id"]
                print(f"  Updated fine_tuning_list_id: {fine_tuning['list_id']}")
                updated = True
            
            if fine_tuning.get("space_id"):
                clickup_config.space_id = fine_tuning["space_id"]
                print(f"  Updated space_id: {fine_tuning['space_id']}")
                updated = True
        
        if updated:
            try:
                save_config_to_file(config, "config.json")
                print("\n✓ Config file updated successfully!")
            except Exception as e:
                print(f"\n✗ Error saving config: {e}")
                import traceback
                traceback.print_exc()
        else:
            print("  No updates needed")
    
    print("\n" + "=" * 70)
    print("Final Configuration:")
    print("=" * 70)
    print(f"  fine_tuning_list_id: {clickup_config.fine_tuning_list_id}")
    print(f"  engineering_list_id: {clickup_config.engineering_list_id}")
    if hasattr(clickup_config, 'space_id') and clickup_config.space_id:
        print(f"  space_id: {clickup_config.space_id}")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()

