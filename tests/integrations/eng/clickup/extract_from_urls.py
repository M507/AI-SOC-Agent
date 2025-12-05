"""
Extract list IDs and space IDs from ClickUp board view URLs.
"""

import os
import sys
import re
import json

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../.."))
sys.path.insert(0, project_root)

from src.core.config_storage import load_config_from_file, save_config_to_file
from src.integrations.eng.clickup.clickup_http import ClickUpHttpClient


def extract_ids_from_url(url):
    """Extract workspace ID and view ID from ClickUp board view URL."""
    # Pattern: https://app.clickup.com/{workspace_id}/v/b/{view_id}
    pattern = r'https://app\.clickup\.com/(\d+)/v/b/([^/?]+)'
    match = re.match(pattern, url)
    if match:
        workspace_id = match.group(1)
        view_id = match.group(2)
        return workspace_id, view_id
    return None, None


def get_view_details(http_client, view_id):
    """Get view details from ClickUp API."""
    # Try different endpoint formats
    endpoints_to_try = [
        f"/v2/view/{view_id}",
        f"/api/v2/view/{view_id}",
        f"/v2/views/{view_id}",
    ]
    
    for endpoint in endpoints_to_try:
        try:
            response = http_client.get(endpoint)
            return response
        except Exception as e:
            continue
    
    return None


def get_list_from_view(http_client, view_id, workspace_id):
    """Try to get list information from a view."""
    view_details = get_view_details(http_client, view_id)
    
    # If view endpoint doesn't work, try to get all lists from workspace/space
    # and match by name or try to extract from view_id pattern
    list_id = None
    space_id = None
    folder_id = None
    list_info = None
    
    if view_details:
        # View details might contain list information
        # Try different possible fields
        list_id = view_details.get("list_id") or view_details.get("list", {}).get("id")
        space_id = view_details.get("space_id") or view_details.get("space", {}).get("id")
        folder_id = view_details.get("folder_id") or view_details.get("folder", {}).get("id")
    
    # Try alternative: The view ID might actually be a list ID or contain it
    # Some ClickUp URLs use view IDs that are related to lists
    # Let's try treating parts of the view_id as potential list IDs
    if not list_id:
        # Try the view_id itself as a list ID
        try:
            list_response = http_client.get(f"/v2/list/{view_id}")
            list_id = view_id
            list_info = {
                "id": list_id,
                "name": list_response.get("name"),
                "url": list_response.get("url"),
            }
            space_id = list_response.get("space_id") or list_response.get("space", {}).get("id")
        except:
            # Try extracting numeric part if view_id has format like "4-90188208260-2"
            # The middle part might be the list ID
            parts = view_id.split("-")
            for part in parts:
                if part.isdigit() and len(part) > 5:  # Likely a list ID
                    try:
                        list_response = http_client.get(f"/v2/list/{part}")
                        list_id = part
                        list_info = {
                            "id": list_id,
                            "name": list_response.get("name"),
                            "url": list_response.get("url"),
                        }
                        space_id = list_response.get("space_id") or list_response.get("space", {}).get("id")
                        break
                    except:
                        continue
    
    # If we have folder_id, we can get space from folder
    if folder_id and not space_id:
        try:
            folder_response = http_client.get(f"/v2/folder/{folder_id}")
            space_id = folder_response.get("space_id") or folder_response.get("space", {}).get("id")
        except:
            pass
    
    # If we have list_id but no list_info, get list details
    if list_id and not list_info:
        try:
            list_response = http_client.get(f"/v2/list/{list_id}")
            list_info = {
                "id": list_id,
                "name": list_response.get("name"),
                "url": list_response.get("url"),
            }
            # Get space from list if not already found
            if not space_id:
                space_id = list_response.get("space_id") or list_response.get("space", {}).get("id")
        except Exception as e:
            print(f"  Error getting list details: {e}")
    
    return {
        "list_id": list_id,
        "list_info": list_info,
        "space_id": space_id,
        "folder_id": folder_id,
        "view_details": view_details,
    }


def main():
    """Extract list IDs from URLs and update config."""
    print("=" * 70)
    print("Extracting List IDs from ClickUp Board View URLs")
    print("=" * 70)
    
    # URLs provided by user
    visibility_url = "https://app.clickup.com/90182069588/v/b/2kzmabam-198"
    fine_tuning_url = "https://app.clickup.com/90182069588/v/b/4-90188208260-2"
    
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
    
    results = {}
    
    # Process Visibility board
    print("\n" + "-" * 70)
    print("Processing Visibility Tasks board...")
    print(f"URL: {visibility_url}")
    print("-" * 70)
    
    workspace_id, view_id = extract_ids_from_url(visibility_url)
    if not workspace_id or not view_id:
        print("  ERROR: Could not extract IDs from URL")
        return
    
    print(f"  Workspace ID: {workspace_id}")
    print(f"  View ID: {view_id}")
    
    visibility_data = get_list_from_view(http_client, view_id, workspace_id)
    if visibility_data:
        print(f"  List ID: {visibility_data.get('list_id', 'Not found')}")
        print(f"  Space ID: {visibility_data.get('space_id', 'Not found')}")
        if visibility_data.get('list_info'):
            print(f"  List Name: {visibility_data['list_info'].get('name', 'Unknown')}")
        results['visibility'] = visibility_data
    else:
        print("  ERROR: Could not get list information from view")
    
    # Process Fine-tuning board
    print("\n" + "-" * 70)
    print("Processing Fine-tuning Tasks board...")
    print(f"URL: {fine_tuning_url}")
    print("-" * 70)
    
    workspace_id, view_id = extract_ids_from_url(fine_tuning_url)
    if not workspace_id or not view_id:
        print("  ERROR: Could not extract IDs from URL")
        return
    
    print(f"  Workspace ID: {workspace_id}")
    print(f"  View ID: {view_id}")
    
    fine_tuning_data = get_list_from_view(http_client, view_id, workspace_id)
    if fine_tuning_data:
        print(f"  List ID: {fine_tuning_data.get('list_id', 'Not found')}")
        print(f"  Space ID: {fine_tuning_data.get('space_id', 'Not found')}")
        if fine_tuning_data.get('list_info'):
            print(f"  List Name: {fine_tuning_data['list_info'].get('name', 'Unknown')}")
        results['fine_tuning'] = fine_tuning_data
    else:
        print("  ERROR: Could not get list information from view")
    
    # Update config if we found the IDs
    print("\n" + "=" * 70)
    print("Updating config.json...")
    print("=" * 70)
    
    updated = False
    
    if results.get('visibility') and results['visibility'].get('list_id'):
        visibility_list_id = results['visibility']['list_id']
        if clickup_config.engineering_list_id != visibility_list_id:
            clickup_config.engineering_list_id = visibility_list_id
            print(f"  Updated engineering_list_id: {visibility_list_id}")
            updated = True
        else:
            print(f"  engineering_list_id already correct: {visibility_list_id}")
    
    if results.get('fine_tuning') and results['fine_tuning'].get('list_id'):
        fine_tuning_list_id = results['fine_tuning']['list_id']
        if clickup_config.fine_tuning_list_id != fine_tuning_list_id:
            clickup_config.fine_tuning_list_id = fine_tuning_list_id
            print(f"  Updated fine_tuning_list_id: {fine_tuning_list_id}")
            updated = True
        else:
            print(f"  fine_tuning_list_id already correct: {fine_tuning_list_id}")
    
    # Add space_id to config if we found it
    # First, check if ClickUpConfig has space_id field
    space_id = None
    if results.get('visibility') and results['visibility'].get('space_id'):
        space_id = results['visibility']['space_id']
    elif results.get('fine_tuning') and results['fine_tuning'].get('space_id'):
        space_id = results['fine_tuning']['space_id']
    
    if space_id:
        # Check if we need to add space_id to the config structure
        # For now, we'll add it as an optional field
        if not hasattr(clickup_config, 'space_id') or clickup_config.space_id != space_id:
            clickup_config.space_id = space_id
            print(f"  Added/Updated space_id: {space_id}")
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
        print("\n  No updates needed - config already has correct values")
    
    # Show final config values
    print("\n" + "=" * 70)
    print("Final Configuration:")
    print("=" * 70)
    print(f"  fine_tuning_list_id: {clickup_config.fine_tuning_list_id}")
    print(f"  engineering_list_id: {clickup_config.engineering_list_id}")
    if hasattr(clickup_config, 'space_id'):
        print(f"  space_id: {clickup_config.space_id}")
    
    print("\n" + "=" * 70)
    print("Done!")
    print("=" * 70)


if __name__ == "__main__":
    main()

