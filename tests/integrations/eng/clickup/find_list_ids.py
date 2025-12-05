"""
Helper script to find ClickUp list IDs from view URLs or by listing all lists.

Usage:
    python find_list_ids.py

This script will:
1. Connect to ClickUp API using your config.json
2. List all spaces and their lists
3. Help you identify the correct list IDs for your boards
"""

import os
import sys

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../.."))
sys.path.insert(0, project_root)

from src.core.config_storage import load_config_from_file
from src.integrations.eng.clickup.clickup_http import ClickUpHttpClient


def find_list_ids():
    """Find list IDs from ClickUp API."""
    print("=" * 70)
    print("ClickUp List ID Finder")
    print("=" * 70)
    
    # Load configuration
    try:
        config = load_config_from_file("config.json")
        if not config.eng or not config.eng.clickup:
            print("ERROR: ClickUp configuration not found in config.json")
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
    
    print("\nFetching all spaces and lists from ClickUp...")
    print("-" * 70)
    
    try:
        # Get authenticated user info
        user = http_client.get("/v2/user")
        user_id = user.get("user", {}).get("id")
        print(f"User ID: {user_id}")
        
        # Get all teams (workspaces) for the user
        teams = http_client.get("/v2/team")
        teams_list = teams.get("teams", [])
        if not teams_list:
            print("ERROR: No teams found")
            return
        
        team_id = teams_list[0].get("id")
        print(f"Team ID: {team_id}")
        
        # Get all spaces
        spaces = http_client.get(f"/v2/team/{team_id}/space", params={"archived": False})
        spaces_list = spaces.get("spaces", [])
        
        print(f"\nFound {len(spaces_list)} spaces:")
        print("-" * 70)
        
        all_lists = []
        
        for space in spaces_list:
            space_id = space.get("id")
            space_name = space.get("name")
            print(f"\nSpace: {space_name} (ID: {space_id})")
            
            # Get all folders in the space
            folders = http_client.get(f"/v2/space/{space_id}/folder", params={"archived": False})
            folders_list = folders.get("folders", [])
            
            # Also get lists directly in the space (not in folders)
            lists = http_client.get(f"/v2/space/{space_id}/list", params={"archived": False})
            lists_list = lists.get("lists", [])
            
            for folder in folders_list:
                folder_id = folder.get("id")
                folder_name = folder.get("name")
                print(f"  Folder: {folder_name} (ID: {folder_id})")
                
                # Get lists in folder
                folder_lists = http_client.get(f"/v2/folder/{folder_id}/list", params={"archived": False})
                folder_lists_list = folder_lists.get("lists", [])
                
                for lst in folder_lists_list:
                    list_id = lst.get("id")
                    list_name = lst.get("name")
                    list_url = lst.get("url", "")
                    print(f"    - List: {list_name}")
                    print(f"      ID: {list_id}")
                    print(f"      URL: {list_url}")
                    all_lists.append({
                        "name": list_name,
                        "id": list_id,
                        "url": list_url,
                        "space": space_name,
                        "folder": folder_name,
                    })
            
            # Lists directly in space (not in folders)
            for lst in lists_list:
                list_id = lst.get("id")
                list_name = lst.get("name")
                list_url = lst.get("url", "")
                print(f"  - List: {list_name} (no folder)")
                print(f"    ID: {list_id}")
                print(f"    URL: {list_url}")
                all_lists.append({
                    "name": list_name,
                    "id": list_id,
                    "url": list_url,
                    "space": space_name,
                    "folder": None,
                })
        
        print("\n" + "=" * 70)
        print("Summary - All Lists Found:")
        print("=" * 70)
        
        # Try to match based on the URLs provided
        visibility_url = "https://app.clickup.com/90182069588/v/b/2kzmabam-198"
        fine_tuning_url = "https://app.clickup.com/90182069588/v/b/4-90188208260-2"
        
        print("\nLooking for lists that might match your URLs...")
        print(f"Visibility Tasks URL: {visibility_url}")
        print(f"Fine-tuning Tasks URL: {fine_tuning_url}")
        print("\nAll available lists:")
        
        for lst in all_lists:
            print(f"\n  Name: {lst['name']}")
            print(f"  ID: {lst['id']}")
            print(f"  URL: {lst['url']}")
            print(f"  Space: {lst['space']}")
            if lst['folder']:
                print(f"  Folder: {lst['folder']}")
        
        print("\n" + "=" * 70)
        print("To find the correct list ID:")
        print("1. Look for lists with names matching 'Visibility' or 'Fine-tuning'")
        print("2. Or check the list URLs above")
        print("3. Use the 'ID' value (not the view ID from the board URL)")
        print("=" * 70)
        
        # Also try to get views to help match
        print("\nFetching views to help match board URLs...")
        print("-" * 70)
        
        for space in spaces_list[:3]:  # Limit to first 3 spaces
            space_id = space.get("id")
            try:
                views = http_client.get(f"/v2/space/{space_id}/view", params={"archived": False})
                views_list = views.get("views", [])
                
                for view in views_list:
                    view_id = view.get("id")
                    view_name = view.get("name")
                    view_type = view.get("type")
                    if view_type == "board":
                        print(f"\nView: {view_name} (Type: {view_type})")
                        print(f"  View ID: {view_id}")
                        # Try to get the list IDs from this view
                        try:
                            view_details = http_client.get(f"/v2/view/{view_id}")
                            list_ids = view_details.get("list_ids", [])
                            if list_ids:
                                print(f"  Contains lists: {list_ids}")
                                # Match these list IDs to our all_lists
                                for list_id in list_ids:
                                    for lst in all_lists:
                                        if lst['id'] == list_id:
                                            print(f"    -> List: {lst['name']} (ID: {list_id})")
                        except Exception as e:
                            print(f"  Could not get view details: {e}")
            except Exception as e:
                print(f"Could not get views for space {space_id}: {e}")
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    find_list_ids()
