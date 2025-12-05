"""
Simple helper to find ClickUp list IDs.

The URLs you provided are board VIEW URLs, not list URLs.
We need the actual LIST IDs for the API.

To find list IDs:
1. Go to ClickUp and open the list (not the board view)
2. The list URL will look like: https://app.clickup.com/90182069588/v/li/XXXXX
3. The XXXXX part is the list ID

Or use this script to list all your lists.
"""

import os
import sys

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../.."))
sys.path.insert(0, project_root)

from src.core.config_storage import load_config_from_file
from src.integrations.eng.clickup.clickup_http import ClickUpHttpClient


def find_list_ids_simple():
    """Find list IDs - simplified version."""
    print("=" * 70)
    print("ClickUp List ID Finder")
    print("=" * 70)
    print("\nNOTE: The URLs you provided are BOARD VIEW URLs, not LIST URLs.")
    print("We need the actual LIST IDs for the API.\n")
    print("Your URLs:")
    print("  Visibility: https://app.clickup.com/90182069588/v/b/2kzmabam-198")
    print("  Fine-tuning: https://app.clickup.com/90182069588/v/b/4-90188208260-2")
    print("\nThese are view IDs, not list IDs.\n")
    
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
    
    print("Testing API connection...")
    try:
        # Try to get user info - this is the simplest endpoint
        user_response = http_client.get("/v2/user")
        print("✓ API connection successful!")
        print(f"User: {user_response.get('user', {}).get('username', 'Unknown')}")
    except Exception as e:
        print(f"✗ API connection failed: {e}")
        print("\nTroubleshooting:")
        print("1. Check that your API token is correct")
        print("2. Make sure the token has the right permissions")
        print("3. The token should start with 'pk_'")
        return
    
    print("\n" + "=" * 70)
    print("Finding all lists...")
    print("=" * 70)
    
    try:
        # Get teams
        teams_response = http_client.get("/v2/team")
        teams = teams_response.get("teams", [])
        
        if not teams:
            print("No teams found")
            return
        
        team = teams[0]
        team_id = team.get("id")
        team_name = team.get("name", "Unknown")
        print(f"\nTeam: {team_name} (ID: {team_id})")
        
        # Get spaces
        spaces_response = http_client.get(f"/v2/team/{team_id}/space", params={"archived": False})
        spaces = spaces_response.get("spaces", [])
        
        print(f"\nFound {len(spaces)} spaces")
        print("-" * 70)
        
        all_lists = []
        
        for space in spaces:
            space_id = space.get("id")
            space_name = space.get("name", "Unknown")
            print(f"\n📁 Space: {space_name}")
            
            # Get folders
            folders_response = http_client.get(f"/v2/space/{space_id}/folder", params={"archived": False})
            folders = folders_response.get("folders", [])
            
            # Get lists directly in space
            lists_response = http_client.get(f"/v2/space/{space_id}/list", params={"archived": False})
            space_lists = lists_response.get("lists", [])
            
            for lst in space_lists:
                list_id = lst.get("id")
                list_name = lst.get("name", "Unknown")
                list_url = lst.get("url", "")
                print(f"  📋 List: {list_name}")
                print(f"     ID: {list_id}")
                if list_url:
                    print(f"     URL: {list_url}")
                all_lists.append({
                    "name": list_name,
                    "id": list_id,
                    "url": list_url,
                    "space": space_name,
                })
            
            # Get lists in folders
            for folder in folders:
                folder_id = folder.get("id")
                folder_name = folder.get("name", "Unknown")
                print(f"  📂 Folder: {folder_name}")
                
                folder_lists_response = http_client.get(f"/v2/folder/{folder_id}/list", params={"archived": False})
                folder_lists = folder_lists_response.get("lists", [])
                
                for lst in folder_lists:
                    list_id = lst.get("id")
                    list_name = lst.get("name", "Unknown")
                    list_url = lst.get("url", "")
                    print(f"    📋 List: {list_name}")
                    print(f"       ID: {list_id}")
                    if list_url:
                        print(f"       URL: {list_url}")
                    all_lists.append({
                        "name": list_name,
                        "id": list_id,
                        "url": list_url,
                        "space": space_name,
                        "folder": folder_name,
                    })
        
        print("\n" + "=" * 70)
        print("SUMMARY - Look for lists matching your board names:")
        print("=" * 70)
        print("\nSearching for lists with 'Visibility' or 'Fine-tuning' in the name...\n")
        
        visibility_lists = [lst for lst in all_lists if "visibility" in lst["name"].lower() or "vis" in lst["name"].lower()]
        fine_tuning_lists = [lst for lst in all_lists if "fine" in lst["name"].lower() or "tuning" in lst["name"].lower() or "fine-tuning" in lst["name"].lower()]
        
        if visibility_lists:
            print("Possible Visibility lists:")
            for lst in visibility_lists:
                print(f"  ✓ {lst['name']}")
                print(f"    ID: {lst['id']}")
                print(f"    Use this ID for 'engineering_list_id'")
        else:
            print("⚠ No lists found with 'Visibility' in the name")
        
        if fine_tuning_lists:
            print("\nPossible Fine-tuning lists:")
            for lst in fine_tuning_lists:
                print(f"  ✓ {lst['name']}")
                print(f"    ID: {lst['id']}")
                print(f"    Use this ID for 'fine_tuning_list_id'")
        else:
            print("\n⚠ No lists found with 'Fine-tuning' in the name")
        
        print("\n" + "=" * 70)
        print("All Lists (for reference):")
        print("=" * 70)
        for lst in all_lists:
            print(f"\n  {lst['name']}")
            print(f"    ID: {lst['id']}")
            if lst.get('folder'):
                print(f"    Location: {lst['space']} > {lst['folder']}")
            else:
                print(f"    Location: {lst['space']}")
        
        print("\n" + "=" * 70)
        print("Next Steps:")
        print("=" * 70)
        print("1. Find the lists that match 'Visibility Tasks' and 'Fine-tuning Tasks'")
        print("2. Copy the 'ID' values (they look like numbers, e.g., 123456789)")
        print("3. Update your config.json:")
        print("   - fine_tuning_list_id: <ID from Fine-tuning list>")
        print("   - engineering_list_id: <ID from Visibility list>")
        print("=" * 70)
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    find_list_ids_simple()

