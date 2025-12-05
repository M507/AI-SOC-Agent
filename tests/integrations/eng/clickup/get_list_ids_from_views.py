"""
Get list IDs from ClickUp board views.

This script queries the ClickUp API to find which lists are in your board views,
then extracts the list IDs you need.
"""

import os
import sys
import json
import requests

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../.."))
sys.path.insert(0, project_root)

from src.core.config_storage import load_config_from_file


def get_list_ids_from_views():
    """Get list IDs from board view IDs."""
    print("=" * 70)
    print("ClickUp: Get List IDs from Board Views")
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
    
    api_token = config.eng.clickup.api_token
    
    # Your board view IDs from the URLs
    visibility_view_id = "2kzmabam-198"  # From: /v/b/2kzmabam-198
    fine_tuning_view_id = "4-90188208260-2"  # From: /v/b/4-90188208260-2
    
    print("\nYour board view IDs:")
    print(f"  Visibility: {visibility_view_id}")
    print(f"  Fine-tuning: {fine_tuning_view_id}")
    print("\nQuerying ClickUp API to find list IDs...")
    print("-" * 70)
    
    headers = {
        "Authorization": api_token,
        "Content-Type": "application/json",
    }
    
    base_url = "https://api.clickup.com/api/v2"
    
    # Try to get view details
    views_to_check = [
        ("Visibility Tasks", visibility_view_id),
        ("Fine-tuning Tasks", fine_tuning_view_id),
    ]
    
    # First, get view details to find the folder
    folder_id = None
    for view_name, view_id in views_to_check:
        print(f"\nChecking view: {view_name} (ID: {view_id})")
        
        try:
            url = f"{base_url}/view/{view_id}"
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                view_data = data.get("view", {})
                print(f"  ✓ View: {view_data.get('name', 'Unknown')}")
                
                # Check if there's a parent folder
                parent = view_data.get("parent", {})
                if parent.get("type") == 4:  # Type 4 = Folder
                    folder_id = parent.get("id")
                    print(f"  Found folder ID: {folder_id}")
        except Exception as e:
            print(f"  ✗ Failed: {e}")
    
    # Now get lists from the folder
    if folder_id:
        print(f"\n{'='*70}")
        print(f"Getting lists from folder ID: {folder_id}")
        print(f"{'='*70}")
        
        try:
            folder_url = f"{base_url}/folder/{folder_id}/list"
            folder_response = requests.get(folder_url, headers=headers, params={"archived": False}, timeout=30)
            
            if folder_response.status_code == 200:
                folder_data = folder_response.json()
                lists = folder_data.get("lists", [])
                
                print(f"\nFound {len(lists)} lists in folder:")
                print("-" * 70)
                
                for lst in lists:
                    list_id = lst.get("id")
                    list_name = lst.get("name", "Unknown")
                    list_url = lst.get("url", "")
                    
                    print(f"\n  List: {list_name}")
                    print(f"    ID: {list_id}")
                    if list_url:
                        print(f"    URL: {list_url}")
                    
                    # Check if this matches our view names
                    if "visibility" in list_name.lower() or "vis" in list_name.lower():
                        print(f"    ⭐ MATCHES 'Visibility Tasks' - Use this ID for 'engineering_list_id'")
                    if "fine" in list_name.lower() or "tuning" in list_name.lower() or "fine-tuning" in list_name.lower():
                        print(f"    ⭐ MATCHES 'Fine-tuning Tasks' - Use this ID for 'fine_tuning_list_id'")
            else:
                print(f"✗ Failed to get folder lists: HTTP {folder_response.status_code}")
                print(f"  Response: {folder_response.text[:200]}")
        except Exception as e:
            print(f"✗ Failed to get folder lists: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("\n⚠ Could not determine folder ID from views")
    
    print("\n" + "=" * 70)
    print("Alternative: Manual Method")
    print("=" * 70)
    print("""
If the API method doesn't work, find the list IDs manually:

1. Open ClickUp in your browser
2. Go to the board view (use your URLs)
3. Click on any task OR click "View List" button
4. Look at the URL - it will change to:
   https://app.clickup.com/90182069588/v/li/123456789
5. The number after /v/li/ is the list ID (e.g., 123456789)

Do this for both:
- Visibility Tasks board -> get list ID
- Fine-tuning Tasks board -> get list ID

Then update config.json with those list IDs.
""")


if __name__ == "__main__":
    get_list_ids_from_views()

