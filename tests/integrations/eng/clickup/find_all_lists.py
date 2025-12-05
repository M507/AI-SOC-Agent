"""
Script to find all ClickUp lists in the workspace.
This will help identify the correct list IDs for fine-tuning and visibility boards.
"""

import os
import sys
import json

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../.."))
sys.path.insert(0, project_root)

from src.core.config_storage import load_config_from_file
from src.integrations.eng.clickup.clickup_http import ClickUpHttpClient


def find_all_lists():
    """Find all lists in the ClickUp workspace."""
    print("=" * 70)
    print("Finding All ClickUp Lists")
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
    
    all_lists = []
    
    try:
        # Step 1: Get teams
        print("\nStep 1: Getting teams...")
        try:
            teams_response = http_client.get("/v2/team")
            teams = teams_response.get("teams", [])
            if not teams:
                print("  No teams found. Trying alternative endpoint...")
                # Try without 'teams' wrapper
                if isinstance(teams_response, list):
                    teams = teams_response
                else:
                    teams = [teams_response] if teams_response else []
        except Exception as e:
            print(f"  Error getting teams: {e}")
            print("  Trying to get lists directly from known endpoints...")
            teams = []
        
        if not teams:
            print("  Could not get teams. You may need to manually find list IDs.")
            print("  To find list IDs manually:")
            print("  1. Open your ClickUp board in the browser")
            print("  2. Click on a list to open it")
            print("  3. The list ID is in the URL: https://app.clickup.com/.../v/li/{LIST_ID}")
            return
        
        print(f"  Found {len(teams)} team(s)")
        
        # Step 2: Get spaces for each team
        for team in teams:
            team_id = team.get("id")
            team_name = team.get("name", "Unknown")
            print(f"\nStep 2: Getting spaces for team '{team_name}' (ID: {team_id})...")
            
            try:
                spaces_response = http_client.get(f"/v2/team/{team_id}/space")
                spaces = spaces_response.get("spaces", [])
                if not spaces and isinstance(spaces_response, list):
                    spaces = spaces_response
                elif not spaces and isinstance(spaces_response, dict):
                    spaces = [spaces_response] if spaces_response else []
            except Exception as e:
                print(f"  Error getting spaces: {e}")
                continue
            
            print(f"  Found {len(spaces)} space(s)")
            
            # Step 3: Get folders and lists for each space
            for space in spaces:
                space_id = space.get("id")
                space_name = space.get("name", "Unknown")
                print(f"\n  Step 3: Getting folders/lists for space '{space_name}' (ID: {space_id})...")
                
                try:
                    # Get folders in space
                    folders_response = http_client.get(f"/v2/space/{space_id}/folder")
                    folders = folders_response.get("folders", [])
                    if not folders and isinstance(folders_response, list):
                        folders = folders_response
                    elif not folders and isinstance(folders_response, dict):
                        folders = [folders_response] if folders_response else []
                    
                    # Also get lists directly in space (not in folders)
                    try:
                        lists_response = http_client.get(f"/v2/space/{space_id}/list")
                        space_lists = lists_response.get("lists", [])
                        if not space_lists and isinstance(lists_response, list):
                            space_lists = lists_response
                        elif not space_lists and isinstance(lists_response, dict):
                            space_lists = [lists_response] if lists_response else []
                        
                        for list_item in space_lists:
                            list_item["folder_name"] = "(No Folder)"
                            all_lists.append(list_item)
                    except Exception as e:
                        print(f"    Error getting lists in space: {e}")
                    
                    # Get lists from each folder
                    for folder in folders:
                        folder_id = folder.get("id")
                        folder_name = folder.get("name", "Unknown")
                        
                        try:
                            lists_response = http_client.get(f"/v2/folder/{folder_id}/list")
                            folder_lists = lists_response.get("lists", [])
                            if not folder_lists and isinstance(lists_response, list):
                                folder_lists = lists_response
                            elif not folder_lists and isinstance(lists_response, dict):
                                folder_lists = [lists_response] if lists_response else []
                            
                            for list_item in folder_lists:
                                list_item["folder_name"] = folder_name
                                all_lists.append(list_item)
                        except Exception as e:
                            print(f"    Error getting lists from folder '{folder_name}': {e}")
                
                except Exception as e:
                    print(f"  Error processing space '{space_name}': {e}")
                    continue
    
    except Exception as e:
        print(f"\nError during list enumeration: {e}")
        import traceback
        traceback.print_exc()
    
    # Display results
    print("\n" + "=" * 70)
    print("Found Lists:")
    print("=" * 70)
    
    if not all_lists:
        print("No lists found. This could mean:")
        print("  1. The API token doesn't have access to the workspace")
        print("  2. The workspace structure is different than expected")
        print("  3. There are no lists in the workspace")
        print("\nTo find list IDs manually:")
        print("  1. Open your ClickUp board in the browser")
        print("  2. Click on a list to open it")
        print("  3. The list ID is in the URL: https://app.clickup.com/.../v/li/{LIST_ID}")
        return
    
    # Look for lists matching our target names
    fine_tuning_candidates = []
    visibility_candidates = []
    
    for list_item in all_lists:
        list_name = list_item.get("name", "").lower()
        list_id = list_item.get("id", "")
        folder_name = list_item.get("folder_name", "")
        
        print(f"\n  List: {list_item.get('name', 'Unknown')}")
        print(f"    ID: {list_id}")
        print(f"    Folder: {folder_name}")
        print(f"    URL: {list_item.get('url', 'N/A')}")
        
        # Check if it matches our target names
        if "fine" in list_name and "tun" in list_name:
            fine_tuning_candidates.append(list_item)
        if "visib" in list_name or "engineer" in list_name:
            visibility_candidates.append(list_item)
    
    # Show recommendations
    print("\n" + "=" * 70)
    print("Recommendations:")
    print("=" * 70)
    
    if fine_tuning_candidates:
        print("\nFine-tuning list candidates:")
        for candidate in fine_tuning_candidates:
            print(f"  - {candidate.get('name')}: {candidate.get('id')}")
    else:
        print("\nNo fine-tuning list candidates found. Look for lists with 'fine' and 'tun' in the name above.")
    
    if visibility_candidates:
        print("\nVisibility/Engineering list candidates:")
        for candidate in visibility_candidates:
            print(f"  - {candidate.get('name')}: {candidate.get('id')}")
    else:
        print("\nNo visibility/engineering list candidates found. Look for lists with 'visib' or 'engineer' in the name above.")
    
    print("\n" + "=" * 70)
    print("Update your config.json with the correct list IDs above.")
    print("=" * 70)


if __name__ == "__main__":
    find_all_lists()

