"""
Detailed API test to diagnose ClickUp API issues.
"""

import os
import sys
import json

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../.."))
sys.path.insert(0, project_root)

import requests
from src.core.config_storage import load_config_from_file


def main():
    """Test ClickUp API with detailed output."""
    print("=" * 70)
    print("ClickUp API Detailed Diagnostic Test")
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
    api_token = clickup_config.api_token
    
    print(f"\nAPI Token (first 20 chars): {api_token[:20]}...")
    print(f"Token length: {len(api_token)}")
    print(f"Token starts with 'pk_': {api_token.startswith('pk_')}")
    
    # Test different endpoints
    base_url = "https://api.clickup.com"
    headers = {
        "Authorization": api_token,
        "Content-Type": "application/json",
    }
    
    endpoints_to_test = [
        "/v2/team",
        "/api/v2/team",  # Try with /api prefix
        "/v2/user",
        "/api/v2/user",  # Try with /api prefix
    ]
    
    for endpoint in endpoints_to_test:
        url = f"{base_url}{endpoint}"
        print(f"\n{'=' * 70}")
        print(f"Testing: {endpoint}")
        print(f"Full URL: {url}")
        print(f"{'=' * 70}")
        
        try:
            response = requests.get(url, headers=headers, timeout=30, verify=True)
            print(f"Status Code: {response.status_code}")
            print(f"Response Headers:")
            for key, value in response.headers.items():
                print(f"  {key}: {value}")
            print(f"\nResponse Body (first 500 chars):")
            print(response.text[:500])
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    print(f"\nParsed JSON:")
                    print(json.dumps(data, indent=2)[:1000])
                except:
                    print("  (Not valid JSON)")
        except Exception as e:
            print(f"Exception: {e}")
            import traceback
            traceback.print_exc()
    
    # Test with a real list ID if provided (not placeholder)
    if clickup_config.fine_tuning_list_id and clickup_config.fine_tuning_list_id != "123456789":
        list_id = clickup_config.fine_tuning_list_id
        print(f"\n{'=' * 70}")
        print(f"Testing list access: {list_id}")
        print(f"{'=' * 70}")
        
        url = f"{base_url}/v2/list/{list_id}"
        try:
            response = requests.get(url, headers=headers, timeout=30, verify=True)
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text[:500]}")
        except Exception as e:
            print(f"Exception: {e}")


if __name__ == "__main__":
    main()

