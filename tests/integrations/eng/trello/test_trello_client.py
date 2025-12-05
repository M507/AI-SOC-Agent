"""
Test script for Trello client.

Tests the following operations:
1. Create a fine-tuning recommendation card
2. Create a visibility recommendation card

All operations use the Python functions directly from src/integrations/eng/trello/*
"""

import os
import sys

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../.."))
sys.path.insert(0, project_root)

from src.core.config_storage import load_config_from_file
from src.integrations.eng.trello.trello_client import TrelloClient


def main():
    """Run all test operations."""
    print("=" * 70)
    print("Trello Client Test")
    print("=" * 70)
    
    # Load configuration
    try:
        config = load_config_from_file("config.json")
        if not config.eng or not config.eng.trello:
            print("ERROR: Trello configuration not found in config.json")
            print("Please add 'eng' section with 'trello' configuration:")
            print("""
{
  "eng": {
    "trello": {
      "api_key": "your-trello-api-key",
      "api_token": "your-trello-api-token",
      "fine_tuning_board_id": "your-fine-tuning-board-id",
      "engineering_board_id": "your-engineering-board-id",
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
    
    # Create Trello client
    try:
        client = TrelloClient.from_config(config)
        print("✓ Trello client created successfully")
    except Exception as e:
        print(f"ERROR: Failed to create Trello client: {e}")
        return
    
    # Test ping
    print("\n" + "-" * 70)
    print("Test 1: Ping Trello API")
    print("-" * 70)
    try:
        if client.ping():
            print("✓ Trello API is reachable")
        else:
            print("✗ Trello API is not reachable")
            return
    except Exception as e:
        print(f"✗ Ping failed: {e}")
        return
    
    # Test create fine-tuning recommendation
    print("\n" + "-" * 70)
    print("Test 2: Create Fine-Tuning Recommendation")
    print("-" * 70)
    try:
        card = client.create_fine_tuning_recommendation(
            title="Test Fine-Tuning Recommendation",
            description="This is a test recommendation for fine-tuning improvements.",
            labels=["test", "recommendation"]
        )
        print(f"✓ Fine-tuning recommendation card created successfully")
        print(f"  Card ID: {card.get('id')}")
        print(f"  Card Name: {card.get('name')}")
        print(f"  Card URL: {card.get('url')}")
    except Exception as e:
        print(f"✗ Failed to create fine-tuning recommendation: {e}")
        import traceback
        traceback.print_exc()
    
    # Test create visibility recommendation
    print("\n" + "-" * 70)
    print("Test 3: Create Visibility Recommendation")
    print("-" * 70)
    try:
        card = client.create_visibility_recommendation(
            title="Test Visibility Recommendation",
            description="This is a test recommendation for visibility improvements.",
            labels=["test", "recommendation"]
        )
        print(f"✓ Visibility recommendation card created successfully")
        print(f"  Card ID: {card.get('id')}")
        print(f"  Card Name: {card.get('name')}")
        print(f"  Card URL: {card.get('url')}")
    except Exception as e:
        print(f"✗ Failed to create visibility recommendation: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 70)
    print("All tests completed!")
    print("=" * 70)


if __name__ == "__main__":
    main()

