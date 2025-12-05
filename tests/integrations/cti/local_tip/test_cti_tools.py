#!/usr/bin/env python3
"""
Integration test for CTI tools.

Tests the CTI tool wrapper functions end-to-end.
"""

import sys
import json
from pathlib import Path

# Add project root to path
# File is at: tests/integrations/cti/local_tip/test_cti_tools.py
# Need to go up 6 levels: local_tip -> cti -> integrations -> tests -> project root
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from src.core.config import SamiConfig, CTIConfig
from src.core.config_storage import load_config_from_file
from src.integrations.cti.local_tip.local_tip_client import LocalTipCTIClient
from src.orchestrator.tools_cti import lookup_hash_ti


def test_tool(tool_name: str, func, *args, **kwargs):
    """Test a single tool and print results."""
    print(f"\n{'='*80}")
    print(f"Testing: {tool_name}")
    print(f"{'='*80}")
    try:
        result = func(*args, **kwargs)
        print(f"✓ SUCCESS")
        print(f"Result type: {type(result)}")
        if isinstance(result, dict):
            print(f"Result keys: {list(result.keys())}")
            if "success" in result:
                print(f"Success: {result['success']}")
            # Print a summary (truncate if too long)
            result_str = json.dumps(result, indent=2, default=str)
            if len(result_str) > 500:
                print(f"Result (truncated):\n{result_str[:500]}...")
            else:
                print(f"Result:\n{result_str}")
        else:
            print(f"Result: {result}")
        return True
    except Exception as e:
        print(f"✗ FAILED: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Test CTI tools."""
    print("Loading configuration...")
    config = load_config_from_file("config.json")
    
    if not config.cti:
        print("ERROR: CTI configuration not found in config.json")
        print("Add CTI configuration to config.json:")
        print('  "cti": {')
        print('    "cti_type": "local_tip",')
        print('    "base_url": "http://10.10.10.95:8084",')
        print('    "timeout_seconds": 30,')
        print('    "verify_ssl": false')
        print('  }')
        return 1
    
    print("Initializing Local TIP CTI client...")
    try:
        cti_client = LocalTipCTIClient.from_config(config)
        print("✓ Local TIP CTI client initialized")
    except Exception as e:
        print(f"✗ Failed to initialize Local TIP CTI client: {e}")
        return 1
    
    results = {}
    
    # CTI Tools
    print("\n" + "="*80)
    print("CTI TOOLS")
    print("="*80)
    
    # Test with a sample hash (SHA256 of empty string)
    test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    results["lookup_hash_ti"] = test_tool(
        "lookup_hash_ti",
        lookup_hash_ti,
        hash_value=test_hash,
        client=cti_client
    )
    
    # Test with MD5 hash
    test_md5 = "d41d8cd98f00b204e9800998ecf8427e"  # MD5 of empty string
    results["lookup_hash_ti_md5"] = test_tool(
        "lookup_hash_ti (MD5)",
        lookup_hash_ti,
        hash_value=test_md5,
        client=cti_client
    )
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    failed = total - passed
    
    print(f"Total tools tested: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if failed > 0:
        print("\nFailed tools:")
        for tool, success in results.items():
            if not success:
                print(f"  - {tool}")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

