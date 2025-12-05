#!/usr/bin/env python3
"""
Comprehensive tests for OpenCTI integration library.

Tests all Python functions in the OpenCTI integration to ensure they work correctly.
"""

import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import requests

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from src.core.config import CTIConfig, SamiConfig
from src.core.errors import IntegrationError
from src.integrations.cti.opencti.opencti_http import OpenCTIHttpClient
from src.integrations.cti.opencti.opencti_client import OpenCTIClient


class TestOpenCTIHttpClient:
    """Test the OpenCTI HTTP client."""
    
    def test_init(self):
        """Test HTTP client initialization."""
        client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
            timeout_seconds=30,
            verify_ssl=False,
        )
        assert client.base_url == "https://opencti.example.com"
        assert client.api_key == "test-api-key"
        assert client.timeout_seconds == 30
        assert client.verify_ssl is False
        assert client.graphql_endpoint == "https://opencti.example.com/graphql"
        print("✓ test_init: PASSED")
    
    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from base_url."""
        client = OpenCTIHttpClient(
            base_url="https://opencti.example.com/",
            api_key="test-api-key",
            timeout_seconds=30,
        )
        assert client.base_url == "https://opencti.example.com"
        assert client.graphql_endpoint == "https://opencti.example.com/graphql"
        print("✓ test_init_strips_trailing_slash: PASSED")
    
    def test_get_hash_type(self):
        """Test hash type detection."""
        client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
        )
        
        assert client._get_hash_type("a" * 32) == "MD5"
        assert client._get_hash_type("a" * 40) == "SHA1"
        assert client._get_hash_type("a" * 64) == "SHA256"
        assert client._get_hash_type("a" * 128) == "SHA512"
        assert client._get_hash_type("a" * 50) == "SHA256"  # Default
        print("✓ test_get_hash_type: PASSED")
    
    def test_headers(self):
        """Test header construction."""
        client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key-123",
        )
        headers = client._headers()
        
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "application/json"
        assert headers["Authorization"] == "Bearer test-api-key-123"
        print("✓ test_headers: PASSED")
    
    @patch("src.integrations.cti.opencti.opencti_http.requests.post")
    def test_lookup_hash_success(self, mock_post):
        """Test successful hash lookup."""
        # Setup mock response
        mock_response = Mock()
        mock_response.json.return_value = {
            "data": {
                "hashes": {
                    "edges": [
                        {
                            "node": {
                                "id": "hash-123",
                                "value": "abc123def456",
                                "algorithm": "SHA256",
                                "indicators": {
                                    "edges": [
                                        {
                                            "node": {
                                                "id": "indicator-123",
                                                "pattern": "[file:hashes.'SHA-256' = 'abc123def456']",
                                                "pattern_type": "stix",
                                                "valid_from": "2024-01-01T00:00:00Z",
                                                "valid_until": None,
                                                "x_opencti_score": 85,
                                                "x_opencti_detection": True,
                                                "created_at": "2024-01-01T00:00:00Z",
                                                "updated_at": "2024-01-01T00:00:00Z",
                                                "labels": {
                                                    "edges": [
                                                        {"node": {"id": "label-1", "value": "malware"}},
                                                        {"node": {"id": "label-2", "value": "trojan"}},
                                                    ]
                                                },
                                                "killChainPhases": {
                                                    "edges": [
                                                        {
                                                            "node": {
                                                                "id": "phase-1",
                                                                "kill_chain_name": "mitre-attack",
                                                                "phase_name": "execution",
                                                            }
                                                        }
                                                    ]
                                                },
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        # Test
        client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
            timeout_seconds=30,
        )
        result = client.lookup_hash("abc123def456")

        # Verify
        assert result is not None
        assert result["value"] == "abc123def456"
        assert result["algorithm"] == "SHA256"
        assert result["id"] == "hash-123"
        assert len(result["indicators"]) == 1
        assert result["indicators"][0]["id"] == "indicator-123"
        assert result["indicators"][0]["score"] == 85
        assert result["indicators"][0]["detection"] is True
        assert "malware" in result["indicators"][0]["labels"]
        assert "trojan" in result["indicators"][0]["labels"]
        assert len(result["indicators"][0]["kill_chain_phases"]) == 1
        assert result["indicators"][0]["kill_chain_phases"][0]["kill_chain_name"] == "mitre-attack"
        assert result["indicators"][0]["kill_chain_phases"][0]["phase_name"] == "execution"
        
        # Verify API call
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://opencti.example.com/graphql"
        assert "query" in call_args[1]["json"]
        assert "variables" in call_args[1]["json"]
        assert call_args[1]["json"]["variables"]["hashValue"] == "abc123def456"
        assert call_args[1]["json"]["variables"]["hashAlgorithm"] == "SHA256"
        assert call_args[1]["timeout"] == 30
        assert "Authorization" in call_args[1]["headers"]
        assert call_args[1]["headers"]["Authorization"] == "Bearer test-api-key"
        print("✓ test_lookup_hash_success: PASSED")
    
    @patch("src.integrations.cti.opencti.opencti_http.requests.post")
    def test_lookup_hash_not_found(self, mock_post):
        """Test hash lookup when hash is not found."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "data": {
                "hashes": {
                    "edges": []
                }
            }
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
        )
        result = client.lookup_hash("nonexistent")

        assert result is None
        print("✓ test_lookup_hash_not_found: PASSED")
    
    @patch("src.integrations.cti.opencti.opencti_http.requests.post")
    def test_lookup_hash_strips_whitespace(self, mock_post):
        """Test that hash value whitespace is stripped."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "data": {"hashes": {"edges": []}}
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
        )
        client.lookup_hash("  abc123  ")

        call_args = mock_post.call_args
        variables = call_args[1]["json"]["variables"]
        assert variables["hashValue"] == "abc123"
        print("✓ test_lookup_hash_strips_whitespace: PASSED")
    
    @patch("src.integrations.cti.opencti.opencti_http.requests.post")
    def test_lookup_hash_timeout(self, mock_post):
        """Test timeout handling."""
        mock_post.side_effect = requests.exceptions.Timeout("Request timed out")

        client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
        )
        
        try:
            client.lookup_hash("abc123")
            assert False, "Should have raised IntegrationError"
        except IntegrationError as e:
            assert "Timeout" in str(e)
        print("✓ test_lookup_hash_timeout: PASSED")
    
    @patch("src.integrations.cti.opencti.opencti_http.requests.post")
    def test_lookup_hash_graphql_errors(self, mock_post):
        """Test GraphQL error handling."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "errors": [
                {"message": "Invalid query syntax"}
            ]
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
        )
        
        try:
            client.lookup_hash("abc123")
            assert False, "Should have raised IntegrationError"
        except IntegrationError as e:
            assert "GraphQL query failed" in str(e)
            assert "Invalid query syntax" in str(e)
        print("✓ test_lookup_hash_graphql_errors: PASSED")
    
    @patch("src.integrations.cti.opencti.opencti_http.requests.post")
    def test_lookup_hash_http_error(self, mock_post):
        """Test HTTP error handling."""
        mock_response = Mock()
        mock_response.json.return_value = {"detail": "Unauthorized"}
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "401 Unauthorized", response=mock_response
        )
        mock_post.return_value = mock_response

        client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
        )
        
        try:
            client.lookup_hash("abc123")
            assert False, "Should have raised IntegrationError"
        except IntegrationError as e:
            assert "API request failed" in str(e)
        print("✓ test_lookup_hash_http_error: PASSED")
    
    @patch("src.integrations.cti.opencti.opencti_http.requests.post")
    def test_lookup_hash_verify_ssl(self, mock_post):
        """Test SSL verification setting."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "data": {"hashes": {"edges": []}}
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
            verify_ssl=False,
        )
        client.lookup_hash("abc123")

        call_args = mock_post.call_args
        assert call_args[1]["verify"] is False
        print("✓ test_lookup_hash_verify_ssl: PASSED")


class TestOpenCTIClient:
    """Test the OpenCTI CTI client."""
    
    def test_from_config_success(self):
        """Test client creation from config."""
        config = SamiConfig(
            cti=CTIConfig(
                cti_type="opencti",
                base_url="https://opencti.example.com",
                api_key="test-api-key",
                timeout_seconds=30,
                verify_ssl=False,
            )
        )

        client = OpenCTIClient.from_config(config)

        assert client is not None
        assert client._http.base_url == "https://opencti.example.com"
        assert client._http.api_key == "test-api-key"
        assert client._http.timeout_seconds == 30
        assert client._http.verify_ssl is False
        print("✓ test_from_config_success: PASSED")
    
    def test_from_config_no_cti(self):
        """Test that error is raised when CTI config is missing."""
        config = SamiConfig(cti=None)

        try:
            OpenCTIClient.from_config(config)
            assert False, "Should have raised IntegrationError"
        except IntegrationError as e:
            assert "CTI configuration is not set" in str(e)
        print("✓ test_from_config_no_cti: PASSED")
    
    def test_from_config_wrong_type(self):
        """Test that error is raised for unsupported CTI type."""
        config = SamiConfig(
            cti=CTIConfig(
                cti_type="local_tip",
                base_url="http://example.com",
            )
        )

        try:
            OpenCTIClient.from_config(config)
            assert False, "Should have raised IntegrationError"
        except IntegrationError as e:
            assert "not supported" in str(e)
            assert "opencti" in str(e)
        print("✓ test_from_config_wrong_type: PASSED")
    
    def test_from_config_no_api_key(self):
        """Test that error is raised when API key is missing."""
        config = SamiConfig(
            cti=CTIConfig(
                cti_type="opencti",
                base_url="https://opencti.example.com",
                api_key=None,
            )
        )

        try:
            OpenCTIClient.from_config(config)
            assert False, "Should have raised IntegrationError"
        except IntegrationError as e:
            assert "API key" in str(e)
        print("✓ test_from_config_no_api_key: PASSED")
    
    @patch("src.integrations.cti.opencti.opencti_client.OpenCTIHttpClient.lookup_hash")
    def test_lookup_hash_success(self, mock_lookup):
        """Test successful hash lookup."""
        mock_lookup.return_value = {
            "value": "abc123def456",
            "algorithm": "SHA256",
            "id": "hash-123",
            "indicators": [
                {
                    "id": "indicator-123",
                    "pattern": "[file:hashes.'SHA-256' = 'abc123def456']",
                    "score": 85,
                    "detection": True,
                }
            ],
        }

        http_client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
        )
        client = OpenCTIClient(http_client=http_client)

        result = client.lookup_hash("abc123def456")

        assert result["value"] == "abc123def456"
        assert result["found"] is True
        assert len(result["indicators"]) == 1
        assert result["indicators"][0]["score"] == 85
        mock_lookup.assert_called_once_with("abc123def456")
        print("✓ test_lookup_hash_success: PASSED")
    
    @patch("src.integrations.cti.opencti.opencti_client.OpenCTIHttpClient.lookup_hash")
    def test_lookup_hash_returns_none(self, mock_lookup):
        """Test handling when lookup returns None."""
        mock_lookup.return_value = None

        http_client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
        )
        client = OpenCTIClient(http_client=http_client)

        result = client.lookup_hash("abc123")

        assert result["found"] is False
        assert result["value"] == "abc123"
        assert result["indicators"] == []
        print("✓ test_lookup_hash_returns_none: PASSED")
    
    @patch("src.integrations.cti.opencti.opencti_client.OpenCTIHttpClient.lookup_hash")
    def test_lookup_hash_http_error(self, mock_lookup):
        """Test error propagation from HTTP client."""
        mock_lookup.side_effect = IntegrationError("API request failed")

        http_client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
        )
        client = OpenCTIClient(http_client=http_client)

        try:
            client.lookup_hash("abc123")
            assert False, "Should have raised IntegrationError"
        except IntegrationError as e:
            # IntegrationError from HTTP client is re-raised as-is (not wrapped)
            assert "API request failed" in str(e) or "Failed to lookup hash" in str(e)
        print("✓ test_lookup_hash_http_error: PASSED")
    
    @patch("src.integrations.cti.opencti.opencti_client.OpenCTIHttpClient.lookup_hash")
    def test_lookup_hash_generic_exception(self, mock_lookup):
        """Test handling of generic exceptions."""
        mock_lookup.side_effect = Exception("Unexpected error")

        http_client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
        )
        client = OpenCTIClient(http_client=http_client)

        try:
            client.lookup_hash("abc123")
            assert False, "Should have raised IntegrationError"
        except IntegrationError as e:
            assert "Failed to lookup hash" in str(e)
        print("✓ test_lookup_hash_generic_exception: PASSED")
    
    @patch("src.integrations.cti.opencti.opencti_client.OpenCTIHttpClient.lookup_hash")
    def test_lookup_hash_different_hash_types(self, mock_lookup):
        """Test lookup with different hash types."""
        mock_lookup.return_value = {
            "value": "test-hash",
            "algorithm": "MD5",
            "found": True,
            "indicators": [],
        }

        http_client = OpenCTIHttpClient(
            base_url="https://opencti.example.com",
            api_key="test-api-key",
        )
        client = OpenCTIClient(http_client=http_client)

        # Test MD5
        result = client.lookup_hash("a" * 32)
        assert result["found"] is True
        
        # Test SHA1
        result = client.lookup_hash("a" * 40)
        assert result["found"] is True
        
        # Test SHA256
        result = client.lookup_hash("a" * 64)
        assert result["found"] is True
        
        # Test SHA512
        result = client.lookup_hash("a" * 128)
        assert result["found"] is True
        
        print("✓ test_lookup_hash_different_hash_types: PASSED")


def run_all_tests():
    """Run all tests."""
    print("=" * 80)
    print("OpenCTI Library Tests")
    print("=" * 80)
    print()
    
    test_classes = [TestOpenCTIHttpClient, TestOpenCTIClient]
    total_tests = 0
    passed_tests = 0
    failed_tests = []
    
    for test_class in test_classes:
        class_name = test_class.__name__
        print(f"\n{'-' * 80}")
        print(f"Running {class_name}...")
        print(f"{'-' * 80}")
        
        test_instance = test_class()
        test_methods = [method for method in dir(test_instance) if method.startswith("test_")]
        
        for test_method_name in test_methods:
            total_tests += 1
            test_method = getattr(test_instance, test_method_name)
            try:
                test_method()
                passed_tests += 1
            except Exception as e:
                failed_tests.append(f"{class_name}.{test_method_name}")
                print(f"✗ {test_method_name}: FAILED - {e}")
                import traceback
                traceback.print_exc()
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Total tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {len(failed_tests)}")
    
    if failed_tests:
        print("\nFailed tests:")
        for test in failed_tests:
            print(f"  - {test}")
        return 1
    
    print("\n✓ All tests PASSED!")
    return 0


if __name__ == "__main__":
    sys.exit(run_all_tests())

