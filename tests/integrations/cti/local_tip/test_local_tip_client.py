"""
Unit tests for Local TIP CTI client.

Tests hash lookup functionality and error handling.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import requests

from src.core.config import CTIConfig, SamiConfig
from src.core.errors import IntegrationError
from src.integrations.cti.local_tip.local_tip_http import LocalTipHttpClient
from src.integrations.cti.local_tip.local_tip_client import LocalTipCTIClient


class TestLocalTipHttpClient:
    """Test the Local TIP HTTP client."""

    def test_init(self):
        """Test HTTP client initialization."""
        client = LocalTipHttpClient(
            base_url="http://10.10.10.95:8084",
            timeout_seconds=30,
            verify_ssl=False,
        )
        assert client.base_url == "http://10.10.10.95:8084"
        assert client.timeout_seconds == 30
        assert client.verify_ssl is False

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from base_url."""
        client = LocalTipHttpClient(
            base_url="http://10.10.10.95:8084/",
            timeout_seconds=30,
        )
        assert client.base_url == "http://10.10.10.95:8084"

    @patch("src.integrations.cti.local_tip.local_tip_http.requests.post")
    def test_lookup_hash_success(self, mock_post):
        """Test successful hash lookup."""
        # Setup mock response
        mock_response = Mock()
        mock_response.json.return_value = {
            "value": "abc123def456",
            "type": "sha256",
            "threat_score": 85,
            "classification": "malicious",
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        # Test
        client = LocalTipHttpClient(
            base_url="http://10.10.10.95:8084",
            timeout_seconds=30,
        )
        result = client.lookup_hash("abc123def456")

        # Verify
        assert result is not None
        assert result["value"] == "abc123def456"
        assert result["threat_score"] == 85
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == "http://10.10.10.95:8084/hashes"
        assert call_args[1]["json"] == {"value": "abc123def456"}
        assert call_args[1]["timeout"] == 30

    @patch("src.integrations.cti.local_tip.local_tip_http.requests.post")
    def test_lookup_hash_strips_whitespace(self, mock_post):
        """Test that hash value whitespace is stripped."""
        mock_response = Mock()
        mock_response.json.return_value = {"value": "abc123", "type": "sha256"}
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        client = LocalTipHttpClient(base_url="http://10.10.10.95:8084")
        result = client.lookup_hash("  abc123  ")

        assert result is not None
        call_args = mock_post.call_args
        assert call_args[1]["json"] == {"value": "abc123"}

    @patch("src.integrations.cti.local_tip.local_tip_http.requests.post")
    def test_lookup_hash_timeout(self, mock_post):
        """Test timeout handling."""
        mock_post.side_effect = requests.exceptions.Timeout("Request timed out")

        client = LocalTipHttpClient(base_url="http://10.10.10.95:8084")
        
        with pytest.raises(IntegrationError) as exc_info:
            client.lookup_hash("abc123")
        
        assert "Timeout" in str(exc_info.value)

    @patch("src.integrations.cti.local_tip.local_tip_http.requests.post")
    def test_lookup_hash_http_error(self, mock_post):
        """Test HTTP error handling."""
        mock_response = Mock()
        mock_response.json.return_value = {"detail": "Hash not found"}
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "404 Not Found", response=mock_response
        )
        mock_post.return_value = mock_response

        client = LocalTipHttpClient(base_url="http://10.10.10.95:8084")
        
        with pytest.raises(IntegrationError) as exc_info:
            client.lookup_hash("abc123")
        
        assert "API request failed" in str(exc_info.value)

    @patch("src.integrations.cti.local_tip.local_tip_http.requests.post")
    def test_lookup_hash_http_error_with_detail(self, mock_post):
        """Test HTTP error with detail message."""
        mock_response = Mock()
        mock_response.json.return_value = {"detail": "Invalid hash format"}
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "400 Bad Request", response=mock_response
        )
        mock_post.return_value = mock_response

        client = LocalTipHttpClient(base_url="http://10.10.10.95:8084")
        
        with pytest.raises(IntegrationError) as exc_info:
            client.lookup_hash("invalid")
        
        assert "Invalid hash format" in str(exc_info.value)

    @patch("src.integrations.cti.local_tip.local_tip_http.requests.post")
    def test_lookup_hash_verify_ssl(self, mock_post):
        """Test SSL verification setting."""
        mock_response = Mock()
        mock_response.json.return_value = {"value": "abc123"}
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        client = LocalTipHttpClient(
            base_url="http://10.10.10.95:8084",
            verify_ssl=False,
        )
        client.lookup_hash("abc123")

        call_args = mock_post.call_args
        assert call_args[1]["verify"] is False


class TestLocalTipCTIClient:
    """Test the Local TIP CTI client."""

    def test_from_config_success(self):
        """Test client creation from config."""
        config = SamiConfig(
            cti=CTIConfig(
                cti_type="local_tip",
                base_url="http://10.10.10.95:8084",
                timeout_seconds=30,
                verify_ssl=False,
            )
        )

        client = LocalTipCTIClient.from_config(config)

        assert client is not None
        assert client._http.base_url == "http://10.10.10.95:8084"
        assert client._http.timeout_seconds == 30
        assert client._http.verify_ssl is False

    def test_from_config_no_cti(self):
        """Test that error is raised when CTI config is missing."""
        config = SamiConfig(cti=None)

        with pytest.raises(IntegrationError) as exc_info:
            LocalTipCTIClient.from_config(config)
        
        assert "CTI configuration is not set" in str(exc_info.value)

    def test_from_config_wrong_type(self):
        """Test that error is raised for unsupported CTI type."""
        config = SamiConfig(
            cti=CTIConfig(
                cti_type="other_tip",
                base_url="http://example.com",
            )
        )

        with pytest.raises(IntegrationError) as exc_info:
            LocalTipCTIClient.from_config(config)
        
        assert "not supported" in str(exc_info.value)
        assert "local_tip" in str(exc_info.value)

    @patch("src.integrations.cti.local_tip.local_tip_client.LocalTipHttpClient.lookup_hash")
    def test_lookup_hash_success(self, mock_lookup):
        """Test successful hash lookup."""
        mock_lookup.return_value = {
            "value": "abc123def456",
            "type": "sha256",
            "threat_score": 85,
            "classification": "malicious",
        }

        http_client = LocalTipHttpClient(base_url="http://10.10.10.95:8084")
        client = LocalTipCTIClient(http_client=http_client)

        result = client.lookup_hash("abc123def456")

        assert result["value"] == "abc123def456"
        assert result["threat_score"] == 85
        mock_lookup.assert_called_once_with("abc123def456")

    @patch("src.integrations.cti.local_tip.local_tip_client.LocalTipHttpClient.lookup_hash")
    def test_lookup_hash_returns_none(self, mock_lookup):
        """Test handling when lookup returns None."""
        mock_lookup.return_value = None

        http_client = LocalTipHttpClient(base_url="http://10.10.10.95:8084")
        client = LocalTipCTIClient(http_client=http_client)

        with pytest.raises(IntegrationError) as exc_info:
            client.lookup_hash("abc123")
        
        assert "returned no result" in str(exc_info.value)

    @patch("src.integrations.cti.local_tip.local_tip_client.LocalTipHttpClient.lookup_hash")
    def test_lookup_hash_http_error(self, mock_lookup):
        """Test error propagation from HTTP client."""
        mock_lookup.side_effect = IntegrationError("API request failed")

        http_client = LocalTipHttpClient(base_url="http://10.10.10.95:8084")
        client = LocalTipCTIClient(http_client=http_client)

        with pytest.raises(IntegrationError) as exc_info:
            client.lookup_hash("abc123")
        
        assert "Failed to lookup hash" in str(exc_info.value)

    @patch("src.integrations.cti.local_tip.local_tip_client.LocalTipHttpClient.lookup_hash")
    def test_lookup_hash_generic_exception(self, mock_lookup):
        """Test handling of generic exceptions."""
        mock_lookup.side_effect = Exception("Unexpected error")

        http_client = LocalTipHttpClient(base_url="http://10.10.10.95:8084")
        client = LocalTipCTIClient(http_client=http_client)

        with pytest.raises(IntegrationError) as exc_info:
            client.lookup_hash("abc123")
        
        assert "Failed to lookup hash" in str(exc_info.value)

