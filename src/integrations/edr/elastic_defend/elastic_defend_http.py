"""
Low-level HTTP client for Elastic Defend (Endpoint Security).

This module is responsible for:
- authentication (API key)
- building URLs
- making HTTP requests
- basic error handling
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from ....core.errors import IntegrationError
from ....core.logging import get_logger


logger = get_logger("sami.integrations.elastic_defend.http")


@dataclass
class ElasticDefendHttpClient:
    """
    Simple HTTP client for Elastic Defend API.
    
    Elastic Defend uses the Elasticsearch API with API key authentication.
    """

    base_url: str
    api_key: str
    timeout_seconds: int = 30
    verify_ssl: bool = True

    def _headers(self) -> Dict[str, str]:
        """Build request headers with authentication."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        # Elastic API key format: "ApiKey <base64-encoded-key>"
        if not self.api_key.startswith("ApiKey "):
            headers["Authorization"] = f"ApiKey {self.api_key}"
        else:
            headers["Authorization"] = self.api_key
        
        return headers

    def _build_url(self, endpoint: str) -> str:
        """
        Build a full URL from a base URL and an endpoint.
        
        Elastic Defend uses endpoints like:
        - /api/fleet/agents
        - /api/endpoint/actions
        - /api/endpoint/isolate
        
        Args:
            endpoint: API endpoint path (e.g., "/api/fleet/agents" or "api/fleet/agents")
        
        Returns:
            Full URL string
        """
        base = self.base_url.rstrip("/")
        endpoint = endpoint.lstrip("/")
        
        return f"{base}/{endpoint}"

    def _handle_elastic_error(self, response: requests.Response) -> None:
        """
        Raise IntegrationError if the response indicates an error.
        
        Args:
            response: HTTP response object
        
        Raises:
            IntegrationError: If the response indicates an error
        """
        if response.status_code < 400:
            return

        try:
            error_data = response.json()
            error_type = error_data.get("error", {}).get("type", "Unknown")
            error_reason = error_data.get("error", {}).get("reason", f"HTTP {response.status_code}")
            full_message = f"{error_type}: {error_reason}"
        except Exception:
            full_message = f"HTTP {response.status_code}: {response.text[:200]}"

        raise IntegrationError(f"Elastic Defend API error: {full_message}")

    def request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make an HTTP request to Elastic Defend API.
        
        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE)
            endpoint: API endpoint path
            json_data: JSON payload (for POST, PUT, PATCH)
            params: Query parameters (for GET, etc.)
        
        Returns:
            Response JSON as dictionary
        
        Raises:
            IntegrationError: If the request fails
        """
        url = self._build_url(endpoint)
        headers = self._headers()

        try:
            logger.debug(f"Elastic Defend {method} {url}")
            if params:
                logger.debug(f"  Query params: {params}")
            if json_data:
                logger.debug(f"  JSON payload: {json.dumps(json_data)[:200]}...")

            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data,
                params=params,
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
            )

            logger.debug(f"Elastic Defend response status: {response.status_code}")
            if response.status_code >= 400:
                logger.error(f"Elastic Defend API error - Status: {response.status_code}, URL: {url}, Response: {response.text[:500]}")

            self._handle_elastic_error(response)

            if response.status_code == 204:  # No Content
                return {}

            return response.json()

        except requests.exceptions.Timeout as e:
            raise IntegrationError(f"Elastic Defend API request timeout: {e}") from e
        except requests.exceptions.RequestException as e:
            raise IntegrationError(f"Elastic Defend API request failed: {e}") from e

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """GET request."""
        return self.request("GET", endpoint, params=params)

    def post(self, endpoint: str, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """POST request."""
        return self.request("POST", endpoint, json_data=json_data)

