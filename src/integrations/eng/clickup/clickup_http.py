"""
Low-level HTTP client for ClickUp API.

This module is responsible for:
- authentication (API token)
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


logger = get_logger("sami.integrations.clickup.http")


@dataclass
class ClickUpHttpClient:
    """
    Simple HTTP client for ClickUp's REST API.
    
    ClickUp API documentation: https://clickup.com/api
    """

    api_token: str
    timeout_seconds: int = 30
    verify_ssl: bool = True

    def _headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        return {
            "Authorization": self.api_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _build_url(self, endpoint: str) -> str:
        """
        Build a full URL from an endpoint.
        
        Args:
            endpoint: API endpoint path (e.g., "/v2/list/{list_id}/task")
        
        Returns:
            Full URL string
        """
        # Official ClickUp API base URL is https://api.clickup.com/api/v2/...
        # We keep the version in the endpoint and include the /api prefix here.
        base_url = "https://api.clickup.com/api"
        endpoint = endpoint.lstrip("/")
        return f"{base_url}/{endpoint}"

    def _handle_clickup_error(self, response: requests.Response) -> None:
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
            message = error_data.get("err", error_data.get("message", f"HTTP {response.status_code}"))
        except Exception:
            message = f"HTTP {response.status_code}: {response.text[:200]}"

        raise IntegrationError(f"ClickUp API error: {message}")

    def request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make an HTTP request to ClickUp API.
        
        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE)
            endpoint: API endpoint path
            json_data: JSON payload (for POST, PUT, PATCH)
            params: Query parameters
        
        Returns:
            Response JSON as dictionary
        
        Raises:
            IntegrationError: If the request fails
        """
        url = self._build_url(endpoint)
        headers = self._headers()

        try:
            logger.debug(f"ClickUp {method} {url}")
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

            logger.debug(f"ClickUp response status: {response.status_code}")
            if response.status_code >= 400:
                logger.error(f"ClickUp API error - Status: {response.status_code}, URL: {url}, Response: {response.text[:500]}")

            self._handle_clickup_error(response)

            if response.status_code == 204:  # No Content
                return {}

            return response.json()

        except requests.exceptions.Timeout as e:
            raise IntegrationError(f"ClickUp API request timeout: {e}") from e
        except requests.exceptions.RequestException as e:
            raise IntegrationError(f"ClickUp API request failed: {e}") from e

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """GET request."""
        return self.request("GET", endpoint, params=params)

    def post(self, endpoint: str, json_data: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """POST request."""
        return self.request("POST", endpoint, json_data=json_data, params=params)

    def put(self, endpoint: str, json_data: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """PUT request."""
        return self.request("PUT", endpoint, json_data=json_data, params=params)

    def delete(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """DELETE request."""
        return self.request("DELETE", endpoint, params=params)

