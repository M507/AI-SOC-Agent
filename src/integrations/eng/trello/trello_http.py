"""
Low-level HTTP client for Trello API.

This module is responsible for:
- authentication (API key and token)
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


logger = get_logger("sami.integrations.trello.http")


@dataclass
class TrelloHttpClient:
    """
    Simple HTTP client for Trello's REST API.
    
    Trello API documentation: https://developer.atlassian.com/cloud/trello/guides/rest-api/api-introduction/
    """

    api_key: str
    api_token: str
    timeout_seconds: int = 30
    verify_ssl: bool = True

    def _auth_params(self) -> Dict[str, str]:
        """Get authentication query parameters."""
        return {
            "key": self.api_key,
            "token": self.api_token,
        }

    def _build_url(self, endpoint: str) -> str:
        """
        Build a full URL from an endpoint.
        
        Args:
            endpoint: API endpoint path (e.g., "/1/boards/{boardId}/cards")
        
        Returns:
            Full URL string
        """
        base_url = "https://api.trello.com"
        endpoint = endpoint.lstrip("/")
        return f"{base_url}/{endpoint}"

    def _handle_trello_error(self, response: requests.Response) -> None:
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
            message = error_data.get("message", f"HTTP {response.status_code}")
        except Exception:
            message = f"HTTP {response.status_code}: {response.text[:200]}"

        raise IntegrationError(f"Trello API error: {message}")

    def request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make an HTTP request to Trello API.
        
        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE)
            endpoint: API endpoint path
            json_data: JSON payload (for POST, PUT, PATCH)
            params: Query parameters (merged with auth params)
        
        Returns:
            Response JSON as dictionary
        
        Raises:
            IntegrationError: If the request fails
        """
        url = self._build_url(endpoint)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        # Merge auth params with provided params
        all_params = self._auth_params().copy()
        if params:
            all_params.update(params)

        try:
            logger.debug(f"Trello {method} {url}")
            if all_params:
                logger.debug(f"  Query params: {all_params}")
            if json_data:
                logger.debug(f"  JSON payload: {json.dumps(json_data)[:200]}...")

            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data,
                params=all_params,
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
            )

            logger.debug(f"Trello response status: {response.status_code}")
            if response.status_code >= 400:
                logger.error(f"Trello API error - Status: {response.status_code}, URL: {url}, Response: {response.text[:500]}")

            self._handle_trello_error(response)

            if response.status_code == 204:  # No Content
                return {}

            return response.json()

        except requests.exceptions.Timeout as e:
            raise IntegrationError(f"Trello API request timeout: {e}") from e
        except requests.exceptions.RequestException as e:
            raise IntegrationError(f"Trello API request failed: {e}") from e

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

