"""
Low-level HTTP client for GitHub API.

This module is responsible for:
- authentication (Personal Access Token)
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


logger = get_logger("sami.integrations.github.http")


@dataclass
class GitHubHttpClient:
    """
    Simple HTTP client for GitHub's REST API.
    
    GitHub API documentation: https://docs.github.com/en/rest
    """

    api_token: str
    timeout_seconds: int = 30
    verify_ssl: bool = True

    def _headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _build_url(self, endpoint: str) -> str:
        """
        Build a full URL from an endpoint.
        
        Args:
            endpoint: API endpoint path (e.g., "/repos/{owner}/{repo}/projects")
        
        Returns:
            Full URL string
        """
        base_url = "https://api.github.com"
        endpoint = endpoint.lstrip("/")
        return f"{base_url}/{endpoint}"

    def _handle_github_error(self, response: requests.Response) -> None:
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
            errors = error_data.get("errors", [])
            if errors:
                error_details = "; ".join([str(e) for e in errors])
                message = f"{message}: {error_details}"
        except Exception:
            message = f"HTTP {response.status_code}: {response.text[:200]}"

        raise IntegrationError(f"GitHub API error: {message}")

    def request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make an HTTP request to GitHub API.
        
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
            logger.debug(f"GitHub {method} {url}")
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

            logger.debug(f"GitHub response status: {response.status_code}")
            if response.status_code >= 400:
                logger.error(f"GitHub API error - Status: {response.status_code}, URL: {url}, Response: {response.text[:500]}")

            self._handle_github_error(response)

            if response.status_code == 204:  # No Content
                return {}

            return response.json()

        except requests.exceptions.Timeout as e:
            raise IntegrationError(f"GitHub API request timeout: {e}") from e
        except requests.exceptions.RequestException as e:
            raise IntegrationError(f"GitHub API request failed: {e}") from e

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

