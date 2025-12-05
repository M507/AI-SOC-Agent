"""
Low-level HTTP client for IRIS.

This module is responsible for:
- authentication (API key header)
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


logger = get_logger("sami.integrations.iris.http")


@dataclass
class IrisHttpClient:
    """
    Simple HTTP client for IRIS's REST API.
    
    IRIS API documentation: https://docs.dfir-iris.org/
    """

    base_url: str
    api_key: str
    timeout_seconds: int = 30
    verify_ssl: bool = True

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def authenticate(self) -> None:
        """
        Placeholder for any explicit authentication logic.
        
        IRIS uses API keys in headers, so there may be no
        separate login step. This method exists to match the design doc
        and as a hook for future changes.
        """
        logger.debug("IrisHttpClient.authenticate called (no-op for API key)")

    def _build_url(self, endpoint: str) -> str:
        """
        Build a full URL from a base URL and an endpoint.
        
        IRIS API v2.0.0+ uses direct paths without /api/v1/ prefix for manage endpoints.
        API endpoints (like /api/ping, /api/versions) use /api/ prefix.
        
        Args:
            endpoint: API endpoint path (e.g., "/manage/cases/list" or "manage/cases/list")
        
        Returns:
            Full URL string
        """
        base = self.base_url.rstrip("/")
        endpoint = endpoint.lstrip("/")
        
        # IRIS API structure:
        # - /api/* for API endpoints (ping, versions, etc.)
        # - /manage/* for management endpoints (cases, users, etc.)
        # - /case/* for case-specific operations
        # No need to add /api/v1/ prefix - use endpoint as-is
        
        return f"{base}/{endpoint}"

    def _handle_iris_error(self, response: requests.Response) -> None:
        """
        Raise IntegrationError if the response indicates an error.
        
        IRIS API returns responses in format: {"status": "success|error", "message": "...", "data": ...}
        
        Args:
            response: HTTP response object
        
        Raises:
            IntegrationError: If the response indicates an error
        """
        if response.status_code < 400:
            # Check if response body indicates an error
            try:
                error_data = response.json()
                if error_data.get("status") == "error":
                    message = error_data.get("message", "Unknown error")
                    raise IntegrationError(f"IRIS API error: {message}")
            except (ValueError, IntegrationError):
                # If it's already an IntegrationError, re-raise it
                if isinstance(error_data, dict) and error_data.get("status") == "error":
                    raise
                # Otherwise continue (might not be JSON or might be success)
            return

        # HTTP error status code
        try:
            error_data = response.json()
            # IRIS API error format
            if error_data.get("status") == "error":
                message = error_data.get("message", f"HTTP {response.status_code}")
            else:
                message = error_data.get("message", f"HTTP {response.status_code}")
            details = error_data.get("detail") or error_data.get("error", "")
            full_message = f"{message}: {details}" if details else message
        except Exception:
            full_message = f"HTTP {response.status_code}: {response.text[:200]}"

        raise IntegrationError(f"IRIS API error: {full_message}")

    def request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make an HTTP request to IRIS API.
        
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
            logger.debug(f"IRIS {method} {url}")
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

            logger.debug(f"IRIS response status: {response.status_code}")
            if response.status_code >= 400:
                logger.error(f"IRIS API error - Status: {response.status_code}, URL: {url}, Response: {response.text[:500]}")

            self._handle_iris_error(response)

            if response.status_code == 204:  # No Content
                return {}

            response_data = response.json()
            
            # IRIS API wraps responses in {"status": "success", "message": "", "data": ...}
            # Extract the data field if present
            if isinstance(response_data, dict):
                if response_data.get("status") == "success" and "data" in response_data:
                    return response_data["data"]
                elif response_data.get("status") == "error":
                    # Error already handled by _handle_iris_error, but just in case
                    message = response_data.get("message", "Unknown error")
                    raise IntegrationError(f"IRIS API error: {message}")
            
            return response_data

        except requests.exceptions.Timeout as e:
            raise IntegrationError(f"IRIS API request timeout: {e}") from e
        except requests.exceptions.RequestException as e:
            raise IntegrationError(f"IRIS API request failed: {e}") from e

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """GET request."""
        return self.request("GET", endpoint, params=params)

    def post(self, endpoint: str, json_data: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """POST request."""
        return self.request("POST", endpoint, json_data=json_data, params=params)
    
    def post_file(
        self,
        endpoint: str,
        file_path: str,
        file_field: str = "file",
        additional_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        POST request with file upload.
        
        Args:
            endpoint: API endpoint path
            file_path: Path to file to upload
            file_field: Form field name for the file (default: "file")
            additional_data: Additional form data to include
            params: Query parameters to include in the URL
        
        Returns:
            Response JSON as dictionary
        """
        import os
        from pathlib import Path
        
        url = self._build_url(endpoint)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            # Don't set Content-Type - let requests set it for multipart/form-data
        }
        
        if not os.path.exists(file_path):
            raise IntegrationError(f"File not found: {file_path}")
        
        try:
            with open(file_path, "rb") as f:
                files = {file_field: (os.path.basename(file_path), f)}
                data = additional_data or {}
                
                logger.debug(f"IRIS POST FILE {url}")
                if params:
                    logger.debug(f"  Query params: {params}")
                logger.debug(f"  File: {file_path}, Field: {file_field}")
                
                response = requests.post(
                    url,
                    headers=headers,
                    files=files,
                    data=data,
                    params=params,
                    timeout=self.timeout_seconds,
                    verify=self.verify_ssl,
                )
                
                logger.debug(f"IRIS response status: {response.status_code}")
                if response.status_code >= 400:
                    logger.error(f"IRIS API error - Status: {response.status_code}, URL: {url}, Response: {response.text[:500]}")
                
                self._handle_iris_error(response)
                
                if response.status_code == 204:
                    return {}
                
                return response.json()
        except requests.exceptions.Timeout as e:
            raise IntegrationError(f"IRIS API request timeout: {e}") from e
        except requests.exceptions.RequestException as e:
            raise IntegrationError(f"IRIS API request failed: {e}") from e

    def patch(self, endpoint: str, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """PATCH request."""
        return self.request("PATCH", endpoint, json_data=json_data)

    def delete(self, endpoint: str) -> Dict[str, Any]:
        """DELETE request."""
        return self.request("DELETE", endpoint)

