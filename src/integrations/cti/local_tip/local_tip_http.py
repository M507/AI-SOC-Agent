"""
Low-level HTTP client for Local TIP (Threat Intelligence Platform).

This module handles HTTP requests to the local TIP API for hash lookups.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

import requests

from ....core.errors import IntegrationError
from ....core.logging import get_logger


logger = get_logger("sami.integrations.cti.local_tip.http")


class LocalTipHttpClient:
    """
    HTTP client for Local TIP API.
    
    Handles hash lookups via POST /hashes endpoint.
    """

    def __init__(
        self,
        base_url: str,
        timeout_seconds: int = 30,
        verify_ssl: bool = True,
    ) -> None:
        """
        Initialize the Local TIP HTTP client.
        
        Args:
            base_url: Base URL of the TIP API (e.g., "http://10.10.10.95:8084")
            timeout_seconds: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.verify_ssl = verify_ssl

    def _headers(self) -> Dict[str, str]:
        """Build request headers."""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def lookup_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """
        Look up a hash via the API endpoint.
        
        Uses POST /hashes which acts as an upsert - returns existing hash or creates new one.
        
        Args:
            hash_value: The hash value to look up (MD5, SHA1, SHA256, SHA512)
            
        Returns:
            Dictionary containing hash information, or None if lookup failed
            
        Raises:
            IntegrationError: If the API request fails
        """
        url = f"{self.base_url}/hashes"
        payload = {"value": hash_value.strip()}
        
        try:
            logger.debug(f"Looking up hash: {hash_value[:16]}... (POST {url})")
            
            response = requests.post(
                url,
                json=payload,
                headers=self._headers(),
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
            )
            
            response.raise_for_status()
            result = response.json()
            
            logger.debug(f"Hash lookup successful for {hash_value[:16]}...")
            return result
            
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout looking up hash {hash_value[:16]}...: {e}")
            raise IntegrationError(f"Timeout looking up hash: {e}") from e
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed for hash {hash_value[:16]}...: {e}")
            
            # Try to extract error details from response
            error_detail = None
            if hasattr(e, "response") and e.response is not None:
                try:
                    error_detail = e.response.json()
                    if "detail" in error_detail:
                        error_detail = error_detail["detail"]
                except Exception:
                    if e.response.text:
                        error_detail = e.response.text[:200]
            
            error_msg = f"API request failed: {e}"
            if error_detail:
                error_msg += f" - {error_detail}"
            
            raise IntegrationError(error_msg) from e

