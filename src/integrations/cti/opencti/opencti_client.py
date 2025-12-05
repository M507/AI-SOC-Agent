"""
OpenCTI (Open Cyber Threat Intelligence Platform) implementation of CTI client.

This client provides hash lookup capabilities via the OpenCTI GraphQL API.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ....core.config import SamiConfig
from ....core.errors import IntegrationError
from ....core.logging import get_logger
from .opencti_http import OpenCTIHttpClient


logger = get_logger("sami.integrations.cti.opencti.client")


class OpenCTIClient:
    """
    CTI client backed by OpenCTI.
    
    Provides threat intelligence lookup capabilities for hashes.
    """

    def __init__(self, http_client: OpenCTIHttpClient) -> None:
        """
        Initialize the OpenCTI CTI client.
        
        Args:
            http_client: HTTP client for making API requests
        """
        self._http = http_client

    @classmethod
    def from_config(cls, config: SamiConfig) -> "OpenCTIClient":
        """
        Factory to construct a client from SamiConfig.
        
        Args:
            config: SamiConfig instance with CTI configuration
            
        Returns:
            OpenCTIClient instance
            
        Raises:
            IntegrationError: If CTI configuration is not set or invalid
        """
        if not config.cti:
            raise IntegrationError("CTI configuration is not set in SamiConfig")
        
        if config.cti.cti_type != "opencti":
            raise IntegrationError(
                f"CTI type '{config.cti.cti_type}' is not supported. Only 'opencti' is supported."
            )
        
        if not config.cti.api_key:
            raise IntegrationError("OpenCTI requires an API key. Set 'api_key' in CTI configuration.")

        http_client = OpenCTIHttpClient(
            base_url=config.cti.base_url,
            api_key=config.cti.api_key,
            timeout_seconds=config.cti.timeout_seconds,
            verify_ssl=config.cti.verify_ssl,
        )
        return cls(http_client=http_client)

    def lookup_hash(self, hash_value: str) -> Dict[str, Any]:
        """
        Look up a hash in the threat intelligence platform.
        
        Args:
            hash_value: The hash value to look up (MD5, SHA1, SHA256, SHA512)
            
        Returns:
            Dictionary containing hash intelligence information
            
        Raises:
            IntegrationError: If lookup fails
        """
        try:
            result = self._http.lookup_hash(hash_value)
            
            if result is None:
                # Return a structured response even when hash is not found
                return {
                    "value": hash_value.strip(),
                    "found": False,
                    "indicators": [],
                }
            
            # Add found flag
            result["found"] = True
            return result
        except Exception as e:
            logger.exception(f"Error looking up hash {hash_value[:16]}...: {e}")
            if isinstance(e, IntegrationError):
                raise
            raise IntegrationError(f"Failed to lookup hash: {e}") from e

