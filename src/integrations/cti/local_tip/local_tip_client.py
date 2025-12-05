"""
Local TIP (Threat Intelligence Platform) implementation of CTI client.

This client provides hash lookup capabilities via the local TIP API.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ....core.config import SamiConfig
from ....core.errors import IntegrationError
from ....core.logging import get_logger
from .local_tip_http import LocalTipHttpClient


logger = get_logger("sami.integrations.cti.local_tip.client")


class LocalTipCTIClient:
    """
    CTI client backed by Local TIP.
    
    Provides threat intelligence lookup capabilities for hashes.
    """

    def __init__(self, http_client: LocalTipHttpClient) -> None:
        """
        Initialize the Local TIP CTI client.
        
        Args:
            http_client: HTTP client for making API requests
        """
        self._http = http_client

    @classmethod
    def from_config(cls, config: SamiConfig) -> "LocalTipCTIClient":
        """
        Factory to construct a client from SamiConfig.
        
        Args:
            config: SamiConfig instance with CTI configuration
            
        Returns:
            LocalTipCTIClient instance
            
        Raises:
            IntegrationError: If CTI configuration is not set
        """
        if not config.cti:
            raise IntegrationError("CTI configuration is not set in SamiConfig")
        
        if config.cti.cti_type != "local_tip":
            raise IntegrationError(
                f"CTI type '{config.cti.cti_type}' is not supported. Only 'local_tip' is supported."
            )

        http_client = LocalTipHttpClient(
            base_url=config.cti.base_url,
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
                raise IntegrationError(f"Hash lookup returned no result for {hash_value[:16]}...")
            
            return result
        except Exception as e:
            logger.exception(f"Error looking up hash {hash_value[:16]}...: {e}")
            if isinstance(e, IntegrationError):
                raise
            raise IntegrationError(f"Failed to lookup hash: {e}") from e

