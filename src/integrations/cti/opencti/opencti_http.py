"""
Low-level HTTP client for OpenCTI (Open Cyber Threat Intelligence Platform).

This module handles GraphQL requests to the OpenCTI API for hash lookups.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

import requests

from ....core.errors import IntegrationError
from ....core.logging import get_logger


logger = get_logger("sami.integrations.cti.opencti.http")


class OpenCTIHttpClient:
    """
    HTTP client for OpenCTI GraphQL API.
    
    Handles hash lookups via GraphQL queries.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_seconds: int = 30,
        verify_ssl: bool = True,
    ) -> None:
        """
        Initialize the OpenCTI HTTP client.
        
        Args:
            base_url: Base URL of the OpenCTI API (e.g., "https://opencti.example.com")
            api_key: API key/token for authentication
            timeout_seconds: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.verify_ssl = verify_ssl
        # Try /api/graphql first, fallback to /graphql
        self.graphql_endpoint = f"{self.base_url}/api/graphql"
        self.graphql_endpoint_fallback = f"{self.base_url}/graphql"
        
        logger.info(
            f"OpenCTI HTTP client initialized: base_url={self.base_url}, "
            f"primary_endpoint={self.graphql_endpoint}, "
            f"fallback_endpoint={self.graphql_endpoint_fallback}, "
            f"timeout={timeout_seconds}s, verify_ssl={verify_ssl}"
        )

    def _headers(self) -> Dict[str, str]:
        """Build request headers."""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

    def _get_hash_type(self, hash_value: str) -> str:
        """
        Determine hash type based on length.
        
        Args:
            hash_value: The hash value
            
        Returns:
            Hash algorithm name (MD5, SHA1, SHA256, SHA512)
        """
        hash_length = len(hash_value.strip())
        if hash_length == 32:
            return "MD5"
        elif hash_length == 40:
            return "SHA1"
        elif hash_length == 64:
            return "SHA256"
        elif hash_length == 128:
            return "SHA512"
        else:
            # Default to SHA256 for unknown lengths
            return "SHA256"
    
    def _get_observable_type(self, hash_type: str) -> str:
        """
        Get OpenCTI observable type for hash.
        
        Args:
            hash_type: Hash algorithm name (MD5, SHA1, SHA256, SHA512)
            
        Returns:
            OpenCTI observable type (e.g., "File-SHA256")
        """
        type_map = {
            "MD5": "File-MD5",
            "SHA1": "File-SHA1",
            "SHA256": "File-SHA256",
            "SHA512": "File-SHA512",
        }
        return type_map.get(hash_type, "File-SHA256")

    def lookup_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """
        Look up a hash via the GraphQL API.
        
        Args:
            hash_value: The hash value to look up (MD5, SHA1, SHA256, SHA512)
            
        Returns:
            Dictionary containing hash information and related indicators, or None if not found
            
        Raises:
            IntegrationError: If the API request fails
        """
        hash_type = self._get_hash_type(hash_value)
        observable_type = self._get_observable_type(hash_type)
        hash_value_clean = hash_value.strip()
        
        logger.info(
            f"Starting OpenCTI hash lookup: hash={hash_value_clean[:16]}... "
            f"(type={hash_type}, observable_type={observable_type})"
        )
        
        # OpenCTI GraphQL query using stixCyberObservables
        # This is the correct way to query observables in OpenCTI
        query = """
        query HashLookup($filters: [StixCyberObservablesFiltering!], $first: Int) {
          stixCyberObservables(filters: $filters, first: $first) {
            edges {
              node {
                id
                observable_value
                entity_type
                indicators {
                  edges {
                    node {
                      id
                      pattern
                      pattern_type
                      valid_from
                      valid_until
                      x_opencti_score
                      x_opencti_detection
                      created_at
                      updated_at
                      labels {
                        edges {
                          node {
                            id
                            value
                          }
                        }
                      }
                      killChainPhases {
                        edges {
                          node {
                            id
                            kill_chain_name
                            phase_name
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        # Build filters for OpenCTI
        # Filter by observable type (e.g., "File-SHA256") and hash value
        filters = [
            {
                "key": "entity_type",
                "values": [observable_type]
            },
            {
                "key": "observable_value",
                "values": [hash_value_clean]
            }
        ]
        
        variables = {
            "filters": filters,
            "first": 10  # Limit to first 10 results
        }
        
        payload = {
            "query": query,
            "variables": variables
        }
        
        try:
            logger.debug(
                f"OpenCTI request details: endpoint={self.graphql_endpoint}, "
                f"hash_type={hash_type}, observable_type={observable_type}, "
                f"filters={filters}, timeout={self.timeout_seconds}s"
            )
            
            # Try primary endpoint first
            logger.debug(f"Sending POST request to primary endpoint: {self.graphql_endpoint}")
            response = requests.post(
                self.graphql_endpoint,
                json=payload,
                headers=self._headers(),
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
            )
            
            logger.debug(f"Primary endpoint response: status_code={response.status_code}")
            
            # If 404 on primary endpoint, try fallback
            if response.status_code == 404:
                logger.warning(
                    f"Primary endpoint {self.graphql_endpoint} returned 404 (Not Found). "
                    f"Attempting fallback endpoint: {self.graphql_endpoint_fallback}"
                )
                response = requests.post(
                    self.graphql_endpoint_fallback,
                    json=payload,
                    headers=self._headers(),
                    timeout=self.timeout_seconds,
                    verify=self.verify_ssl,
                )
                logger.debug(f"Fallback endpoint response: status_code={response.status_code}")
                
                # Update endpoint for future requests if fallback works
                if response.status_code != 404:
                    logger.info(
                        f"Fallback endpoint successful. Updating primary endpoint to: "
                        f"{self.graphql_endpoint_fallback}"
                    )
                    self.graphql_endpoint = self.graphql_endpoint_fallback
                else:
                    logger.error(
                        f"Both endpoints returned 404: primary={self.graphql_endpoint}, "
                        f"fallback={self.graphql_endpoint_fallback}"
                    )
            
            # Raise for any HTTP errors (including 404 if both endpoints fail)
            response.raise_for_status()
            
            logger.debug(f"HTTP request successful: status_code={response.status_code}")
            result = response.json()
            
            # Log response structure for debugging (without sensitive data)
            logger.debug(
                f"GraphQL response received: has_data={'data' in result}, "
                f"has_errors={'errors' in result}, response_keys={list(result.keys())}"
            )
            
            # Check for GraphQL errors
            if "errors" in result:
                error_messages = [err.get("message", "Unknown error") for err in result["errors"]]
                error_msg = "; ".join(error_messages)
                logger.error(
                    f"GraphQL query returned errors for hash {hash_value_clean[:16]}...: "
                    f"{error_msg}. Full errors: {json.dumps(result['errors'], indent=2)}"
                )
                raise IntegrationError(f"GraphQL query failed: {error_msg}")
            
            # Extract hash data from GraphQL response
            data = result.get("data", {})
            observables = data.get("stixCyberObservables", {})
            edges = observables.get("edges", [])
            
            logger.debug(
                f"Parsed GraphQL response: observables_found={len(edges)}, "
                f"observable_keys={list(observables.keys()) if observables else 'N/A'}"
            )
            
            if not edges:
                logger.info(
                    f"Hash {hash_value_clean[:16]}... (type={hash_type}) not found in OpenCTI. "
                    f"No observables matching the criteria."
                )
                return None
            
            # Get the first observable result
            observable_node = edges[0]["node"]
            observable_id = observable_node.get("id", "unknown")
            observable_value = observable_node.get("observable_value", hash_value_clean)
            
            logger.info(
                f"Found observable in OpenCTI: id={observable_id}, "
                f"value={observable_value[:16]}..., type={observable_type}"
            )
            
            # Build result dictionary
            hash_result = {
                "value": observable_value,
                "algorithm": hash_type,  # Use detected hash type
                "id": observable_id,
                "indicators": [],
            }
            
            # Extract indicators
            indicators = observable_node.get("indicators", {}).get("edges", [])
            logger.debug(f"Found {len(indicators)} indicator(s) associated with observable")
            
            for idx, indicator_edge in enumerate(indicators):
                indicator_node = indicator_edge["node"]
                indicator_id = indicator_node.get("id", "unknown")
                indicator_score = indicator_node.get("x_opencti_score")
                indicator_detection = indicator_node.get("x_opencti_detection")
                
                logger.debug(
                    f"Processing indicator {idx + 1}/{len(indicators)}: "
                    f"id={indicator_id}, score={indicator_score}, "
                    f"detection={indicator_detection}"
                )
                
                indicator = {
                    "id": indicator_id,
                    "pattern": indicator_node.get("pattern"),
                    "pattern_type": indicator_node.get("pattern_type"),
                    "valid_from": indicator_node.get("valid_from"),
                    "valid_until": indicator_node.get("valid_until"),
                    "score": indicator_score,
                    "detection": indicator_detection,
                    "created_at": indicator_node.get("created_at"),
                    "updated_at": indicator_node.get("updated_at"),
                    "labels": [],
                    "kill_chain_phases": [],
                }
                
                # Extract labels
                labels = indicator_node.get("labels", {}).get("edges", [])
                for label_edge in labels:
                    label_value = label_edge["node"].get("value")
                    indicator["labels"].append(label_value)
                
                if labels:
                    logger.debug(f"Indicator {indicator_id} has {len(labels)} label(s): {[l['node'].get('value') for l in labels]}")
                
                # Extract kill chain phases
                kill_chain = indicator_node.get("killChainPhases", {}).get("edges", [])
                for phase_edge in kill_chain:
                    phase_node = phase_edge["node"]
                    indicator["kill_chain_phases"].append({
                        "kill_chain_name": phase_node.get("kill_chain_name"),
                        "phase_name": phase_node.get("phase_name"),
                    })
                
                if kill_chain:
                    logger.debug(
                        f"Indicator {indicator_id} has {len(kill_chain)} kill chain phase(s): "
                        f"{[p['node'].get('phase_name') for p in kill_chain]}"
                    )
                
                hash_result["indicators"].append(indicator)
            
            logger.info(
                f"OpenCTI hash lookup successful: hash={hash_value_clean[:16]}..., "
                f"observable_id={observable_id}, indicators_count={len(hash_result['indicators'])}"
            )
            return hash_result
            
        except requests.exceptions.Timeout as e:
            logger.error(
                f"Timeout looking up hash {hash_value_clean[:16]}... in OpenCTI: "
                f"endpoint={self.graphql_endpoint}, timeout={self.timeout_seconds}s, error={e}"
            )
            raise IntegrationError(f"Timeout looking up hash: {e}") from e
        except requests.exceptions.RequestException as e:
            logger.error(
                f"API request failed for hash {hash_value_clean[:16]}... in OpenCTI: "
                f"endpoint={self.graphql_endpoint}, error_type={type(e).__name__}, error={e}"
            )
            
            # Try to extract error details from response
            error_detail = None
            status_code = None
            if hasattr(e, "response") and e.response is not None:
                status_code = e.response.status_code
                logger.debug(
                    f"Error response details: status_code={status_code}, "
                    f"headers={dict(e.response.headers) if e.response.headers else 'N/A'}"
                )
                
                try:
                    error_detail = e.response.json()
                    logger.debug(f"Error response JSON: {json.dumps(error_detail, indent=2)}")
                    
                    if "errors" in error_detail:
                        error_messages = [err.get("message", "Unknown error") for err in error_detail["errors"]]
                        error_detail = "; ".join(error_messages)
                    elif "detail" in error_detail:
                        error_detail = error_detail["detail"]
                except Exception as parse_error:
                    logger.debug(f"Could not parse error response as JSON: {parse_error}")
                    if e.response.text:
                        error_detail = e.response.text[:200]
                        logger.debug(f"Error response text (first 200 chars): {error_detail}")
            
            error_msg = f"API request failed: {e}"
            if status_code:
                error_msg += f" (status_code={status_code})"
            if error_detail:
                error_msg += f" - {error_detail}"
            
            logger.error(f"OpenCTI hash lookup failed: {error_msg}")
            raise IntegrationError(error_msg) from e
        except Exception as e:
            logger.exception(
                f"Unexpected error during OpenCTI hash lookup for {hash_value_clean[:16]}...: "
                f"error_type={type(e).__name__}, error={e}"
            )
            raise IntegrationError(f"Unexpected error during hash lookup: {e}") from e

