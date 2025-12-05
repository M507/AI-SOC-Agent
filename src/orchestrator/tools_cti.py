"""
LLM-callable tools for CTI (Cyber Threat Intelligence) operations.

These functions wrap the CTI client interface and provide
LLM-friendly error handling and return values.
"""

from __future__ import annotations

import concurrent.futures
from typing import Any, Dict, List, Optional

from ..core.errors import IntegrationError
from ..core.logging import get_logger

logger = get_logger("sami.orchestrator.tools_cti")


def lookup_hash_ti(
    hash_value: str,
    client=None,  # type: ignore
    clients: Optional[List] = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Look up a hash in the threat intelligence platform(s).
    
    If multiple clients are provided, queries all platforms concurrently and merges results.
    
    Tool schema:
    - name: lookup_hash_ti
    - description: Look up a file hash (MD5, SHA1, SHA256, SHA512) in the threat intelligence platform to get threat intelligence information
    - parameters:
      - hash_value (str, required): The hash value to look up
    
    Args:
        hash_value: The hash value to look up.
        client: Single CTI client (for backward compatibility).
        clients: List of CTI clients (for multi-platform support).
    
    Returns:
        Dictionary containing merged threat intelligence information from all platforms.
    
    Raises:
        IntegrationError: If all lookups fail.
    """
    # Determine which clients to use
    cti_clients = clients if clients is not None else ([client] if client is not None else [])
    
    if not cti_clients:
        raise IntegrationError("No CTI client(s) provided")
    
    # If only one client, use simple path for backward compatibility
    if len(cti_clients) == 1:
        try:
            result = cti_clients[0].lookup_hash(hash_value)
            # Ensure result has the expected structure for threat assessment
            if not isinstance(result, dict):
                result = {"value": hash_value, "found": False, "indicators": []}
            
            # Generate threat assessment for single client too
            threat_assessment = _generate_threat_assessment(result)
            
            return {
                "success": True,
                "hash_value": hash_value,
                "threat_intelligence": result,
                "sources": [_get_client_type(cti_clients[0])],
                "sources_successful": [_get_client_type(cti_clients[0])],
                "threat_assessment": threat_assessment,
            }
        except Exception as e:
            raise IntegrationError(f"Failed to lookup hash in threat intelligence: {str(e)}") from e
    
    # Multiple clients - query concurrently and merge
    return _lookup_hash_ti_multi(hash_value, cti_clients)


def _get_client_type(client) -> str:
    """Get the type name of a CTI client."""
    client_class_name = client.__class__.__name__
    if "LocalTip" in client_class_name:
        return "local_tip"
    elif "OpenCTI" in client_class_name:
        return "opencti"
    return "unknown"


def _lookup_hash_ti_multi(hash_value: str, clients: List) -> Dict[str, Any]:
    """
    Query multiple CTI platforms concurrently and merge results.
    
    Args:
        hash_value: The hash value to look up.
        clients: List of CTI clients to query.
    
    Returns:
        Merged threat intelligence information from all platforms.
    """
    results = {}
    errors = {}
    sources = []
    
    def query_client(client):
        """Query a single client and return results."""
        client_type = _get_client_type(client)
        try:
            logger.debug(f"Querying {client_type} for hash {hash_value[:16]}...")
            result = client.lookup_hash(hash_value)
            return {
                "client_type": client_type,
                "success": True,
                "result": result,
                "error": None,
            }
        except Exception as e:
            logger.warning(f"Failed to query {client_type} for hash {hash_value[:16]}...: {e}")
            return {
                "client_type": client_type,
                "success": False,
                "result": None,
                "error": str(e),
            }
    
    # Query all clients concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(clients)) as executor:
        future_to_client = {executor.submit(query_client, client): client for client in clients}
        
        for future in concurrent.futures.as_completed(future_to_client):
            response = future.result()
            client_type = response["client_type"]
            sources.append(client_type)
            
            if response["success"]:
                results[client_type] = response["result"]
            else:
                errors[client_type] = response["error"]
    
    # Merge results
    merged = _merge_cti_results(results, hash_value)
    
    # Build response with clear threat assessment
    response = {
        "success": len(results) > 0,  # Success if at least one platform returned results
        "hash_value": hash_value,
        "threat_intelligence": merged,
        "sources": sources,
        "sources_successful": list(results.keys()),
        # Add clear threat assessment summary for LLM understanding
        "threat_assessment": _generate_threat_assessment(merged),
    }
    
    if errors:
        response["sources_failed"] = errors
    
    if not results:
        # All platforms failed
        error_msg = "; ".join([f"{k}: {v}" for k, v in errors.items()])
        raise IntegrationError(f"All CTI lookups failed: {error_msg}")
    
    return response


def _generate_threat_assessment(threat_intel: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a clear threat assessment summary for LLM understanding.
    
    Args:
        threat_intel: Merged threat intelligence data
        
    Returns:
        Dictionary with clear threat assessment
    """
    assessment = {
        "is_malicious": False,
        "is_suspicious": False,
        "is_benign": False,
        "threat_level": "unknown",
        "confidence": "low",
        "summary": "",
    }
    
    # Check if hash was found
    if not threat_intel.get("found", False):
        assessment["is_benign"] = True
        assessment["threat_level"] = "benign"
        assessment["confidence"] = "medium"
        assessment["summary"] = "Hash not found in threat intelligence databases - likely benign or unknown"
        return assessment
    
    # Check classification
    classification = threat_intel.get("classification", "").lower()
    if classification == "malicious":
        assessment["is_malicious"] = True
        assessment["threat_level"] = "malicious"
        assessment["confidence"] = "high"
    elif classification == "suspicious":
        assessment["is_suspicious"] = True
        assessment["threat_level"] = "suspicious"
        assessment["confidence"] = "medium"
    elif classification == "benign":
        assessment["is_benign"] = True
        assessment["threat_level"] = "benign"
        assessment["confidence"] = "high"
    
    # Check threat score
    threat_score = threat_intel.get("threat_score")
    if threat_score is not None:
        if threat_score >= 70:
            assessment["is_malicious"] = True
            assessment["threat_level"] = "malicious"
            assessment["confidence"] = "high"
        elif threat_score >= 40:
            assessment["is_suspicious"] = True
            if assessment["threat_level"] == "unknown":
                assessment["threat_level"] = "suspicious"
                assessment["confidence"] = "medium"
        elif threat_score < 30:
            assessment["is_benign"] = True
            if assessment["threat_level"] == "unknown":
                assessment["threat_level"] = "benign"
                assessment["confidence"] = "medium"
    
    # Check labels for threat indicators
    labels = threat_intel.get("labels", [])
    malicious_labels = ["malware", "trojan", "ransomware", "virus", "backdoor", "rootkit", "spyware", "adware", "exploit"]
    suspicious_labels = ["suspicious", "potentially_unwanted", "phishing", "crypto_miner"]
    
    has_malicious_label = any(label.lower() in malicious_labels for label in labels)
    has_suspicious_label = any(label.lower() in suspicious_labels for label in labels)
    
    if has_malicious_label:
        assessment["is_malicious"] = True
        assessment["threat_level"] = "malicious"
        assessment["confidence"] = "high"
    elif has_suspicious_label:
        assessment["is_suspicious"] = True
        if assessment["threat_level"] == "unknown":
            assessment["threat_level"] = "suspicious"
            assessment["confidence"] = "medium"
    
    # Check if indicators exist
    indicators = threat_intel.get("indicators", [])
    if indicators:
        # Check indicator scores
        high_score_indicators = [ind for ind in indicators if ind.get("score", 0) >= 70]
        if high_score_indicators:
            assessment["is_malicious"] = True
            assessment["threat_level"] = "malicious"
            assessment["confidence"] = "high"
        elif not assessment["is_malicious"]:
            assessment["is_suspicious"] = True
            if assessment["threat_level"] == "unknown":
                assessment["threat_level"] = "suspicious"
                assessment["confidence"] = "medium"
    
    # Generate summary
    if assessment["is_malicious"]:
        assessment["summary"] = f"MALICIOUS: Hash is known malicious (threat_score: {threat_score}, classification: {classification}, labels: {labels}). Take immediate action."
    elif assessment["is_suspicious"]:
        assessment["summary"] = f"SUSPICIOUS: Hash shows suspicious indicators (threat_score: {threat_score}, labels: {labels}). Investigate further."
    elif assessment["is_benign"]:
        assessment["summary"] = f"BENIGN: Hash appears benign (threat_score: {threat_score}, classification: {classification}). Low risk."
    else:
        assessment["summary"] = f"UNKNOWN: Hash found in database but threat level unclear (threat_score: {threat_score}, indicators: {len(indicators)}). Review indicators."
    
    return assessment


def _merge_cti_results(results: Dict[str, Dict[str, Any]], hash_value: str) -> Dict[str, Any]:
    """
    Merge results from multiple CTI platforms into a unified format.
    
    Args:
        results: Dictionary mapping client_type to result data.
        hash_value: The hash value that was queried.
    
    Returns:
        Merged threat intelligence data.
    """
    merged = {
        "value": hash_value,
        "found": False,
        "platforms": {},
        "indicators": [],
        "threat_score": None,
        "classification": None,
        "labels": [],
        "kill_chain_phases": [],
    }
    
    # Process each platform's results
    for platform, data in results.items():
        if data is None:
            continue
        
        # Store platform-specific data
        merged["platforms"][platform] = data
        
        # Extract common fields
        if platform == "local_tip":
            # Local TIP format
            if data.get("threat_score") is not None:
                # Use highest threat score if multiple platforms
                if merged["threat_score"] is None or data["threat_score"] > merged["threat_score"]:
                    merged["threat_score"] = data["threat_score"]
            
            if data.get("classification"):
                # Prefer malicious > suspicious > benign
                if not merged["classification"] or data["classification"] == "malicious":
                    merged["classification"] = data["classification"]
                elif data["classification"] == "suspicious" and merged["classification"] != "malicious":
                    merged["classification"] = data["classification"]
            
            if data.get("value"):
                merged["found"] = True
        
        elif platform == "opencti":
            # OpenCTI format
            if data.get("found"):
                merged["found"] = True
            
            # Merge indicators
            if data.get("indicators"):
                for indicator in data["indicators"]:
                    # Check if we already have this indicator (by ID or pattern)
                    existing = next(
                        (ind for ind in merged["indicators"] 
                         if ind.get("id") == indicator.get("id") or 
                            ind.get("pattern") == indicator.get("pattern")),
                        None
                    )
                    if not existing:
                        merged["indicators"].append(indicator)
                    
                    # Merge labels
                    if indicator.get("labels"):
                        for label in indicator["labels"]:
                            if label not in merged["labels"]:
                                merged["labels"].append(label)
                    
                    # Merge kill chain phases
                    if indicator.get("kill_chain_phases"):
                        for phase in indicator["kill_chain_phases"]:
                            existing_phase = next(
                                (p for p in merged["kill_chain_phases"]
                                 if p.get("kill_chain_name") == phase.get("kill_chain_name") and
                                    p.get("phase_name") == phase.get("phase_name")),
                                None
                            )
                            if not existing_phase:
                                merged["kill_chain_phases"].append(phase)
                    
                    # Use highest threat score
                    if indicator.get("score") is not None:
                        if merged["threat_score"] is None or indicator["score"] > merged["threat_score"]:
                            merged["threat_score"] = indicator["score"]
    
    return merged

