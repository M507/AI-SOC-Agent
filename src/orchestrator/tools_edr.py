"""
LLM-callable tools for EDR operations.

These functions wrap the generic EDRClient interface and provide
LLM-friendly error handling and return values.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..api.edr import EDRClient
from ..core.errors import IntegrationError


def get_endpoint_summary(
    endpoint_id: str,
    client: EDRClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get a summary of an endpoint.

    Tool schema:
    - name: get_endpoint_summary
    - description: Retrieve summary information about an endpoint including
      hostname, platform, last seen time, primary user, and isolation status.
    - parameters:
      - endpoint_id (str, required): The endpoint ID.

    Args:
        endpoint_id: The endpoint ID.
        client: The EDR client.

    Returns:
        Dictionary containing endpoint summary.

    Raises:
        IntegrationError: If retrieving endpoint fails.
    """
    if client is None:
        raise IntegrationError("EDR client not provided")

    try:
        endpoint = client.get_endpoint_summary(endpoint_id)

        return {
            "success": True,
            "endpoint": {
                "id": endpoint.id,
                "hostname": endpoint.hostname,
                "platform": endpoint.platform.value,
                "last_seen": endpoint.last_seen.isoformat()
                if endpoint.last_seen
                else None,
                "primary_user": endpoint.primary_user,
                "is_isolated": endpoint.is_isolated,
            },
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get endpoint summary for {endpoint_id}: {str(e)}") from e


def get_detection_details(
    detection_id: str,
    client: EDRClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get details of a detection.

    Tool schema:
    - name: get_detection_details
    - description: Retrieve detailed information about a specific detection
      including type, severity, description, associated file hash, and process.
    - parameters:
      - detection_id (str, required): The detection ID.

    Args:
        detection_id: The detection ID.
        client: The EDR client.

    Returns:
        Dictionary containing detection details.

    Raises:
        IntegrationError: If retrieving detection fails.
    """
    if client is None:
        raise IntegrationError("EDR client not provided")

    try:
        detection = client.get_detection_details(detection_id)

        return {
            "success": True,
            "detection": {
                "id": detection.id,
                "endpoint_id": detection.endpoint_id,
                "created_at": detection.created_at.isoformat(),
                "detection_type": detection.detection_type.value,
                "severity": detection.severity,
                "description": detection.description,
                "file_hash": detection.file_hash,
                "process": {
                    "pid": detection.process.pid,
                    "name": detection.process.name,
                    "path": detection.process.path,
                    "user": detection.process.user,
                    "command_line": detection.process.command_line,
                }
                if detection.process
                else None,
            },
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get detection details for {detection_id}: {str(e)}") from e


def isolate_endpoint(
    endpoint_id: str,
    client: EDRClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Isolate an endpoint from the network.

    Tool schema:
    - name: isolate_endpoint
    - description: Isolate an endpoint from the network to prevent further
      compromise or lateral movement. This is a critical response action.
    - parameters:
      - endpoint_id (str, required): The endpoint ID to isolate.

    Args:
        endpoint_id: The endpoint ID.
        client: The EDR client.

    Returns:
        Dictionary containing isolation action details.

    Raises:
        IntegrationError: If isolation fails.
    """
    if client is None:
        raise IntegrationError("EDR client not provided")

    try:
        action = client.isolate_endpoint(endpoint_id)

        return {
            "success": True,
            "action": {
                "endpoint_id": action.endpoint_id,
                "result": action.result.value,
                "requested_at": action.requested_at.isoformat(),
                "completed_at": action.completed_at.isoformat()
                if action.completed_at
                else None,
                "message": action.message,
            },
        }
    except Exception as e:
        raise IntegrationError(f"Failed to isolate endpoint {endpoint_id}: {str(e)}") from e


def release_endpoint_isolation(
    endpoint_id: str,
    client: EDRClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Release an endpoint from isolation.

    Tool schema:
    - name: release_endpoint_isolation
    - description: Release an endpoint from network isolation, restoring
      normal network connectivity.
    - parameters:
      - endpoint_id (str, required): The endpoint ID to release.

    Args:
        endpoint_id: The endpoint ID.
        client: The EDR client.

    Returns:
        Dictionary containing release action details.

    Raises:
        IntegrationError: If release fails.
    """
    if client is None:
        raise IntegrationError("EDR client not provided")

    try:
        action = client.release_endpoint_isolation(endpoint_id)

        return {
            "success": True,
            "action": {
                "endpoint_id": action.endpoint_id,
                "result": action.result.value,
                "requested_at": action.requested_at.isoformat(),
                "completed_at": action.completed_at.isoformat()
                if action.completed_at
                else None,
                "message": action.message,
            },
        }
    except Exception as e:
        raise IntegrationError(
            f"Failed to release endpoint isolation for {endpoint_id}: {str(e)}"
        ) from e


def kill_process_on_endpoint(
    endpoint_id: str,
    pid: int,
    client: EDRClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Kill a process on an endpoint.

    Tool schema:
    - name: kill_process_on_endpoint
    - description: Terminate a specific process running on an endpoint by
      its process ID. Use with caution as this is a disruptive action.
    - parameters:
      - endpoint_id (str, required): The endpoint ID.
      - pid (int, required): The process ID to kill.

    Args:
        endpoint_id: The endpoint ID.
        pid: The process ID.
        client: The EDR client.

    Returns:
        Dictionary containing kill action details.

    Raises:
        IntegrationError: If killing process fails.
    """
    if client is None:
        raise IntegrationError("EDR client not provided")

    try:
        action = client.kill_process_on_endpoint(endpoint_id, pid)

        return {
            "success": True,
            "action": {
                "endpoint_id": action.endpoint_id,
                "pid": action.pid,
                "result": action.result.value,
                "requested_at": action.requested_at.isoformat(),
                "completed_at": action.completed_at.isoformat()
                if action.completed_at
                else None,
                "message": action.message,
            },
        }
    except Exception as e:
        raise IntegrationError(
            f"Failed to kill process {pid} on endpoint {endpoint_id}: {str(e)}"
        ) from e


def collect_forensic_artifacts(
    endpoint_id: str,
    artifact_types: List[str],
    client: EDRClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Collect forensic artifacts from an endpoint.

    Tool schema:
    - name: collect_forensic_artifacts
    - description: Initiate collection of forensic artifacts from an endpoint,
      such as process lists, network connections, file system artifacts, etc.
    - parameters:
      - endpoint_id (str, required): The endpoint ID.
      - artifact_types (list[str], required): List of artifact types to collect
        (e.g., ["processes", "network", "filesystem"]).

    Args:
        endpoint_id: The endpoint ID.
        artifact_types: List of artifact types to collect.
        client: The EDR client.

    Returns:
        Dictionary containing collection request details.

    Raises:
        IntegrationError: If collection request fails.
    """
    if client is None:
        raise IntegrationError("EDR client not provided")

    try:
        request = client.collect_forensic_artifacts(endpoint_id, artifact_types)

        return {
            "success": True,
            "request": {
                "endpoint_id": request.endpoint_id,
                "artifact_types": request.artifact_types,
                "result": request.result.value,
                "requested_at": request.requested_at.isoformat(),
                "completed_at": request.completed_at.isoformat()
                if request.completed_at
                else None,
                "message": request.message,
            },
        }
    except Exception as e:
        raise IntegrationError(
            f"Failed to collect forensic artifacts from endpoint {endpoint_id}: {str(e)}"
        ) from e

