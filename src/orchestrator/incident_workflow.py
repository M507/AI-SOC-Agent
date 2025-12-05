"""
High-level incident response workflows for SamiGPT.

This module provides orchestration functions that coordinate between
case management, SIEM, and EDR clients to perform common incident
response tasks.
"""

from __future__ import annotations

from typing import List, Optional

from ..api.case_management import (
    Case,
    CaseManagementClient,
    CaseObservable,
    CaseStatus,
)
from ..api.edr import EDRClient, Endpoint
from ..api.siem import SIEMClient, SiemAlert
from ..core.errors import IntegrationError


def create_incident_from_alert(
    alert: SiemAlert,
    case_client: CaseManagementClient,
    title_prefix: Optional[str] = None,
) -> Case:
    """
    Create a new case in the case management system from a SIEM alert.

    Args:
        alert: The SIEM alert to convert into a case.
        case_client: The case management client to use.
        title_prefix: Optional prefix for the case title.

    Returns:
        The created case.

    Raises:
        IntegrationError: If case creation fails.
    """
    title = f"{title_prefix + ': ' if title_prefix else ''}{alert.title or 'Security Alert'}"
    description = f"Alert from SIEM: {alert.description or 'No description'}\n\n"
    description += f"Severity: {alert.severity}\n"
    description += f"Source: {alert.source}\n"
    if alert.timestamp:
        description += f"Timestamp: {alert.timestamp.isoformat()}\n"

    case = Case(
        title=title,
        description=description,
        status=CaseStatus.OPEN,
        priority=alert.severity.value if hasattr(alert.severity, "value") else "medium",
        tags=alert.tags or [],
    )

    try:
        created_case = case_client.create_case(case)
        return created_case
    except Exception as e:
        raise IntegrationError(f"Failed to create case from alert: {e}") from e


def enrich_case_from_siem(
    case_id: str,
    case_client: CaseManagementClient,
    siem_client: SIEMClient,
    search_terms: Optional[List[str]] = None,
) -> List[CaseObservable]:
    """
    Enrich a case by searching SIEM for related events and adding observables.

    Args:
        case_id: The ID of the case to enrich.
        case_client: The case management client.
        siem_client: The SIEM client to search.
        search_terms: Optional list of terms to search for in SIEM.

    Returns:
        List of observables added to the case.

    Raises:
        IntegrationError: If enrichment fails.
    """
    try:
        case = case_client.get_case(case_id)
    except Exception as e:
        raise IntegrationError(f"Failed to retrieve case {case_id}: {e}") from e

    observables_added = []

    # Extract potential observables from case title/description
    search_terms = search_terms or []
    if case.title:
        search_terms.append(case.title)
    if case.description:
        # Simple extraction - in production, use more sophisticated parsing
        search_terms.append(case.description[:100])

    # Search SIEM for related events
    try:
        if search_terms:
            query = " OR ".join(search_terms[:5])  # Limit to avoid huge queries
            events = siem_client.search_security_events(
                query=query,
                limit=50,
            )

            # Extract unique observables from events
            seen_observables = set()
            for event in events.events:
                # Add IP addresses as observables
                if event.ip:
                    key = f"ip:{event.ip}"
                    if key not in seen_observables:
                        observable = CaseObservable(
                            type="ip",
                            value=event.ip,
                            description=f"Found in SIEM event: {event.id}",
                        )
                        case_client.add_case_observable(case_id, observable)
                        observables_added.append(observable)
                        seen_observables.add(key)

                # Add file hashes if present
                if event.file_hash:
                    key = f"hash:{event.file_hash}"
                    if key not in seen_observables:
                        observable = CaseObservable(
                            type="hash",
                            value=event.file_hash,
                            description=f"Found in SIEM event: {event.id}",
                        )
                        case_client.add_case_observable(case_id, observable)
                        observables_added.append(observable)
                        seen_observables.add(key)

    except Exception as e:
        raise IntegrationError(f"Failed to search SIEM or add observables: {e}") from e

    return observables_added


def enrich_case_from_edr(
    case_id: str,
    case_client: CaseManagementClient,
    edr_client: EDRClient,
    endpoint_id: Optional[str] = None,
) -> List[CaseObservable]:
    """
    Enrich a case by querying EDR for endpoint information and adding observables.

    Args:
        case_id: The ID of the case to enrich.
        case_client: The case management client.
        edr_client: The EDR client to query.
        endpoint_id: Optional endpoint ID to focus on. If not provided, uses
            observables from the case to find relevant endpoints.

    Returns:
        List of observables added to the case.

    Raises:
        IntegrationError: If enrichment fails.
    """
    try:
        case = case_client.get_case(case_id)
    except Exception as e:
        raise IntegrationError(f"Failed to retrieve case {case_id}: {e}") from e

    observables_added = []

    try:
        # If endpoint_id provided, get that endpoint's details
        if endpoint_id:
            endpoint = edr_client.get_endpoint_summary(endpoint_id)
            if endpoint:
                # Add endpoint hostname as observable
                if endpoint.hostname:
                    observable = CaseObservable(
                        type="hostname",
                        value=endpoint.hostname,
                        description=f"Endpoint from EDR: {endpoint_id}",
                    )
                    case_client.add_case_observable(case_id, observable)
                    observables_added.append(observable)

        # Get recent detections and add file hashes as observables
        detections = edr_client.list_detections(limit=20)
        seen_hashes = set()
        for detection in detections:
            if detection.file_hash:
                key = f"hash:{detection.file_hash}"
                if key not in seen_hashes:
                    observable = CaseObservable(
                        type="hash",
                        value=detection.file_hash,
                        description=f"EDR detection: {detection.id}",
                    )
                    case_client.add_case_observable(case_id, observable)
                    observables_added.append(observable)
                    seen_hashes.add(key)

    except Exception as e:
        raise IntegrationError(f"Failed to query EDR or add observables: {e}") from e

    return observables_added


def close_incident(
    case_id: str,
    case_client: CaseManagementClient,
    resolution_notes: Optional[str] = None,
) -> Case:
    """
    Close an incident case with optional resolution notes.

    Args:
        case_id: The ID of the case to close.
        case_client: The case management client.
        resolution_notes: Optional notes about the resolution.

    Returns:
        The updated case.

    Raises:
        IntegrationError: If closing the case fails.
    """
    try:
        # Add resolution notes as a comment if provided
        if resolution_notes:
            case_client.add_case_comment(
                case_id=case_id,
                content=f"Resolution: {resolution_notes}",
                author=None,  # System-generated
            )

        # Update status to closed
        updated_case = case_client.update_case_status(case_id, CaseStatus.CLOSED)
        return updated_case
    except Exception as e:
        raise IntegrationError(f"Failed to close case {case_id}: {e}") from e

