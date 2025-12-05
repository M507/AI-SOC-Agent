"""
Generic SIEM API for SamiGPT.

This module defines vendor-neutral DTOs and the ``SIEMClient`` interface
that orchestrator code and LLM tools will use for searching security events
and retrieving reports about files, IPs, and related entities.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol

from ..core.dto import BaseDTO


class Severity(str, Enum):
    """
    Generic severity levels for SIEM alerts/events.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """
    Generic status for SIEM alerts.
    """

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
    SUPPRESSED = "suppressed"


class SourceType(str, Enum):
    """
    High-level source type for events.
    """

    ENDPOINT = "endpoint"
    NETWORK = "network"
    AUTH = "auth"
    CLOUD = "cloud"
    OTHER = "other"


@dataclass
class SiemEvent(BaseDTO):
    """
    Generic SIEM event.
    """

    id: str
    timestamp: datetime
    source_type: SourceType
    message: str
    host: Optional[str] = None
    username: Optional[str] = None
    ip: Optional[str] = None
    process_name: Optional[str] = None
    file_hash: Optional[str] = None
    raw: Optional[dict] = None


@dataclass
class SiemAlert(BaseDTO):
    """
    Generic SIEM alert.
    """

    id: str
    created_at: datetime
    severity: Severity
    status: AlertStatus
    title: str
    description: Optional[str] = None
    related_entities: Optional[List[str]] = None
    raw: Optional[dict] = None


@dataclass
class QueryResult(BaseDTO):
    """
    Container for results of a security event search.
    """

    query: str
    events: List[SiemEvent]
    total_count: int


@dataclass
class FileReport(BaseDTO):
    """
    Aggregated report about a file (by hash).
    """

    file_hash: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    detection_count: int = 0
    affected_hosts: Optional[List[str]] = None
    raw: Optional[dict] = None


@dataclass
class FileBehaviorSummary(BaseDTO):
    """
    High-level behavior summary for a file.
    """

    file_hash: str
    process_trees: Optional[List[dict]] = None
    network_activity: Optional[List[dict]] = None
    persistence_mechanisms: Optional[List[str]] = None
    notes: Optional[str] = None


@dataclass
class IpAddressReport(BaseDTO):
    """
    Aggregated report for an IP address.
    """

    ip: str
    reputation: Optional[str] = None
    geo: Optional[dict] = None
    related_alerts: Optional[List[str]] = None
    raw: Optional[dict] = None


@dataclass
class RelatedEntities(BaseDTO):
    """
    Entities related to a specific indicator (e.g. file hash).
    """

    indicator: str
    hosts: Optional[List[str]] = None
    users: Optional[List[str]] = None
    processes: Optional[List[str]] = None
    alerts: Optional[List[str]] = None


class SIEMClient(Protocol):
    """
    Vendor-neutral interface for SIEM operations.

    This interface is designed to support the skills described in the README:
    - search_security_events
    - get_file_report
    - get_file_behavior_summary
    - get_entities_related_to_file
    - get_ip_address_report
    - search_user_activity
    - pivot_on_indicator
    """

    def search_security_events(
        self,
        query: str,
        limit: int = 100,
    ) -> QueryResult:
        """
        Search security events/logs across environments using a vendor-specific
        query language or filter, returning a normalized result.
        """

        ...

    def get_file_report(self, file_hash: str) -> FileReport:
        ...

    def get_file_behavior_summary(self, file_hash: str) -> FileBehaviorSummary:
        ...

    def get_entities_related_to_file(self, file_hash: str) -> RelatedEntities:
        ...

    def get_ip_address_report(self, ip: str) -> IpAddressReport:
        ...

    def search_user_activity(
        self,
        username: str,
        limit: int = 100,
    ) -> QueryResult:
        ...

    def pivot_on_indicator(
        self,
        indicator: str,
        limit: int = 200,
    ) -> QueryResult:
        """
        Given an IOC (hash, IP, domain, etc.), search for related events
        and return them for further investigation.
        """

        ...

    def search_kql_query(
        self,
        kql_query: str,
        limit: int = 500,
        hours_back: Optional[int] = None,
    ) -> QueryResult:
        """
        Execute a KQL (Kusto Query Language) or advanced query for deeper investigations.
        
        This method allows for complex queries that may include:
        - Advanced filtering and aggregation
        - Time-based analysis
        - Cross-index searches
        - Complex joins and correlations
        
        Args:
            kql_query: KQL query string or advanced query DSL
            limit: Maximum number of events to return (default: 500)
            hours_back: Optional time window in hours to limit the search
            
        Returns:
            QueryResult containing matching events
        """
        ...

    def get_siem_event_by_id(
        self,
        event_id: str,
    ) -> SiemEvent:
        """
        Retrieve a specific security event by its ID.
        
        Args:
            event_id: The unique identifier of the event to retrieve.
            
        Returns:
            SiemEvent containing the event details.
            
        Raises:
            IntegrationError: If the event is not found or retrieval fails.
        """
        ...

    def close_alert(
        self,
        alert_id: str,
        reason: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Close an alert in the SIEM, typically used for false positives.
        
        Args:
            alert_id: The ID of the alert to close.
            reason: Optional reason for closing (e.g., "false_positive", "benign_true_positive").
            comment: Optional comment explaining why the alert is being closed.
        
        Returns:
            Dictionary with success status and alert details.
        """
        ...

    def tag_alert(
        self,
        alert_id: str,
        tag: str,
    ) -> Dict[str, Any]:
        """
        Tag an alert with a classification tag (FP, TP, or NMI).
        
        Args:
            alert_id: The ID of the alert to tag.
            tag: The tag to apply. Must be one of: "FP" (False Positive), 
                 "TP" (True Positive), or "NMI" (Need More Investigation).
        
        Returns:
            Dictionary with success status and alert details including updated tags.
        """
        ...

    def add_alert_note(
        self,
        alert_id: str,
        note: str,
    ) -> Dict[str, Any]:
        """
        Add a note/comment to an alert in the SIEM.
        
        This is used to document investigation findings, recommendations,
        or other relevant information about the alert.
        
        Args:
            alert_id: The ID of the alert to add a note to.
            note: The note/comment text to add.
        
        Returns:
            Dictionary with success status and alert details including the note.
        """
        ...


