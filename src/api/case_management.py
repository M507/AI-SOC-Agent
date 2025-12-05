"""
Generic case management API for SamiGPT.

This module defines vendor-neutral DTOs and the ``CaseManagementClient``
interface that orchestrator code and LLM tools will use. Concrete
implementations (e.g., TheHive) live under ``src/integrations``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional, Protocol

from ..core.dto import BaseDTO


class CaseStatus(str, Enum):
    """
    High-level lifecycle status for a case.
    """

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"


class CasePriority(str, Enum):
    """
    Generic priority of a case.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CaseObservable(BaseDTO):
    """
    Observable associated with a case (hash, IP, domain, URL, etc.).
    """

    type: str
    value: str
    tags: Optional[List[str]] = None
    description: Optional[str] = None


@dataclass
class CaseComment(BaseDTO):
    """
    Comment on a case, either from a human analyst or the agent.
    """

    id: Optional[str]
    case_id: str
    author: Optional[str]
    content: str
    created_at: Optional[datetime] = None


@dataclass
class CaseSummary(BaseDTO):
    """
    Lightweight representation of a case for listing/search results.
    """

    id: str
    title: str
    status: CaseStatus
    priority: CasePriority
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    assignee: Optional[str] = None


@dataclass
class Case(BaseDTO):
    """
    Full case representation.
    """

    id: Optional[str]
    title: str
    description: str
    status: CaseStatus
    priority: CasePriority
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    assignee: Optional[str] = None
    tags: Optional[List[str]] = None
    observables: Optional[List[CaseObservable]] = None


@dataclass
class CaseAssignment(BaseDTO):
    """
    Representation of a case assignment operation.
    """

    case_id: str
    assignee: str
    assigned_at: Optional[datetime] = None


@dataclass
class CaseSearchQuery(BaseDTO):
    """
    Generic search query for cases.
    """

    text: Optional[str] = None
    status: Optional[CaseStatus] = None
    priority: Optional[CasePriority] = None
    tags: Optional[List[str]] = None
    assignee: Optional[str] = None
    limit: int = 50


class CaseManagementClient(Protocol):
    """
    Vendor-neutral interface for case management operations.

    This interface is designed to support the skills described in the README:
    - review_case
    - list_cases
    - search_cases
    - add_case_comment
    - attach_observable_to_case
    - update_case_status
    - assign_case
    - get_case_timeline
    """

    # Core CRUD operations
    def create_case(self, case: Case) -> Case:
        ...

    def get_case(self, case_id: str) -> Case:
        ...

    def list_cases(
        self,
        status: Optional[CaseStatus] = None,
        limit: int = 50,
    ) -> List[CaseSummary]:
        ...

    def search_cases(self, query: CaseSearchQuery) -> List[CaseSummary]:
        ...

    def update_case(self, case_id: str, updates: dict) -> Case:
        ...

    def delete_case(self, case_id: str) -> None:
        ...

    # Comments and observables
    def add_case_comment(
        self,
        case_id: str,
        content: str,
        author: Optional[str] = None,
    ) -> CaseComment:
        ...

    def add_case_observable(
        self,
        case_id: str,
        observable: CaseObservable,
    ) -> CaseObservable:
        ...

    # Status and assignment
    def update_case_status(
        self,
        case_id: str,
        status: CaseStatus,
    ) -> Case:
        ...

    def assign_case(
        self,
        case_id: str,
        assignee: str,
    ) -> CaseAssignment:
        ...

    # Linking and timeline
    def link_cases(
        self,
        source_case_id: str,
        target_case_id: str,
        link_type: str,
    ) -> None:
        ...

    def get_case_timeline(self, case_id: str) -> List[CaseComment]:
        ...
    
    # Tasks
    def add_case_task(
        self,
        case_id: str,
        title: str,
        description: str,
        assignee: Optional[str] = None,
        priority: str = "medium",
        status: str = "pending",
    ) -> Dict[str, Any]:
        ...
    
    def list_case_tasks(self, case_id: str) -> List[Dict[str, Any]]:
        ...
    
    def update_case_task_status(
        self,
        case_id: str,
        task_id: str,
        status: str,
    ) -> Dict[str, Any]:
        """
        Update the status of a task in a case.
        
        Args:
            case_id: The ID of the case
            task_id: The ID of the task to update
            status: New task status (pending, in_progress, completed, blocked)
        
        Returns:
            Dictionary with updated task details
        """
        ...
    
    # Assets
    def add_case_asset(
        self,
        case_id: str,
        asset_name: str,
        asset_type: str,
        description: Optional[str] = None,
        ip_address: Optional[str] = None,
        hostname: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        ...
    
    def list_case_assets(self, case_id: str) -> List[Dict[str, Any]]:
        ...
    
    # Evidence
    def add_case_evidence(
        self,
        case_id: str,
        file_path: str,
        description: Optional[str] = None,
        evidence_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        ...
    
    def list_case_evidence(self, case_id: str) -> List[Dict[str, Any]]:
        ...

    # Health check
    def ping(self) -> bool:
        ...


