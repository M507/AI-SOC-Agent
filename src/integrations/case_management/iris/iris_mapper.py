"""
Mapping logic between generic case management DTOs and IRIS models/payloads.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ....api.case_management import (
    Case,
    CaseAssignment,
    CaseComment,
    CaseObservable,
    CasePriority,
    CaseStatus,
    CaseSummary,
)
from .iris_models import (
    IrisCase,
    IrisCasePriority,
    IrisCaseStatus,
    parse_iris_case,
    parse_iris_ioc,
)


# Generic → IRIS


def case_to_iris_payload(case: Case) -> Dict[str, Any]:
    """
    Convert a generic ``Case`` into an IRIS case creation/update payload.
    """
    payload: Dict[str, Any] = {
        "case_name": case.title,
        "case_description": case.description or "",
        "case_customer": 3,  # Always use "All" client (customer_id: 3)
        "case_soc_id": "soc_id_default",  # Required field - default SOC ID
    }
    
    # Convert tags list to comma-separated string (only if tags exist)
    if case.tags:
        tags_str = ", ".join(case.tags)
        payload["case_tags"] = tags_str  # IRIS expects tags as a string, not a list

    # Note: state_id and severity_id are not set during creation
    # IRIS will set defaults (state_id: 3, severity_id: 4)
    # These can be updated after case creation if needed

    if case.assignee:
        # Note: IRIS uses user_id, so we'd need to resolve username to ID
        # For now, assume assignee can be a username or ID string
        payload["case_owner"] = case.assignee

    return payload


def comment_to_iris_payload(comment: CaseComment) -> Dict[str, Any]:
    """Convert generic comment to IRIS payload."""
    return {
        "comment_content": comment.content,
    }


def observable_type_to_iris_ioc_type_id(observable_type: str) -> int:
    """
    Map generic observable type string to IRIS IOC type ID.
    
    Common mappings:
    - ip, ip-any -> 76 (ip-any)
    - ip-dst -> 77
    - ip-src -> 79
    - domain -> 20
    - url -> 141
    - hash, md5 -> 90
    - sha1 -> 111
    - sha256 -> 113
    - email -> 22
    """
    type_lower = observable_type.lower()
    
    # IP addresses
    if type_lower in ("ip", "ip-any", "ip_address"):
        return 76  # ip-any
    elif type_lower == "ip-dst":
        return 77
    elif type_lower == "ip-src":
        return 79
    
    # Domains
    elif type_lower in ("domain", "fqdn", "hostname"):
        return 20  # domain
    
    # URLs
    elif type_lower in ("url", "uri"):
        return 141  # url
    
    # Hashes
    elif type_lower in ("hash", "md5"):
        return 90  # md5
    elif type_lower == "sha1":
        return 111
    elif type_lower == "sha256":
        return 113
    
    # Email
    elif type_lower in ("email", "email-address"):
        return 22  # email
    
    # Default to "other" if type not recognized
    return 96  # other


def observable_to_iris_payload(observable: CaseObservable) -> Dict[str, Any]:
    """Convert generic observable to IRIS IOC payload."""
    # Convert tags list to comma-separated string if needed
    tags_str = ", ".join(observable.tags) if observable.tags else ""
    
    return {
        "ioc_type_id": observable_type_to_iris_ioc_type_id(observable.type),
        "ioc_value": observable.value,
        "ioc_tags": tags_str,  # IRIS may expect string or list - try string first
        "ioc_description": observable.description or "",
        "ioc_tlp_id": 2,  # Default to TLP:AMBER (1=WHITE, 2=AMBER, 3=GREEN, 4=RED)
    }


def status_to_iris_status(case_status: CaseStatus) -> IrisCaseStatus:
    """Map generic CaseStatus to IRIS CaseStatus enum."""
    mapping = {
        CaseStatus.OPEN: IrisCaseStatus.OPEN,
        CaseStatus.IN_PROGRESS: IrisCaseStatus.ONGOING,
        CaseStatus.CLOSED: IrisCaseStatus.CLOSED,
    }
    return mapping.get(case_status, IrisCaseStatus.OPEN)


def status_to_iris_status_id(case_status: CaseStatus) -> int:
    """Map generic CaseStatus to IRIS status ID."""
    # IRIS status IDs: typically 1=open, 2=ongoing, 3=closed, 4=archived
    status_id_map = {
        CaseStatus.OPEN: 1,
        CaseStatus.IN_PROGRESS: 2,
        CaseStatus.CLOSED: 3,
    }
    return status_id_map.get(case_status, 1)


def priority_to_iris_priority(priority: CasePriority) -> IrisCasePriority:
    """Map generic CasePriority to IRIS CasePriority enum."""
    mapping = {
        CasePriority.LOW: IrisCasePriority.LOW,
        CasePriority.MEDIUM: IrisCasePriority.MEDIUM,
        CasePriority.HIGH: IrisCasePriority.HIGH,
        CasePriority.CRITICAL: IrisCasePriority.CRITICAL,
    }
    return mapping[priority]


def priority_id_to_case_priority(priority_id: Optional[int]) -> CasePriority:
    """Map IRIS priority ID to generic CasePriority."""
    if priority_id is None:
        return CasePriority.MEDIUM
    
    # IRIS priority mapping: 4=low, 3=medium, 2=high, 1=critical
    if priority_id >= 4:
        return CasePriority.LOW
    elif priority_id == 3:
        return CasePriority.MEDIUM
    elif priority_id == 2:
        return CasePriority.HIGH
    else:
        return CasePriority.CRITICAL


def status_id_to_case_status(status_id: Optional[int]) -> CaseStatus:
    """Map IRIS status ID to generic CaseStatus."""
    if status_id is None:
        return CaseStatus.OPEN
    
    # IRIS status IDs: typically 1=open, 2=ongoing, 3=closed, 4=archived
    if status_id == 1:
        return CaseStatus.OPEN
    elif status_id == 2:
        return CaseStatus.IN_PROGRESS
    else:
        return CaseStatus.CLOSED


# IRIS → Generic


def iris_case_to_generic(raw: Dict[str, Any]) -> Case:
    """Convert IRIS case to generic Case."""
    iris_case: IrisCase = parse_iris_case(raw)

    priority = priority_id_to_case_priority(iris_case.case_priority_id)
    status = status_id_to_case_status(iris_case.case_status_id)

    return Case(
        id=str(iris_case.case_id),
        title=iris_case.case_name,
        description=iris_case.case_description or "",
        status=status,
        priority=priority,
        created_at=iris_case.case_open_date,
        updated_at=iris_case.case_update_date or iris_case.case_open_date,
        assignee=str(iris_case.case_owner_id) if iris_case.case_owner_id else None,
        tags=iris_case.case_tags or [],
        observables=None,
    )


def iris_case_to_summary(raw: Dict[str, Any]) -> CaseSummary:
    """Convert IRIS case to generic CaseSummary."""
    iris_case: IrisCase = parse_iris_case(raw)

    priority = priority_id_to_case_priority(iris_case.case_priority_id)
    status = status_id_to_case_status(iris_case.case_status_id)

    return CaseSummary(
        id=str(iris_case.case_id),
        title=iris_case.case_name,
        status=status,
        priority=priority,
        created_at=iris_case.case_open_date,
        updated_at=iris_case.case_update_date or iris_case.case_open_date,
        assignee=str(iris_case.case_owner_id) if iris_case.case_owner_id else None,
    )


def iris_comment_to_generic(raw: Dict[str, Any], case_id: str) -> CaseComment:
    """Convert IRIS comment to generic CaseComment."""
    from datetime import datetime

    created_at_value = raw.get("comment_date") or raw.get("comment_added")
    created_at = None
    if isinstance(created_at_value, (int, float)):
        created_at = datetime.fromtimestamp(created_at_value)
    elif isinstance(created_at_value, str):
        try:
            created_at = datetime.fromisoformat(created_at_value.replace("Z", "+00:00"))
        except Exception:
            pass

    return CaseComment(
        id=str(raw.get("comment_id", raw.get("id", 0))),
        case_id=case_id,
        author=raw.get("comment_user") or raw.get("user_name") or raw.get("user"),
        content=raw.get("comment_content", raw.get("content", "")),
        created_at=created_at,
    )


def iris_ioc_to_observable(raw: Dict[str, Any], case_id: str) -> CaseObservable:
    """Convert IRIS IOC to generic CaseObservable."""
    iris_ioc = parse_iris_ioc(raw)
    return CaseObservable(
        type=iris_ioc.ioc_type,
        value=iris_ioc.ioc_value,
        tags=iris_ioc.ioc_tags or [],
        description=iris_ioc.ioc_description,
    )
