"""
Mapping logic between generic case management DTOs and TheHive models/payloads.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ....api.case_management import (
    Case,
    CaseAssignment,
    CaseComment,
    CaseObservable,
    CasePriority,
    CaseStatus,
    CaseSummary,
)
from .thehive_models import (
    TheHiveCase,
    TheHiveCasePriority,
    TheHiveCaseStatus,
    parse_thehive_case,
    parse_thehive_observable,
)


# Generic → TheHive


def case_to_thehive_payload(case: Case) -> Dict[str, Any]:
    """
    Convert a generic ``Case`` into a TheHive case creation/update payload.
    """

    payload: Dict[str, Any] = {
        "title": case.title,
        "description": case.description,
        "tags": case.tags or [],
    }

    if case.priority is not None:
        payload["severity"] = {
            CasePriority.LOW: 1,
            CasePriority.MEDIUM: 2,
            CasePriority.HIGH: 3,
            CasePriority.CRITICAL: 4,
        }[case.priority]

    if case.status is not None:
        payload["status"] = status_to_thehive_status(case.status).value

    if case.assignee:
        payload["owner"] = case.assignee

    return payload


def comment_to_thehive_payload(comment: CaseComment) -> Dict[str, Any]:
    return {
        "message": comment.content,
    }


def observable_to_thehive_payload(observable: CaseObservable) -> Dict[str, Any]:
    return {
        "dataType": observable.type,
        "data": observable.value,
        "tags": observable.tags or [],
        "message": observable.description or "",
    }


def status_to_thehive_status(status: CaseStatus) -> TheHiveCaseStatus:
    mapping = {
        CaseStatus.OPEN: TheHiveCaseStatus.OPEN,
        CaseStatus.IN_PROGRESS: TheHiveCaseStatus.IN_PROGRESS,
        CaseStatus.CLOSED: TheHiveCaseStatus.RESOLVED,
    }
    return mapping.get(status, TheHiveCaseStatus.OPEN)


def priority_to_thehive_priority(priority: CasePriority) -> TheHiveCasePriority:
    mapping = {
        CasePriority.LOW: TheHiveCasePriority.LOW,
        CasePriority.MEDIUM: TheHiveCasePriority.MEDIUM,
        CasePriority.HIGH: TheHiveCasePriority.HIGH,
        CasePriority.CRITICAL: TheHiveCasePriority.CRITICAL,
    }
    return mapping[priority]


# TheHive → Generic


def thehive_case_to_generic(raw: Dict[str, Any]) -> Case:
    hive_case: TheHiveCase = parse_thehive_case(raw)

    # Map severity back to CasePriority using simple thresholds.
    severity = hive_case.severity or 0
    if severity <= 1:
        priority = CasePriority.LOW
    elif severity == 2:
        priority = CasePriority.MEDIUM
    elif severity == 3:
        priority = CasePriority.HIGH
    else:
        priority = CasePriority.CRITICAL

    status_mapping = {
        TheHiveCaseStatus.OPEN: CaseStatus.OPEN,
        TheHiveCaseStatus.IN_PROGRESS: CaseStatus.IN_PROGRESS,
        TheHiveCaseStatus.RESOLVED: CaseStatus.CLOSED,
        TheHiveCaseStatus.DELETED: CaseStatus.CLOSED,
    }
    status = status_mapping.get(hive_case.status, CaseStatus.OPEN)

    return Case(
        id=hive_case.id,
        title=hive_case.title,
        description=hive_case.description or "",
        status=status,
        priority=priority,
        created_at=hive_case.start_date,
        updated_at=hive_case.start_date,
        assignee=hive_case.owner,
        tags=hive_case.tags or [],
        observables=None,
    )


def thehive_case_to_summary(raw: Dict[str, Any]) -> CaseSummary:
    hive_case: TheHiveCase = parse_thehive_case(raw)

    severity = hive_case.severity or 0
    if severity <= 1:
        priority = CasePriority.LOW
    elif severity == 2:
        priority = CasePriority.MEDIUM
    elif severity == 3:
        priority = CasePriority.HIGH
    else:
        priority = CasePriority.CRITICAL

    status_mapping = {
        TheHiveCaseStatus.OPEN: CaseStatus.OPEN,
        TheHiveCaseStatus.IN_PROGRESS: CaseStatus.IN_PROGRESS,
        TheHiveCaseStatus.RESOLVED: CaseStatus.CLOSED,
        TheHiveCaseStatus.DELETED: CaseStatus.CLOSED,
    }
    status = status_mapping.get(hive_case.status, CaseStatus.OPEN)

    return CaseSummary(
        id=hive_case.id,
        title=hive_case.title,
        status=status,
        priority=priority,
        created_at=hive_case.start_date,
        updated_at=hive_case.start_date,
        assignee=hive_case.owner,
    )


def thehive_comment_to_generic(raw: Dict[str, Any], case_id: str) -> CaseComment:
    # TheHive uses "message" and "createdAt" in many comment-like resources.
    from datetime import datetime

    created_at_value = raw.get("createdAt")
    created_at = None
    if isinstance(created_at_value, (int, float)):
        created_at = datetime.fromtimestamp(created_at_value / 1000.0)

    return CaseComment(
        id=str(raw.get("id") or raw.get("_id")),
        case_id=case_id,
        author=raw.get("user"),
        content=raw.get("message", ""),
        created_at=created_at,
    )


def thehive_observable_to_generic(raw: Dict[str, Any], case_id: str) -> CaseObservable:
    hive_obs = parse_thehive_observable(raw)
    return CaseObservable(
        type=hive_obs.data_type,
        value=hive_obs.data,
        tags=hive_obs.tags or [],
        description=None,
    )


