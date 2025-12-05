"""
TheHive-specific data models.

These dataclasses are close to TheHive's API payloads but kept separate
from the generic DTOs defined under ``src/api``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class TheHiveCaseStatus(str, Enum):
    OPEN = "Open"
    IN_PROGRESS = "InProgress"
    RESOLVED = "Resolved"
    DELETED = "Deleted"


class TheHiveCasePriority(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class TheHiveUser:
    id: str
    login: str
    name: Optional[str] = None


@dataclass
class TheHiveObservable:
    id: str
    data_type: str
    data: str
    tlp: Optional[int] = None
    tags: Optional[List[str]] = None


@dataclass
class TheHiveAlert:
    id: str
    title: str
    description: Optional[str] = None
    severity: Optional[int] = None
    source: Optional[str] = None
    source_ref: Optional[str] = None


@dataclass
class TheHiveCase:
    id: str
    title: str
    description: Optional[str]
    severity: Optional[int]
    start_date: Optional[datetime]
    status: TheHiveCaseStatus
    owner: Optional[str]
    tags: Optional[List[str]] = None


def parse_thehive_case(raw: Dict[str, Any]) -> TheHiveCase:
    """
    Parse a raw TheHive case dict into a ``TheHiveCase`` instance.
    """

    # TheHive uses numeric timestamps (epoch ms); keep parsing simple and
    # allow None if absent.
    start_date_value = raw.get("startDate")
    start_date: Optional[datetime]
    if isinstance(start_date_value, (int, float)):
        start_date = datetime.fromtimestamp(start_date_value / 1000.0)
    else:
        start_date = None

    status = raw.get("status", "Open")
    case_status = TheHiveCaseStatus(status) if status in TheHiveCaseStatus._value2member_map_ else TheHiveCaseStatus.OPEN

    return TheHiveCase(
        id=str(raw.get("id") or raw.get("_id")),
        title=raw.get("title", ""),
        description=raw.get("description"),
        severity=raw.get("severity"),
        start_date=start_date,
        status=case_status,
        owner=raw.get("owner"),
        tags=raw.get("tags") or [],
    )


def parse_thehive_observable(raw: Dict[str, Any]) -> TheHiveObservable:
    """
    Parse a raw TheHive observable dict.
    """

    return TheHiveObservable(
        id=str(raw.get("id") or raw.get("_id")),
        data_type=raw.get("dataType", ""),
        data=raw.get("data", ""),
        tlp=raw.get("tlp"),
        tags=raw.get("tags") or [],
    )


def parse_thehive_alert(raw: Dict[str, Any]) -> TheHiveAlert:
    """
    Parse a raw TheHive alert dict.
    """

    return TheHiveAlert(
        id=str(raw.get("id") or raw.get("_id")),
        title=raw.get("title", ""),
        description=raw.get("description"),
        severity=raw.get("severity"),
        source=raw.get("source"),
        source_ref=raw.get("sourceRef"),
    )


