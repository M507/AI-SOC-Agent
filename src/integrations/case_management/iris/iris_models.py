"""
IRIS-specific data models.

These dataclasses are close to IRIS's API payloads but kept separate
from the generic DTOs defined under ``src/api``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class IrisCaseStatus(str, Enum):
    """IRIS case status values."""
    OPEN = "open"
    ONGOING = "ongoing"
    CLOSED = "closed"
    ARCHIVED = "archived"


class IrisCasePriority(str, Enum):
    """IRIS case priority values."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IrisUser:
    """IRIS user model."""
    id: int
    user: str
    name: Optional[str] = None
    email: Optional[str] = None


@dataclass
class IrisIOC:
    """IRIS IOCs (Indicators of Compromise) model."""
    id: int
    ioc_type: str  # e.g., "ip", "domain", "hash", etc.
    ioc_value: str
    ioc_tags: Optional[List[str]] = None
    ioc_description: Optional[str] = None


@dataclass
class IrisCase:
    """IRIS case model."""
    case_id: int
    case_name: str
    case_description: Optional[str]
    case_priority_id: Optional[int]  # Maps to priority: 4=low, 3=medium, 2=high, 1=critical
    case_open_date: Optional[datetime]
    case_update_date: Optional[datetime]
    case_status_id: Optional[int]  # Maps to status
    case_owner_id: Optional[int]
    case_tags: Optional[List[str]] = None


def parse_iris_case(raw: Dict[str, Any]) -> IrisCase:
    """
    Parse a raw IRIS case dict into an ``IrisCase`` instance.
    
    IRIS API uses integer IDs and different field names than TheHive.
    """
    # IRIS uses timestamps or ISO format strings
    open_date_value = raw.get("case_open_date") or raw.get("open_date")
    open_date: Optional[datetime] = None
    if isinstance(open_date_value, (int, float)):
        open_date = datetime.fromtimestamp(open_date_value)
    elif isinstance(open_date_value, str):
        try:
            open_date = datetime.fromisoformat(open_date_value.replace("Z", "+00:00"))
        except Exception:
            pass
    
    update_date_value = raw.get("case_update_date") or raw.get("update_date")
    update_date: Optional[datetime] = None
    if isinstance(update_date_value, (int, float)):
        update_date = datetime.fromtimestamp(update_date_value)
    elif isinstance(update_date_value, str):
        try:
            update_date = datetime.fromisoformat(update_date_value.replace("Z", "+00:00"))
        except Exception:
            pass

    return IrisCase(
        case_id=int(raw.get("case_id", raw.get("id", 0))),
        case_name=raw.get("case_name", raw.get("name", "")),
        case_description=raw.get("case_description", raw.get("description")),
        case_priority_id=raw.get("case_priority_id", raw.get("priority_id")),
        case_open_date=open_date,
        case_update_date=update_date,
        case_status_id=raw.get("case_status_id", raw.get("status_id")),
        case_owner_id=raw.get("case_owner_id", raw.get("owner_id")),
        case_tags=raw.get("case_tags", raw.get("tags")) or [],
    )


def parse_iris_ioc(raw: Dict[str, Any]) -> IrisIOC:
    """
    Parse a raw IRIS IOC dict.
    """
    return IrisIOC(
        id=int(raw.get("ioc_id", 0)),
        ioc_type=raw.get("ioc_type", ""),
        ioc_value=raw.get("ioc_value", ""),
        ioc_tags=raw.get("ioc_tags") or [],
        ioc_description=raw.get("ioc_description"),
    )


def parse_iris_user(raw: Dict[str, Any]) -> IrisUser:
    """
    Parse a raw IRIS user dict.
    """
    return IrisUser(
        id=int(raw.get("user_id", 0)),
        user=raw.get("user", ""),
        name=raw.get("name"),
        email=raw.get("email"),
    )

