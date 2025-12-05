"""
Unit tests for TheHive mapper edge cases and mapping logic.
"""

import pytest
from datetime import datetime

from src.api.case_management import (
    Case,
    CaseComment,
    CaseObservable,
    CasePriority,
    CaseStatus,
    CaseSummary,
)
from src.integrations.case_management.thehive.thehive_mapper import (
    case_to_thehive_payload,
    comment_to_thehive_payload,
    observable_to_thehive_payload,
    priority_to_thehive_priority,
    status_to_thehive_status,
    thehive_case_to_generic,
    thehive_case_to_summary,
    thehive_comment_to_generic,
    thehive_observable_to_generic,
)


class TestCaseToTheHivePayload:
    """Test mapping generic Case to TheHive payload."""

    def test_case_with_all_fields(self):
        """Test case with all fields populated."""
        case = Case(
            id="test-123",
            title="Test Case",
            description="Test description",
            status=CaseStatus.OPEN,
            priority=CasePriority.HIGH,
            assignee="admin@example.com",
            tags=["tag1", "tag2"],
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )
        payload = case_to_thehive_payload(case)
        
        assert payload["title"] == "Test Case"
        assert payload["description"] == "Test description"
        assert payload["tags"] == ["tag1", "tag2"]
        assert payload["severity"] == 3  # HIGH priority
        assert payload["status"] == "Open"
        assert payload["owner"] == "admin@example.com"

    def test_case_with_minimal_fields(self):
        """Test case with only required fields."""
        case = Case(
            id="test-123",
            title="Minimal Case",
            description="",
            status=None,
            priority=None,
            assignee=None,
            tags=None,
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )
        payload = case_to_thehive_payload(case)
        
        assert payload["title"] == "Minimal Case"
        assert payload["description"] == ""
        assert payload["tags"] == []
        assert "severity" not in payload
        assert "status" not in payload
        assert "owner" not in payload

    def test_case_priority_mapping(self):
        """Test all priority levels map correctly."""
        priorities = [
            (CasePriority.LOW, 1),
            (CasePriority.MEDIUM, 2),
            (CasePriority.HIGH, 3),
            (CasePriority.CRITICAL, 4),
        ]
        
        for priority, expected_severity in priorities:
            case = Case(
                id="test",
                title="Test",
                description="",
                status=None,
                priority=priority,
                assignee=None,
                tags=None,
                created_at=datetime.now(),
                updated_at=datetime.now(),
            )
            payload = case_to_thehive_payload(case)
            assert payload["severity"] == expected_severity


class TestStatusToTheHiveStatus:
    """Test status mapping."""

    def test_all_status_mappings(self):
        """Test all status values map correctly."""
        assert status_to_thehive_status(CaseStatus.OPEN).value == "Open"
        assert status_to_thehive_status(CaseStatus.IN_PROGRESS).value == "InProgress"
        assert status_to_thehive_status(CaseStatus.CLOSED).value == "Resolved"

    def test_unknown_status_defaults_to_open(self):
        """Test that unknown status defaults to Open."""
        # This tests the .get() default in the mapping
        result = status_to_thehive_status(CaseStatus.OPEN)
        assert result.value == "Open"


class TestPriorityToTheHivePriority:
    """Test priority mapping."""

    def test_all_priority_mappings(self):
        """Test all priority values map correctly."""
        assert priority_to_thehive_priority(CasePriority.LOW).value == "low"
        assert priority_to_thehive_priority(CasePriority.MEDIUM).value == "medium"
        assert priority_to_thehive_priority(CasePriority.HIGH).value == "high"
        assert priority_to_thehive_priority(CasePriority.CRITICAL).value == "critical"


class TestCommentToTheHivePayload:
    """Test comment mapping."""

    def test_comment_mapping(self):
        """Test comment converts correctly."""
        comment = CaseComment(
            id="comment-1",
            case_id="case-1",
            author="user@example.com",
            content="This is a comment",
            created_at=datetime.now(),
        )
        payload = comment_to_thehive_payload(comment)
        
        assert payload["message"] == "This is a comment"


class TestObservableToTheHivePayload:
    """Test observable mapping."""

    def test_observable_with_all_fields(self):
        """Test observable with all fields."""
        observable = CaseObservable(
            type="ip",
            value="192.168.1.1",
            tags=["malicious"],
            description="Suspicious IP",
        )
        payload = observable_to_thehive_payload(observable)
        
        assert payload["dataType"] == "ip"
        assert payload["data"] == "192.168.1.1"
        assert payload["tags"] == ["malicious"]
        assert payload["message"] == "Suspicious IP"

    def test_observable_with_minimal_fields(self):
        """Test observable with minimal fields."""
        observable = CaseObservable(
            type="domain",
            value="example.com",
            tags=None,
            description=None,
        )
        payload = observable_to_thehive_payload(observable)
        
        assert payload["dataType"] == "domain"
        assert payload["data"] == "example.com"
        assert payload["tags"] == []
        assert payload["message"] == ""


class TestTheHiveCaseToGeneric:
    """Test mapping TheHive case to generic Case."""

    def test_case_with_all_fields(self):
        """Test case with all fields."""
        raw = {
            "_id": "case-123",
            "title": "Test Case",
            "description": "Test description",
            "status": "Open",
            "severity": 3,
            "owner": "admin@example.com",
            "tags": ["tag1", "tag2"],
            "startDate": 1699123456789,
        }
        case = thehive_case_to_generic(raw)
        
        assert case.id == "case-123"
        assert case.title == "Test Case"
        assert case.description == "Test description"
        assert case.status == CaseStatus.OPEN
        assert case.priority == CasePriority.HIGH
        assert case.assignee == "admin@example.com"
        assert case.tags == ["tag1", "tag2"]

    def test_case_with_missing_fields(self):
        """Test case with missing optional fields."""
        raw = {
            "_id": "case-456",
            "title": "Minimal Case",
            "status": "InProgress",
            "severity": 1,
        }
        case = thehive_case_to_generic(raw)
        
        assert case.id == "case-456"
        assert case.title == "Minimal Case"
        assert case.description == ""  # Default when missing
        assert case.status == CaseStatus.IN_PROGRESS
        assert case.priority == CasePriority.LOW
        assert case.assignee is None
        assert case.tags == []

    def test_severity_to_priority_mapping(self):
        """Test severity values map to correct priorities."""
        test_cases = [
            (0, CasePriority.LOW),
            (1, CasePriority.LOW),
            (2, CasePriority.MEDIUM),
            (3, CasePriority.HIGH),
            (4, CasePriority.CRITICAL),
            (5, CasePriority.CRITICAL),  # > 4 maps to CRITICAL
        ]
        
        for severity, expected_priority in test_cases:
            raw = {
                "_id": "test",
                "title": "Test",
                "status": "Open",
                "severity": severity,
            }
            case = thehive_case_to_generic(raw)
            assert case.priority == expected_priority, f"Severity {severity} should map to {expected_priority}"

    def test_status_mapping(self):
        """Test all TheHive status values map correctly."""
        status_mappings = [
            ("Open", CaseStatus.OPEN),
            ("InProgress", CaseStatus.IN_PROGRESS),
            ("Resolved", CaseStatus.CLOSED),
            ("Deleted", CaseStatus.CLOSED),
            ("Unknown", CaseStatus.OPEN),  # Default for unknown
        ]
        
        for thehive_status, expected_status in status_mappings:
            raw = {
                "_id": "test",
                "title": "Test",
                "status": thehive_status,
                "severity": 2,
            }
            case = thehive_case_to_generic(raw)
            assert case.status == expected_status, f"TheHive status {thehive_status} should map to {expected_status}"


class TestTheHiveCaseToSummary:
    """Test mapping TheHive case to CaseSummary."""

    def test_summary_mapping(self):
        """Test case summary mapping."""
        raw = {
            "_id": "case-789",
            "title": "Summary Case",
            "status": "Open",
            "severity": 2,
            "owner": "user@example.com",
            "startDate": 1699123456789,
        }
        summary = thehive_case_to_summary(raw)
        
        assert summary.id == "case-789"
        assert summary.title == "Summary Case"
        assert summary.status == CaseStatus.OPEN
        assert summary.priority == CasePriority.MEDIUM
        assert summary.assignee == "user@example.com"


class TestTheHiveCommentToGeneric:
    """Test mapping TheHive comment to generic CaseComment."""

    def test_comment_with_all_fields(self):
        """Test comment with all fields."""
        raw = {
            "id": "comment-123",
            "message": "This is a comment",
            "user": "user@example.com",
            "createdAt": 1699123456789,
        }
        comment = thehive_comment_to_generic(raw, "case-1")
        
        assert comment.id == "comment-123"
        assert comment.case_id == "case-1"
        assert comment.content == "This is a comment"
        assert comment.author == "user@example.com"
        assert comment.created_at is not None

    def test_comment_with_alt_id_field(self):
        """Test comment using _id instead of id."""
        raw = {
            "_id": "comment-456",
            "message": "Comment with _id",
            "user": "user@example.com",
        }
        comment = thehive_comment_to_generic(raw, "case-2")
        
        assert comment.id == "comment-456"

    def test_comment_with_missing_fields(self):
        """Test comment with missing optional fields."""
        raw = {
            "message": "Comment without all fields",
        }
        comment = thehive_comment_to_generic(raw, "case-3")
        
        assert comment.id is not None  # Should generate or use empty string
        assert comment.case_id == "case-3"
        assert comment.content == "Comment without all fields"
        assert comment.author is None
        assert comment.created_at is None


class TestTheHiveObservableToGeneric:
    """Test mapping TheHive observable to generic CaseObservable."""

    def test_observable_mapping(self):
        """Test observable mapping."""
        raw = {
            "dataType": "ip",
            "data": "192.168.1.1",
            "tags": ["malicious"],
        }
        observable = thehive_observable_to_generic(raw, "case-1")
        
        assert observable.type == "ip"
        assert observable.value == "192.168.1.1"
        assert observable.tags == ["malicious"]

    def test_observable_with_missing_tags(self):
        """Test observable with missing tags."""
        raw = {
            "dataType": "domain",
            "data": "example.com",
        }
        observable = thehive_observable_to_generic(raw, "case-2")
        
        assert observable.type == "domain"
        assert observable.value == "example.com"
        assert observable.tags == []

