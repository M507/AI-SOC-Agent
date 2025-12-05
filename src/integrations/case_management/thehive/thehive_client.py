"""
TheHive implementation of the generic ``CaseManagementClient`` interface.
"""

from __future__ import annotations

from typing import List, Optional

from ....api.case_management import (
    Case,
    CaseAssignment,
    CaseComment,
    CaseManagementClient,
    CaseObservable,
    CaseSearchQuery,
    CaseStatus,
    CaseSummary,
)
from ....core.config import SamiConfig
from ....core.errors import IntegrationError
from ....core.logging import get_logger
from .thehive_http import TheHiveHttpClient
from .thehive_mapper import (
    case_to_thehive_payload,
    comment_to_thehive_payload,
    observable_to_thehive_payload,
    status_to_thehive_status,
    thehive_case_to_generic,
    thehive_case_to_summary,
    thehive_comment_to_generic,
)


logger = get_logger("sami.integrations.thehive.client")


class TheHiveCaseManagementClient(CaseManagementClient):
    """
    Case management client backed by TheHive.
    """

    def __init__(self, http_client: TheHiveHttpClient) -> None:
        self._http = http_client

    @classmethod
    def from_config(cls, config: SamiConfig) -> "TheHiveCaseManagementClient":
        """
        Factory to construct a client from ``SamiConfig``.
        """

        if not config.thehive:
            raise IntegrationError("TheHive configuration is not set in SamiConfig")

        http_client = TheHiveHttpClient(
            base_url=config.thehive.base_url,
            api_key=config.thehive.api_key,
            timeout_seconds=config.thehive.timeout_seconds,
        )
        return cls(http_client=http_client)

    # Core CRUD operations

    def create_case(self, case: Case) -> Case:
        payload = case_to_thehive_payload(case)
        raw = self._http.post("/api/case", json=payload)
        return thehive_case_to_generic(raw)

    def get_case(self, case_id: str) -> Case:
        raw = self._http.get(f"/api/case/{case_id}")
        return thehive_case_to_generic(raw)

    def list_cases(
        self,
        status: Optional[CaseStatus] = None,
        limit: int = 50,
    ) -> List[CaseSummary]:
        params = {"range": f"[0,{max(limit - 1, 0)}]"}
        if status is not None:
            params["status"] = status_to_thehive_status(status).value
        raw_list = self._http.get("/api/case", params=params)
        return [thehive_case_to_summary(raw) for raw in raw_list]

    def search_cases(self, query: CaseSearchQuery) -> List[CaseSummary]:
        # Very simple text/field search mapping; real implementations may need
        # to use TheHive's /api/case/_search endpoint with a JSON query body.
        params: dict = {}
        if query.text:
            params["title"] = query.text
        if query.status:
            params["status"] = status_to_thehive_status(query.status).value

        raw_list = self._http.get("/api/case", params=params)
        summaries = [thehive_case_to_summary(raw) for raw in raw_list]
        return summaries[: query.limit]

    def update_case(self, case_id: str, updates: dict) -> Case:
        raw = self._http.patch(f"/api/case/{case_id}", json=updates)
        return thehive_case_to_generic(raw)

    def delete_case(self, case_id: str) -> None:
        self._http.delete(f"/api/case/{case_id}")

    # Comments and observables

    def add_case_comment(
        self,
        case_id: str,
        content: str,
        author: Optional[str] = None,
    ) -> CaseComment:
        comment = CaseComment(
            id=None,
            case_id=case_id,
            author=author,
            content=content,
        )
        payload = comment_to_thehive_payload(comment)
        raw = self._http.post(f"/api/case/{case_id}/comment", json=payload)
        return thehive_comment_to_generic(raw, case_id=case_id)

    def add_case_observable(
        self,
        case_id: str,
        observable: CaseObservable,
    ) -> CaseObservable:
        payload = observable_to_thehive_payload(observable)
        raw = self._http.post(f"/api/case/{case_id}/artifact", json=payload)
        from .thehive_models import parse_thehive_observable

        return CaseObservable(
            type=parse_thehive_observable(raw).data_type,
            value=parse_thehive_observable(raw).data,
            tags=parse_thehive_observable(raw).tags or [],
            description=None,
        )

    # Status and assignment

    def update_case_status(
        self,
        case_id: str,
        status: CaseStatus,
    ) -> Case:
        payload = {"status": status_to_thehive_status(status).value}
        raw = self._http.patch(f"/api/case/{case_id}", json=payload)
        return thehive_case_to_generic(raw)

    def assign_case(
        self,
        case_id: str,
        assignee: str,
    ) -> CaseAssignment:
        payload = {"owner": assignee}
        raw = self._http.patch(f"/api/case/{case_id}", json=payload)
        case = thehive_case_to_generic(raw)
        from datetime import datetime

        return CaseAssignment(
            case_id=case.id or case_id,
            assignee=case.assignee or assignee,
            assigned_at=case.updated_at or datetime.utcnow(),
        )

    # Linking and timeline

    def link_cases(
        self,
        source_case_id: str,
        target_case_id: str,
        link_type: str,
    ) -> None:
        payload = {
            "caseId": target_case_id,
            "nature": link_type,
        }
        self._http.post(f"/api/case/{source_case_id}/link", json=payload)

    def get_case_timeline(self, case_id: str) -> List[CaseComment]:
        # For now, use the comments endpoint as a simple timeline proxy.
        raw_list = self._http.get(f"/api/case/{case_id}/comment")
        return [thehive_comment_to_generic(raw, case_id=case_id) for raw in raw_list]

    # Health check

    def ping(self) -> bool:
        try:
            self._http.get("/api/health")
            return True
        except IntegrationError:
            logger.exception("TheHive ping failed")
            return False


