"""
IRIS implementation of the generic ``CaseManagementClient`` interface.
"""

from __future__ import annotations

from typing import List, Optional, Dict, Any

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
from .iris_http import IrisHttpClient
from .iris_mapper import (
    case_to_iris_payload,
    comment_to_iris_payload,
    iris_case_to_generic,
    iris_case_to_summary,
    iris_comment_to_generic,
    iris_ioc_to_observable,
    observable_to_iris_payload,
    status_to_iris_status_id,
)


logger = get_logger("sami.integrations.iris.client")


class IRISCaseManagementClient(CaseManagementClient):
    """
    Case management client backed by IRIS.
    """

    def __init__(self, http_client: IrisHttpClient) -> None:
        self._http = http_client

    @classmethod
    def from_config(cls, config: SamiConfig) -> "IRISCaseManagementClient":
        """
        Factory to construct a client from ``SamiConfig``.
        """
        if not config.iris:
            raise IntegrationError("IRIS configuration is not set in SamiConfig")

        http_client = IrisHttpClient(
            base_url=config.iris.base_url,
            api_key=config.iris.api_key,
            timeout_seconds=config.iris.timeout_seconds,
            verify_ssl=config.iris.verify_ssl,
        )
        return cls(http_client=http_client)

    # Core CRUD operations

    def create_case(self, case: Case) -> Case:
        """
        Create a new case in IRIS.
        
        Uses IRIS API endpoint: POST /manage/cases/add
        """
        payload = case_to_iris_payload(case)
        raw = self._http.post("/manage/cases/add", json_data=payload)
        return iris_case_to_generic(raw)

    def get_case(self, case_id: str) -> Case:
        """
        Get a case by ID from IRIS.
        
        Uses IRIS API endpoint: GET /case/case-summary/update (with cid parameter)
        Note: IRIS v2.0.0+ requires cid parameter for access control
        """
        # IRIS v2.0.0+ requires cid parameter
        raw = self._http.get("/case/case-summary/update", params={"cid": case_id})
        return iris_case_to_generic(raw)

    def list_cases(
        self,
        status: Optional[CaseStatus] = None,
        limit: int = 50,
    ) -> List[CaseSummary]:
        """
        List cases from IRIS, optionally filtered by status.
        
        Uses IRIS API endpoint: GET /manage/cases/list
        """
        params: dict = {}
        if status is not None:
            params["state_id"] = status_to_iris_status_id(status)
        
        # IRIS API uses /manage/cases/list endpoint
        response = self._http.get("/manage/cases/list", params=params)
        
        # Response is already unwrapped by iris_http (returns data field)
        # IRIS returns a list of cases directly
        if isinstance(response, list):
            raw_list = response
        elif isinstance(response, dict) and "data" in response:
            raw_list = response["data"]
        else:
            raw_list = []
        
        return [iris_case_to_summary(raw) for raw in raw_list[:limit]]

    def search_cases(self, query: CaseSearchQuery) -> List[CaseSummary]:
        """
        Search cases in IRIS.
        
        Uses IRIS API endpoint: GET /manage/cases/filter
        """
        params: dict = {}
        if query.text:
            params["search"] = query.text
        if query.status:
            params["state_id"] = status_to_iris_status_id(query.status)
        if query.assignee:
            params["owner_id"] = query.assignee

        # IRIS API uses /manage/cases/filter for searching
        response = self._http.get("/manage/cases/filter", params=params)
        
        # Response is already unwrapped by iris_http
        if isinstance(response, list):
            raw_list = response
        elif isinstance(response, dict) and "data" in response:
            raw_list = response["data"]
        else:
            raw_list = []
        
        summaries = [iris_case_to_summary(raw) for raw in raw_list]
        return summaries[:query.limit]

    def update_case(self, case_id: str, updates: dict) -> Case:
        """
        Update a case in IRIS.
        
        Uses IRIS API endpoint: POST /manage/cases/update/{case_id}
        Note: IRIS v2.0.0+ uses POST for updates, not PATCH
        """
        # Always ensure client is set to "All" (customer_id: 3)
        updates = updates.copy()  # Don't modify the original dict
        updates["case_customer"] = 3
        
        raw = self._http.post(f"/manage/cases/update/{case_id}", json_data=updates)
        return iris_case_to_generic(raw)

    def delete_case(self, case_id: str) -> None:
        """
        Delete a case from IRIS.
        
        Uses IRIS API endpoint: POST /manage/cases/delete/{case_id}
        Note: IRIS v2.0.0+ uses POST for deletion, not DELETE
        """
        self._http.post(f"/manage/cases/delete/{case_id}")

    # Comments, notes and observables
    
    def add_case_comment(
        self,
        case_id: str,
        content: str,
        author: Optional[str] = None,
    ) -> CaseComment:
        """
        Add a comment/note to a case in IRIS.
        
        On newer IRIS versions the `/comments/add` endpoint may not be available
        anymore. To ensure comments/notes are visible in the GUI for all users,
        this implementation uses the **Case notes** API:
        
        1. Create a notes group for the case (if needed) via
           ``POST /case/notes/groups/add?cid=<case_id>``.
        2. Create a note inside that group via ``POST /case/notes/add`` with
           body containing ``note_title``, ``note_content`` and ``group_id``.
        
        This maps back to the generic ``CaseComment`` DTO.
        """
        # Defensive: normalise case_id / cid
        cid_int = int(case_id) if isinstance(case_id, str) and case_id.isdigit() else case_id
        
        # 1) Create a notes group for this case.
        # We create a lightweight group each time; IRIS handles multiple groups per case.
        group_title = f"Notes for case {case_id}"
        group_payload: Dict[str, Any] = {"group_title": group_title}
        group_raw = self._http.post("/case/notes/groups/add", json_data=group_payload, params={"cid": cid_int})
        group_id = group_raw.get("group_id")
        if group_id is None:
            raise IntegrationError("IRIS did not return group_id when creating notes group")
        
        # 2) Create the note itself.
        # Use the first part of the content as the title if possible.
        note_title = (content or "").strip().splitlines()[0] or "Case note"
        if len(note_title) > 120:
            note_title = note_title[:117] + "..."
        
        note_payload: Dict[str, Any] = {
            "note_title": note_title,
            "note_content": content,
            "group_id": group_id,
        }
        
        note_raw = self._http.post("/case/notes/add", json_data=note_payload, params={"cid": cid_int})
        
        # Map note response to generic CaseComment DTO
        from datetime import datetime
        
        comment_id = str(note_raw.get("note_id", note_raw.get("id", 0)))
        created_at_str = note_raw.get("note_creationdate") or note_raw.get("note_lastupdate")
        created_at: Optional[datetime] = None
        if isinstance(created_at_str, str):
            try:
                created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
            except Exception:
                created_at = None
        
        return CaseComment(
            id=comment_id,
            case_id=str(case_id),
            author=author,
            content=content,
            created_at=created_at,
        )

    def add_case_observable(
        self,
        case_id: str,
        observable: CaseObservable,
    ) -> CaseObservable:
        """
        Add an observable (IOC) to a case in IRIS.
        
        Uses IRIS API endpoint: POST /case/ioc/add
        Note: IRIS v2.0.0+ requires cid parameter
        """
        payload = observable_to_iris_payload(observable)
        payload["cid"] = case_id
        raw = self._http.post("/case/ioc/add", json_data=payload)
        return iris_ioc_to_observable(raw, case_id=case_id)

    # Status and assignment

    def update_case_status(
        self,
        case_id: str,
        status: CaseStatus,
    ) -> Case:
        """
        Update the status of a case in IRIS.
        
        Uses IRIS API endpoint: POST /manage/cases/update/{case_id}
        """
        payload = {
            "state_id": status_to_iris_status_id(status),
            "case_customer": 3,  # Always use "All" client (customer_id: 3)
        }
        raw = self._http.post(f"/manage/cases/update/{int(case_id)}", json_data=payload)
        return iris_case_to_generic(raw)

    def assign_case(
        self,
        case_id: str,
        assignee: str,
    ) -> CaseAssignment:
        """
        Assign a case to a user in IRIS.
        
        Uses IRIS API endpoint: POST /manage/cases/update/{case_id}
        """
        # IRIS uses owner_id, so assignee should be the user ID
        payload = {"case_owner_id": assignee}
        raw = self._http.post(f"/manage/cases/update/{case_id}", json_data=payload)
        case = iris_case_to_generic(raw)
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
        """
        Link two cases in IRIS.
        
        Uses IRIS API endpoint: POST /case/case-link/add
        Note: IRIS v2.0.0+ requires cid parameter
        """
        payload = {
            "cid": source_case_id,
            "case_id": int(target_case_id),
            "link_type": link_type,
        }
        self._http.post("/case/case-link/add", json_data=payload)

    def get_case_timeline(self, case_id: str) -> List[CaseComment]:
        """
        Get the timeline (comments) for a case in IRIS.
        
        Uses IRIS API endpoint: GET /comments/list
        Note: IRIS v2.0.0+ requires cid parameter
        """
        # IRIS API requires cid and object_type parameters
        raw_list = self._http.get("/comments/list", params={"cid": case_id, "object_type": "case"})
        
        # Response is already unwrapped by iris_http
        if isinstance(raw_list, list):
            pass  # Already a list
        elif isinstance(raw_list, dict) and "data" in raw_list:
            raw_list = raw_list["data"]
        else:
            raw_list = []
        
        return [iris_comment_to_generic(raw, case_id=case_id) for raw in raw_list]

    # Timeline events

    def add_case_timeline_event(
        self,
        case_id: str,
        title: str,
        content: str,
        source: Optional[str] = None,
        category_id: Optional[int] = None,
        tags: Optional[List[str]] = None,
        color: Optional[str] = None,
        event_date: Optional[str] = None,
        include_in_summary: bool = True,
        include_in_graph: bool = True,
        sync_iocs_assets: bool = True,
        asset_ids: Optional[List[int]] = None,
        ioc_ids: Optional[List[int]] = None,
        custom_attributes: Optional[Dict[str, Any]] = None,
        raw: Optional[str] = None,
        tz: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Add an event to a case timeline in IRIS.
        
        Uses IRIS API endpoint: POST /case/timeline/events/add
        as documented in IRIS API reference v2.0.2
        (Case timeline → Add a new event).
        """
        from datetime import datetime, timezone

        cid_int = int(case_id) if isinstance(case_id, str) and case_id.isdigit() else case_id

        # Build reasonable defaults following the API example.
        if event_date is None:
            # Use current UTC time in 'YYYY-MM-DDTHH:MM:SS.mmm' format
            # as shown in IRIS API examples.
            now = datetime.utcnow()
            event_date = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        if tz is None:
            tz = "+00:00"

        payload: Dict[str, Any] = {
            "event_title": title,
            "event_content": content,
            "event_source": source or "SamiGPT",
            "event_category_id": str(category_id or 5),
            "event_in_summary": include_in_summary,
            "event_in_graph": include_in_graph,
            "event_color": color or "#1572E899",
            "event_date": event_date,
            "event_sync_iocs_assets": sync_iocs_assets,
            "event_tags": ",".join(tags) if tags else "",
            "event_tz": tz,
            "custom_attributes": custom_attributes or {},
            "event_raw": raw or content,
            # Always include these arrays; IRIS may require them even if empty
            "event_assets": [],
            "event_iocs": [],
        }

        if asset_ids:
            payload["event_assets"] = [int(a) for a in asset_ids]
        if ioc_ids:
            payload["event_iocs"] = [int(i) for i in ioc_ids]

        raw_resp = self._http.post(
            "/case/timeline/events/add",
            json_data=payload,
            params={"cid": cid_int},
        )
        return raw_resp

    def list_case_timeline_events(self, case_id: str) -> List[Dict[str, Any]]:
        """
        List timeline events for a case in IRIS.
        
        Uses IRIS API endpoint: GET /case/timeline/events/list
        """
        cid_int = int(case_id) if isinstance(case_id, str) and case_id.isdigit() else case_id
        raw = self._http.get("/case/timeline/events/list", params={"cid": cid_int})

        # Response structure:
        # {"status": "...", "message": "...", "data": {"state": {...}, "timeline": [ ... ]}}
        if isinstance(raw, dict) and "data" in raw:
            data = raw["data"] or {}
            timeline = data.get("timeline") or []
        else:
            timeline = []

        return timeline

    # Tasks
    
    def add_case_task(
        self,
        case_id: str,
        title: str,
        description: str,
        assignee: Optional[str] = None,
        priority: str = "medium",  # accepted but not sent – IRIS task API doesn't use priority
        status: str = "pending",
        assignees: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        custom_attributes: Optional[dict] = None,
    ) -> Dict[str, Any]:
        """
        Add a task to a case in IRIS.
        
        Uses IRIS API endpoint: POST /case/tasks/add
        as documented in the IRIS API reference v2.0.2
        (see [Case tasks → Add a case task](https://docs.dfir-iris.org/_static/iris_api_reference_v2.0.2.html#tag/Case-tasks/operation/post-case-add-task)).
        
        Request body:
        {
            "task_assignees_id": [1],
            "task_description": "",
            "task_status_id": 1,
            "task_tags": "",
            "task_title": "dummy title",
            "custom_attributes": {}
        }
        """
        # IRIS v2.0.0+ requires cid as query parameter in URI
        cid_int = int(case_id) if isinstance(case_id, str) and case_id.isdigit() else case_id
        
        payload: Dict[str, Any] = {
            "task_title": title,
            "task_description": description,
            "task_status_id": self._task_status_to_id(status),
        }
        
        # Build task_assignees_id (list of integers)
        assignee_ids: List[int] = []
        if assignees:
            for a in assignees:
                try:
                    assignee_ids.append(int(a))
                except (TypeError, ValueError):
                    continue
        elif assignee is not None:
            try:
                assignee_ids.append(int(assignee))
            except (TypeError, ValueError):
                pass
        else:
            # Fallback to current user (ID 1) if no assignee is provided.
            # This matches the official API example and ensures compatibility
            # when the caller doesn't specify an assignee explicitly.
            assignee_ids.append(1)

        if assignee_ids:
            payload["task_assignees_id"] = assignee_ids
        
        # task_tags is a single string; join list if provided
        if tags:
            payload["task_tags"] = ",".join(tags)
        
        # custom_attributes is an arbitrary JSON object
        if custom_attributes:
            payload["custom_attributes"] = custom_attributes

        # Call the tasks endpoint with cid as query parameter (required since v2.0.0)
        raw = self._http.post("/case/tasks/add", json_data=payload, params={"cid": cid_int})
        return raw
    
    def _task_status_to_id(self, status: str) -> int:
        """Map task status string to IRIS status ID."""
        status_map = {
            "pending": 1,
            "in_progress": 2,
            "completed": 3,
            "blocked": 4,
        }
        return status_map.get(status.lower(), 1)
    
    def _priority_to_task_priority_id(self, priority: str) -> int:
        """Map priority string to IRIS priority ID."""
        priority_map = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        return priority_map.get(priority.lower(), 2)
    
    def list_case_tasks(self, case_id: str) -> List[Dict[str, Any]]:
        """
        List tasks for a case in IRIS.
        
        Uses IRIS API endpoint: GET /case/tasks/list (plural)
        """
        cid_int = int(case_id) if isinstance(case_id, str) and case_id.isdigit() else case_id
        raw_list = self._http.get("/case/tasks/list", params={"cid": cid_int})
        
        if isinstance(raw_list, list):
            return raw_list
        elif isinstance(raw_list, dict) and "data" in raw_list:
            return raw_list["data"]
        else:
            return []
    
    def update_case_task_status(
        self,
        case_id: str,
        task_id: str,
        status: str,
    ) -> Dict[str, Any]:
        """
        Update the status of a task in a case.
        
        Uses IRIS API endpoint: POST /case/tasks/update/{task_id}
        as documented in the IRIS API reference v2.0.2
        
        Endpoint format: /case/tasks/update/{task_id}
        Query parameter: cid (case ID) - required for v2.0.0+
        Request body:
        {
            "task_status_id": 2,
            "task_assignees_id": [1],  # Include existing assignees to avoid validation errors
            ...
        }
        
        Note: task_id is in the path, not in the request body.
        
        To avoid server-side validation issues with deprecated fields, we fetch
        the current task first to get its assignees, then include them in the update.
        """
        cid_int = int(case_id) if isinstance(case_id, str) and case_id.isdigit() else case_id
        task_id_int = int(task_id) if isinstance(task_id, str) and task_id.isdigit() else task_id
        
        # IRIS API requires certain fields to be present in update requests.
        # Even though the docs say fields are optional, the server may require
        # task_title and other fields. We need to fetch the current task first
        # to include all required fields in the update.
        
        # Fetch current task using GET /case/tasks/{task_id} endpoint
        current_task_data: Optional[Dict[str, Any]] = None
        try:
            endpoint = f"/case/tasks/{task_id_int}"
            task_response = self._http.get(endpoint, params={"cid": cid_int})
            # The GET endpoint returns the task data directly (not wrapped in "data" field)
            if isinstance(task_response, dict):
                # Check if it's wrapped in "data" field (some endpoints do this)
                if "data" in task_response and isinstance(task_response["data"], dict):
                    current_task_data = task_response["data"]
                # Otherwise, the response is the task data directly
                elif "id" in task_response or "task_title" in task_response:
                    current_task_data = task_response
        except Exception:
            # If fetching task fails, we'll try a minimal update
            pass
        
        # Build payload with required fields from current task
        payload: Dict[str, Any] = {
            "task_status_id": self._task_status_to_id(status),
        }
        
        # Include existing task fields to satisfy API requirements
        if current_task_data:
            # Include task_title (required by server even if docs say optional)
            if "task_title" in current_task_data:
                payload["task_title"] = current_task_data["task_title"]
            
            # Include task_description if present
            if "task_description" in current_task_data:
                payload["task_description"] = current_task_data.get("task_description", "")
            
            # Include task_tags if present
            if "task_tags" in current_task_data:
                payload["task_tags"] = current_task_data.get("task_tags", "")
            
            # Extract and include assignees
            assignees = current_task_data.get('task_assignees', [])
            assignee_ids: List[int] = []
            if assignees and isinstance(assignees, list):
                for assignee in assignees:
                    if isinstance(assignee, dict):
                        assignee_id = assignee.get('id')
                    elif isinstance(assignee, (int, str)):
                        assignee_id = assignee
                    else:
                        continue
                    if assignee_id:
                        try:
                            assignee_ids.append(int(assignee_id))
                        except (TypeError, ValueError):
                            continue
            
            # If no assignees found, default to user 1 (matches add_case_task behavior)
            if not assignee_ids:
                assignee_ids = [1]
            
            payload["task_assignees_id"] = assignee_ids
            
            # Include custom_attributes if present
            if "custom_attributes" in current_task_data:
                payload["custom_attributes"] = current_task_data.get("custom_attributes", {})
        else:
            # If we couldn't fetch the task, use minimal required fields
            # Default to user 1 for assignees (matches add_case_task behavior)
            payload["task_assignees_id"] = [1]
            # Note: This may fail if task_title is required, but we'll try anyway
        
        # Call the tasks update endpoint with task_id in path and cid as query parameter
        endpoint = f"/case/tasks/update/{task_id_int}"
        # Debug: log the payload being sent (remove in production if needed)
        # import logging; logging.getLogger(__name__).debug(f"Updating task {task_id_int} with payload: {payload}")
        raw = self._http.post(endpoint, json_data=payload, params={"cid": cid_int})
        return raw
    
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
        asset_domain: Optional[str] = None,
        compromise_status_id: Optional[int] = None,
        analysis_status_id: Optional[int] = None,
        custom_attributes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Add an asset to a case in IRIS.
        
        Uses IRIS API endpoint: POST /case/assets/add (plural)
        Note: IRIS v2.0.0+ requires cid parameter and asset_type_id (integer) instead of asset_type (string)
        """
        # Map asset_type string to asset_type_id integer
        asset_type_id = self._asset_type_to_id(asset_type)
        cid_int = int(case_id) if isinstance(case_id, str) and case_id.isdigit() else case_id
        
        # Build payload according to IRIS API v2.0.2 (Case assets → Add a new asset)
        # See: https://docs.dfir-iris.org/_static/iris_api_reference_v2.0.2.html#tag/Case-assets/operation/post-case-asset-add
        payload: Dict[str, Any] = {
            "asset_type_id": str(asset_type_id),
            "asset_name": asset_name,
            "asset_description": description or "",
        }
        
        if asset_domain:
            payload["asset_domain"] = asset_domain
        if ip_address:
            payload["asset_ip"] = ip_address
        # Optional informational field
        payload["asset_info"] = ""
        
        # Default compromise / analysis status if not provided
        payload["asset_compromise_status_id"] = str(compromise_status_id or 1)
        payload["analysis_status_id"] = str(analysis_status_id or 3)
        
        # No IOC links by default
        payload["ioc_links"] = []
        
        if tags:
            payload["asset_tags"] = ",".join(tags)
        
        # custom_attributes is an arbitrary JSON object
        payload["custom_attributes"] = custom_attributes or {}
        
        # IRIS v2.0.0+ requires cid as query parameter in URI (per API documentation)
        raw = self._http.post("/case/assets/add", json_data=payload, params={"cid": cid_int})
        return raw
    
    def _asset_type_to_id(self, asset_type: str) -> int:
        """Map asset type string to IRIS asset_type_id."""
        # IRIS asset types: 1=Account, 2=Host, 3=Network, 4=Other
        # Map common types to IRIS IDs
        type_map = {
            "endpoint": 2,  # Host
            "server": 2,     # Host
            "host": 2,       # Host
            "network": 3,    # Network
            "user_account": 1,  # Account
            "account": 1,    # Account
            "application": 4,  # Other
            "other": 4,      # Other
        }
        return type_map.get(asset_type.lower(), 2)  # Default to Host
    
    def list_case_assets(self, case_id: str) -> List[Dict[str, Any]]:
        """
        List assets for a case in IRIS.
        
        Uses IRIS API endpoint: GET /case/assets/list (plural)
        """
        cid_int = int(case_id) if isinstance(case_id, str) and case_id.isdigit() else case_id
        raw_list = self._http.get("/case/assets/list", params={"cid": cid_int})
        
        if isinstance(raw_list, list):
            return raw_list
        elif isinstance(raw_list, dict) and "data" in raw_list:
            return raw_list["data"]
        else:
            return []
    
    # Evidence
    
    def list_evidence_types(self) -> List[Dict[str, Any]]:
        """
        List evidence types supported by IRIS.
        
        Uses IRIS API endpoint: GET /manage/evidence-types/list
        """
        raw = self._http.get("/manage/evidence-types/list")

        if isinstance(raw, list):
            return raw
        elif isinstance(raw, dict) and "data" in raw:
            return raw["data"] or []
        else:
            return []

    def _resolve_evidence_type_id(self, evidence_type: str) -> Optional[int]:
        """
        Resolve an evidence type name or numeric string to a type_id.
        Returns None if not found.
        """
        # If it's already an integer string, use it directly
        if evidence_type.isdigit():
            return int(evidence_type)

        types = self.list_evidence_types()
        for t in types:
            if str(t.get("name", "")).lower() == evidence_type.lower():
                return int(t.get("id"))
        return None

    def add_case_evidence(
        self,
        case_id: str,
        file_path: str,
        description: Optional[str] = None,
        evidence_type: Optional[str] = None,
        custom_attributes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Add evidence (file) to a case in IRIS.
        
        Uses IRIS API endpoint: POST /case/evidences/add (plural)
        Note: IRIS v2.0.0+ requires cid parameter and filename field.

        Evidence types are managed by IRIS and can be listed with
        ``list_evidence_types()``. Common log-related evidence types include:

        - Logs - Linux
        - Logs - Windows EVTX
        - Logs - Windows EVT
        - Logs - MacOS
        - Logs - Generic
        - Logs - Firewall
        - Logs - Proxy
        - Logs - DNS
        - Logs - Email

        The ``evidence_type`` parameter MUST match one of the IRIS evidence
        type names (or a valid numeric type_id as a string). If it does not,
        an IntegrationError is raised listing the allowed types.
        """
        import os
        import hashlib
        
        # Get filename and file size from file_path
        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        cid_int = int(case_id) if isinstance(case_id, str) and case_id.isdigit() else case_id
        
        # Compute a hash of the file content (SHA256). IRIS only requires a string.
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()
        
        # evidence_type is required – force users to pick a valid IRIS evidence type
        if not evidence_type:
            raise IntegrationError(
                "Evidence type is required for IRIS. "
                "Call list_evidence_types() to see allowed types, e.g. "
                "'Logs - Linux', 'Logs - Windows EVTX', 'Logs - Windows EVT', "
                "'Logs - MacOS', 'Logs - Generic', 'Logs - Firewall', "
                "'Logs - Proxy', 'Logs - DNS', 'Logs - Email'."
            )

        # Build metadata payload according to IRIS API v2.0.2 (Case evidences → Add an evidence):
        # Required fields: filename, file_size, file_hash, file_description, custom_attributes
        base_custom_attrs: Dict[str, Any] = custom_attributes.copy() if custom_attributes else {}

        # Resolve evidence type to type_id and enforce validity
        type_id = self._resolve_evidence_type_id(evidence_type)
        if type_id is None:
            types = self.list_evidence_types()
            allowed_names = [str(t.get("name")) for t in types if t.get("name")]
            raise IntegrationError(
                f"Invalid evidence type '{evidence_type}'. "
                f"Allowed types include: {', '.join(allowed_names[:20])}"
            )

        base_custom_attrs["evidence_type_name"] = evidence_type

        additional_data = {
            "filename": filename,
            "file_size": str(file_size),
            "file_hash": file_hash,
            "file_description": description or filename,
            "custom_attributes": base_custom_attrs,
            "type_id": type_id,
        }
        
        # Use cid as query parameter and send JSON body as specified by the API.
        # Note: On this IRIS version, /case/evidences/add expects application/json,
        # not multipart form-data.
        raw = self._http.post(
            "/case/evidences/add",
            json_data=additional_data,
            params={"cid": cid_int},
        )
        return raw
    
    def list_case_evidence(self, case_id: str) -> List[Dict[str, Any]]:
        """
        List evidence for a case in IRIS.
        
        Uses IRIS API endpoint: GET /case/evidences/list (plural)
        """
        cid_int = int(case_id) if isinstance(case_id, str) and case_id.isdigit() else case_id
        raw_list = self._http.get("/case/evidences/list", params={"cid": cid_int})
        
        if isinstance(raw_list, list):
            return raw_list
        elif isinstance(raw_list, dict) and "data" in raw_list:
            return raw_list["data"]
        else:
            return []

    # Health check

    def ping(self) -> bool:
        """
        Check if IRIS API is reachable.
        
        Uses IRIS API endpoint: GET /api/ping
        """
        try:
            # IRIS has a dedicated ping endpoint
            response = self._http.get("/api/ping")
            # Ping returns {"status": "success", "message": "pong", "data": []}
            return True
        except IntegrationError:
            logger.exception("IRIS ping failed")
            return False

