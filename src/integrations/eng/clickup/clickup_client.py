"""
ClickUp client for creating tasks and recommendations.
"""

from __future__ import annotations

from typing import Dict, Any, Optional, List

from ....core.config import SamiConfig
from ....core.errors import IntegrationError
from ....core.logging import get_logger
from .clickup_http import ClickUpHttpClient


logger = get_logger("sami.integrations.clickup.client")


class ClickUpClient:
    """
    Client for interacting with ClickUp API to create tasks and recommendations.
    """

    def __init__(
        self,
        http_client: ClickUpHttpClient,
        fine_tuning_list_id: str,
        engineering_list_id: str,
        space_id: Optional[str] = None,
    ) -> None:
        """
        Initialize ClickUp client.
        
        Args:
            http_client: HTTP client for ClickUp API
            fine_tuning_list_id: ClickUp list ID for fine-tuning recommendations
                (can be a placeholder; if so, the client will auto-discover a list
                in the configured space)
            engineering_list_id: ClickUp list ID for engineering/visibility recommendations
                (can be a placeholder; if so, the client will auto-discover a list
                in the configured space)
            space_id: Optional ClickUp space ID that contains the engineering boards.
        """
        self._http = http_client
        self.fine_tuning_list_id = fine_tuning_list_id
        self.engineering_list_id = engineering_list_id
        self.space_id = space_id

    @classmethod
    def from_config(cls, config: SamiConfig) -> "ClickUpClient":
        """
        Factory to construct a client from ``SamiConfig``.
        
        Args:
            config: SamiConfig instance with ClickUp configuration
        
        Returns:
            ClickUpClient instance
        
        Raises:
            IntegrationError: If ClickUp configuration is not set
        """
        if not config.eng or not config.eng.clickup:
            raise IntegrationError("ClickUp configuration is not set in SamiConfig")

        clickup_config = config.eng.clickup
        http_client = ClickUpHttpClient(
            api_token=clickup_config.api_token,
            timeout_seconds=clickup_config.timeout_seconds,
            verify_ssl=clickup_config.verify_ssl,
        )
        
        return cls(
            http_client=http_client,
            fine_tuning_list_id=clickup_config.fine_tuning_list_id,
            engineering_list_id=clickup_config.engineering_list_id,
            space_id=clickup_config.space_id,
        )

    # ------------------------------------------------------------------
    # Internal helpers for resolving list IDs
    # ------------------------------------------------------------------

    @staticmethod
    def _is_placeholder_list_id(list_id: Optional[str]) -> bool:
        """
        Return True if the configured list ID looks like a placeholder.
        """
        if not list_id:
            return True
        placeholders = {
            "123456789",
            "987654321",
            "REPLACE_WITH_FINE_TUNING_LIST_ID",
            "REPLACE_WITH_VISIBILITY_LIST_ID",
        }
        return list_id in placeholders

    def _get_space_lists(self) -> List[Dict[str, Any]]:
        """
        Get all lists in the configured space.

        This is a lightweight, production-safe version of the helper logic
        we used in tests to enumerate ClickUp lists.
        """
        if not self.space_id:
            return []

        try:
            response = self._http.get(f"/v2/space/{self.space_id}/list")
        except IntegrationError as e:
            logger.warning(f"Failed to get lists for ClickUp space {self.space_id}: {e}")
            return []

        lists = response.get("lists")
        if isinstance(lists, list):
            return lists
        if isinstance(response, list):
            return response
        if isinstance(response, dict):
            return [response]
        return []

    def _auto_discover_list_id(self, purpose: str) -> str:
        """
        Auto-discover a list ID for the given purpose (\"fine_tuning\" or \"engineering\").

        Strategy:
        - Prefer lists in the configured space (space_id).
        - Try to match list names by keywords (fine-tuning vs visibility/engineering).
        - Fall back to the first list in the space if no better match is found.
        """
        lists = self._get_space_lists()
        if not lists:
            raise IntegrationError(
                "Unable to auto-discover ClickUp list ID: no lists found in the "
                "configured space. Please configure valid fine_tuning_list_id and "
                "engineering_list_id in config.eng.clickup."
            )

        purpose = purpose.lower()
        keywords: List[str] = []
        if purpose == "fine_tuning":
            # Match things like 'Fine-tuning Tasks'
            keywords = ["fine", "tun"]
        elif purpose == "engineering":
            # Match things like 'Visibility Tasks', 'Engineering Tasks', etc.
            keywords = ["visib", "engineer", "eng"]

        def matches_purpose(name: str) -> bool:
            name_l = name.lower()
            if not keywords:
                return False
            # For fine-tuning, require both 'fine' and 'tun' to reduce false matches.
            if purpose == "fine_tuning":
                return "fine" in name_l and "tun" in name_l
            # For engineering/visibility, any of the keywords is good enough.
            return any(k in name_l for k in keywords)

        # First, try to find best matches by name.
        matched_lists: List[Dict[str, Any]] = []
        for lst in lists:
            name = lst.get("name")
            if isinstance(name, str) and matches_purpose(name):
                matched_lists.append(lst)

        chosen: Optional[Dict[str, Any]] = None
        if matched_lists:
            chosen = matched_lists[0]
        else:
            # Fall back to the first list in the space.
            chosen = lists[0]

        list_id = chosen.get("id")
        if not list_id:
            raise IntegrationError(
                "Unable to auto-discover ClickUp list ID: discovered list has no 'id'."
            )

        logger.info(
            "Auto-discovered ClickUp list for %s: %s (id=%s)",
            purpose,
            chosen.get("name", "<unnamed>"),
            list_id,
        )
        return str(list_id)

    def _resolve_list_id(self, configured_id: str, purpose: str) -> str:
        """
        Resolve the effective list ID for the given purpose.

        If a non-placeholder list ID is configured, use it directly.
        Otherwise, auto-discover a list ID in the configured space.
        """
        if not self._is_placeholder_list_id(configured_id):
            return configured_id

        if not self.space_id:
            raise IntegrationError(
                f"ClickUp space_id is not configured, and the {purpose} "
                "list ID looks like a placeholder. Please configure "
                "eng.clickup.space_id and valid list IDs in config.json."
            )

        return self._auto_discover_list_id(purpose)

    def create_fine_tuning_recommendation(
        self,
        title: str,
        description: str,
        status: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create a fine-tuning recommendation task in ClickUp.
        
        Args:
            title: Task name
            description: Task description
            status: Optional status name (defaults to first status in list)
            tags: Optional list of tag names to add to the task
        
        Returns:
            Dictionary with task information
        """
        logger.info(f"Creating fine-tuning recommendation: {title}")

        # Resolve which ClickUp list to use (supports placeholders + auto-discovery).
        list_id = self._resolve_list_id(self.fine_tuning_list_id, purpose="fine_tuning")

        # Get list info to find status
        list_info = self._http.get(f"/v2/list/{list_id}")
        statuses = list_info.get("statuses", [])

        # Find the target status (ClickUp expects status as a string, not an object)
        target_status_value: Optional[str] = None
        if status:
            for status_item in statuses:
                if status_item.get("status") == status:
                    target_status_value = status_item.get("status")
                    break
            if not target_status_value:
                raise IntegrationError(f"Status '{status}' not found in fine-tuning list")
        else:
            # Use the first status if no status specified
            if not statuses:
                raise IntegrationError("No statuses found in fine-tuning list")
            target_status_value = statuses[0].get("status")
        
        # Create the task
        task_data = {
            "name": title,
            "description": description,
            "status": target_status_value,
        }
        
        # Add tags if provided
        if tags:
            task_data["tags"] = tags
        
        response = self._http.post(f"/v2/list/{list_id}/task", json_data=task_data)
        task = response.get("task", response)
        
        logger.info(f"Created fine-tuning recommendation task: {task.get('id')}")
        return task

    def create_visibility_recommendation(
        self,
        title: str,
        description: str,
        status: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create a visibility/engineering recommendation task in ClickUp.
        
        Args:
            title: Task name
            description: Task description
            status: Optional status name (defaults to first status in list)
            tags: Optional list of tag names to add to the task
        
        Returns:
            Dictionary with task information
        """
        logger.info(f"Creating visibility recommendation: {title}")

        # Resolve which ClickUp list to use (supports placeholders + auto-discovery).
        list_id = self._resolve_list_id(self.engineering_list_id, purpose="engineering")

        # Get list info to find status
        list_info = self._http.get(f"/v2/list/{list_id}")
        statuses = list_info.get("statuses", [])

        # Find the target status (ClickUp expects status as a string, not an object)
        target_status_value: Optional[str] = None
        if status:
            for status_item in statuses:
                if status_item.get("status") == status:
                    target_status_value = status_item.get("status")
                    break
            if not target_status_value:
                raise IntegrationError(f"Status '{status}' not found in engineering list")
        else:
            # Use the first status if no status specified
            if not statuses:
                raise IntegrationError("No statuses found in engineering list")
            target_status_value = statuses[0].get("status")
        
        # Create the task
        task_data = {
            "name": title,
            "description": description,
            "status": target_status_value,
        }
        
        # Add tags if provided
        if tags:
            task_data["tags"] = tags
        
        response = self._http.post(f"/v2/list/{list_id}/task", json_data=task_data)
        task = response.get("task", response)
        
        logger.info(f"Created visibility recommendation task: {task.get('id')}")
        return task

    def list_fine_tuning_recommendations(
        self,
        archived: bool = False,
        include_closed: bool = True,
        order_by: Optional[str] = None,
        reverse: bool = False,
        subtasks: bool = False,
        statuses: Optional[list[str]] = None,
        include_markdown_description: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        List all fine-tuning recommendation tasks from the fine-tuning list.
        
        Args:
            archived: Include archived tasks (default: False)
            include_closed: Include closed tasks (default: True)
            order_by: Order tasks by field (e.g., "created", "updated", "priority")
            reverse: Reverse the order (default: False)
            subtasks: Include subtasks (default: False)
            statuses: Filter by status names (optional)
            include_markdown_description: Include markdown in descriptions (default: False)
        
        Returns:
            List of task dictionaries
        """
        logger.info("Listing fine-tuning recommendations")
        
        # Resolve which ClickUp list to use
        list_id = self._resolve_list_id(self.fine_tuning_list_id, purpose="fine_tuning")
        
        # Build query parameters
        params: Dict[str, Any] = {
            "archived": str(archived).lower(),
            "include_closed": str(include_closed).lower(),
            "subtasks": str(subtasks).lower(),
            "include_markdown_description": str(include_markdown_description).lower(),
        }
        
        if order_by:
            params["order_by"] = order_by
        if reverse:
            params["reverse"] = "true"
        if statuses:
            params["statuses[]"] = statuses
        
        try:
            response = self._http.get(f"/v2/list/{list_id}/task", params=params)
            tasks = response.get("tasks", [])
            
            logger.info(f"Found {len(tasks)} fine-tuning recommendation tasks")
            return tasks
        except IntegrationError as e:
            logger.error(f"Failed to list fine-tuning recommendations: {e}")
            raise

    def list_visibility_recommendations(
        self,
        archived: bool = False,
        include_closed: bool = True,
        order_by: Optional[str] = None,
        reverse: bool = False,
        subtasks: bool = False,
        statuses: Optional[list[str]] = None,
        include_markdown_description: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        List all visibility/engineering recommendation tasks from the engineering list.
        
        Args:
            archived: Include archived tasks (default: False)
            include_closed: Include closed tasks (default: True)
            order_by: Order tasks by field (e.g., "created", "updated", "priority")
            reverse: Reverse the order (default: False)
            subtasks: Include subtasks (default: False)
            statuses: Filter by status names (optional)
            include_markdown_description: Include markdown in descriptions (default: False)
        
        Returns:
            List of task dictionaries
        """
        logger.info("Listing visibility recommendations")
        
        # Resolve which ClickUp list to use
        list_id = self._resolve_list_id(self.engineering_list_id, purpose="engineering")
        
        # Build query parameters
        params: Dict[str, Any] = {
            "archived": str(archived).lower(),
            "include_closed": str(include_closed).lower(),
            "subtasks": str(subtasks).lower(),
            "include_markdown_description": str(include_markdown_description).lower(),
        }
        
        if order_by:
            params["order_by"] = order_by
        if reverse:
            params["reverse"] = "true"
        if statuses:
            params["statuses[]"] = statuses
        
        try:
            response = self._http.get(f"/v2/list/{list_id}/task", params=params)
            tasks = response.get("tasks", [])
            
            logger.info(f"Found {len(tasks)} visibility recommendation tasks")
            return tasks
        except IntegrationError as e:
            logger.error(f"Failed to list visibility recommendations: {e}")
            raise

    def add_comment_to_fine_tuning_recommendation(
        self,
        task_id: str,
        comment_text: str,
    ) -> Dict[str, Any]:
        """
        Add a comment to a fine-tuning recommendation task.
        
        Args:
            task_id: ClickUp task ID
            comment_text: Comment text/content
        
        Returns:
            Dictionary with comment information
        """
        logger.info(f"Adding comment to fine-tuning recommendation task: {task_id}")
        
        comment_data = {
            "comment_text": comment_text,
        }
        
        try:
            response = self._http.post(f"/v2/task/{task_id}/comment", json_data=comment_data)
            comment = response.get("comment", response)
            
            logger.info(f"Added comment to fine-tuning recommendation task: {task_id}")
            return comment
        except IntegrationError as e:
            logger.error(f"Failed to add comment to fine-tuning recommendation task {task_id}: {e}")
            raise

    def add_comment_to_visibility_recommendation(
        self,
        task_id: str,
        comment_text: str,
    ) -> Dict[str, Any]:
        """
        Add a comment to a visibility/engineering recommendation task.
        
        Args:
            task_id: ClickUp task ID
            comment_text: Comment text/content
        
        Returns:
            Dictionary with comment information
        """
        logger.info(f"Adding comment to visibility recommendation task: {task_id}")
        
        comment_data = {
            "comment_text": comment_text,
        }
        
        try:
            response = self._http.post(f"/v2/task/{task_id}/comment", json_data=comment_data)
            comment = response.get("comment", response)
            
            logger.info(f"Added comment to visibility recommendation task: {task_id}")
            return comment
        except IntegrationError as e:
            logger.error(f"Failed to add comment to visibility recommendation task {task_id}: {e}")
            raise

    def ping(self) -> bool:
        """
        Check if ClickUp API is reachable by testing access to the configured lists.
        
        Returns:
            True if API is reachable, False otherwise
        """
        try:
            # Try to get list info for fine-tuning list (this verifies both connectivity and list access)
            list_id = self._resolve_list_id(self.fine_tuning_list_id, purpose="fine_tuning")
            self._http.get(f"/v2/list/{list_id}")
            return True
        except IntegrationError:
            logger.exception("ClickUp ping failed")
            return False

