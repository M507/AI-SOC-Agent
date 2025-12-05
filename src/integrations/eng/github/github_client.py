"""
GitHub client for creating project items and recommendations.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from ....core.config import SamiConfig
from ....core.errors import IntegrationError
from ....core.logging import get_logger
from .github_http import GitHubHttpClient


logger = get_logger("sami.integrations.github.client")


class GitHubClient:
    """
    Client for interacting with GitHub Projects API to create project items and recommendations.
    """

    def __init__(
        self,
        http_client: GitHubHttpClient,
        fine_tuning_project_id: str,
        engineering_project_id: str,
    ) -> None:
        """
        Initialize GitHub client.
        
        Args:
            http_client: HTTP client for GitHub API
            fine_tuning_project_id: GitHub project ID for fine-tuning recommendations
            engineering_project_id: GitHub project ID for engineering/visibility recommendations
        """
        self._http = http_client
        self.fine_tuning_project_id = fine_tuning_project_id
        self.engineering_project_id = engineering_project_id

    @classmethod
    def from_config(cls, config: SamiConfig) -> "GitHubClient":
        """
        Factory to construct a client from ``SamiConfig``.
        
        Args:
            config: SamiConfig instance with GitHub configuration
        
        Returns:
            GitHubClient instance
        
        Raises:
            IntegrationError: If GitHub configuration is not set
        """
        if not config.eng or not config.eng.github:
            raise IntegrationError("GitHub configuration is not set in SamiConfig")

        github_config = config.eng.github
        http_client = GitHubHttpClient(
            api_token=github_config.api_token,
            timeout_seconds=github_config.timeout_seconds,
            verify_ssl=github_config.verify_ssl,
        )
        
        return cls(
            http_client=http_client,
            fine_tuning_project_id=github_config.fine_tuning_project_id,
            engineering_project_id=github_config.engineering_project_id,
        )

    def create_fine_tuning_recommendation(
        self,
        title: str,
        description: str,
        content_id: Optional[str] = None,
        content_type: str = "DraftIssue",
    ) -> Dict[str, Any]:
        """
        Create a fine-tuning recommendation project item in GitHub.
        
        Args:
            title: Item title
            description: Item description/body
            content_id: Optional content ID (for linking to issues/PRs)
            content_type: Content type (DraftIssue, Issue, PullRequest). Default: DraftIssue
        
        Returns:
            Dictionary with project item information
        """
        logger.info(f"Creating fine-tuning recommendation: {title}")
        
        # GitHub Projects API v1 (REST) - Note: v1 is deprecated but still functional
        # We use REST API v1 for simplicity: POST /projects/columns/{column_id}/cards
        
        # Get the project columns
        columns = self._http.get(f"/projects/{self.fine_tuning_project_id}/columns")
        
        if not columns:
            raise IntegrationError("No columns found in fine-tuning project")
        
        # Use the first column
        column_id = columns[0].get("id")
        
        # Create a card/item in the column
        # For draft issues, we use note parameter
        card_data = {
            "note": f"## {title}\n\n{description}",
        }
        
        card = self._http.post(f"/projects/columns/{column_id}/cards", json_data=card_data)
        
        logger.info(f"Created fine-tuning recommendation project item: {card.get('id')}")
        return card

    def create_visibility_recommendation(
        self,
        title: str,
        description: str,
        content_id: Optional[str] = None,
        content_type: str = "DraftIssue",
    ) -> Dict[str, Any]:
        """
        Create a visibility/engineering recommendation project item in GitHub.
        
        Args:
            title: Item title
            description: Item description/body
            content_id: Optional content ID (for linking to issues/PRs)
            content_type: Content type (DraftIssue, Issue, PullRequest). Default: DraftIssue
        
        Returns:
            Dictionary with project item information
        """
        logger.info(f"Creating visibility recommendation: {title}")
        
        # Get the project columns
        columns = self._http.get(f"/projects/{self.engineering_project_id}/columns")
        
        if not columns:
            raise IntegrationError("No columns found in engineering project")
        
        # Use the first column
        column_id = columns[0].get("id")
        
        # Create a card/item in the column
        card_data = {
            "note": f"## {title}\n\n{description}",
        }
        
        card = self._http.post(f"/projects/columns/{column_id}/cards", json_data=card_data)
        
        logger.info(f"Created visibility recommendation project item: {card.get('id')}")
        return card

    def ping(self) -> bool:
        """
        Check if GitHub API is reachable.
        
        Returns:
            True if API is reachable, False otherwise
        """
        try:
            # Try to get authenticated user
            self._http.get("/user")
            return True
        except IntegrationError:
            logger.exception("GitHub ping failed")
            return False

