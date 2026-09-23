"""
GitHub Issues client for engineering recommendations.

Creates, lists, and comments on issues in a configured repository
(e.g. M507/HomeLab-DaC), separated by labels for fine-tuning vs visibility.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ....core.config import SamiConfig
from ....core.errors import IntegrationError
from ....core.logging import get_logger
from .github_http import GitHubHttpClient

logger = get_logger("sami.integrations.github.client")


def _parse_repository(raw: str) -> str:
    value = (raw or "").strip().rstrip("/")
    if "github.com/" in value.lower():
        parts = value.split("github.com/", 1)[1].strip("/").split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
    if value.count("/") == 1:
        return value
    raise IntegrationError(
        f"GitHub repository must be 'owner/repo' or a github.com URL, got {raw!r}"
    )


class GitHubClient:
    """Engineering recommendations backed by GitHub Issues."""

    def __init__(
        self,
        http_client: GitHubHttpClient,
        repository: str,
        fine_tuning_label: str = "fine-tuning",
        visibility_label: str = "visibility",
        runbook_label: str = "runbook",
    ) -> None:
        self._http = http_client
        self.repository = _parse_repository(repository)
        self.fine_tuning_label = fine_tuning_label or "fine-tuning"
        self.visibility_label = visibility_label or "visibility"
        self.runbook_label = runbook_label or "runbook"
        self._owner, self._repo = self.repository.split("/", 1)

    @classmethod
    def from_config(cls, config: SamiConfig) -> "GitHubClient":
        if not config.eng or not config.eng.github:
            raise IntegrationError("GitHub configuration is not set in SamiConfig")

        github_config = config.eng.github
        repository = (
            getattr(github_config, "repository", None)
            or github_config.fine_tuning_project_id
            or github_config.engineering_project_id
            or ""
        )
        if not repository or repository.startswith("your-"):
            raise IntegrationError(
                "GitHub eng.github.repository is required (owner/repo), "
                "e.g. M507/HomeLab-DaC"
            )

        http_client = GitHubHttpClient(
            api_token=github_config.api_token,
            timeout_seconds=github_config.timeout_seconds,
            verify_ssl=github_config.verify_ssl,
        )
        return cls(
            http_client=http_client,
            repository=repository,
            fine_tuning_label=getattr(github_config, "fine_tuning_label", None) or "fine-tuning",
            visibility_label=getattr(github_config, "visibility_label", None) or "visibility",
            runbook_label=getattr(github_config, "runbook_label", None) or "runbook",
        )

    def ping(self) -> bool:
        try:
            self._http.get(f"/repos/{self.repository}")
            return True
        except IntegrationError:
            logger.exception("GitHub ping failed")
            return False

    def create_fine_tuning_recommendation(
        self,
        title: str,
        description: str,
        **_: Any,
    ) -> Dict[str, Any]:
        return self._create_issue(
            title=title,
            body=description,
            labels=[self.fine_tuning_label, "enhancement"],
        )

    def create_visibility_recommendation(
        self,
        title: str,
        description: str,
        **_: Any,
    ) -> Dict[str, Any]:
        return self._create_issue(
            title=title,
            body=description,
            labels=[self.visibility_label, "enhancement"],
        )

    def create_runbook_recommendation(
        self,
        title: str,
        description: str,
        **_: Any,
    ) -> Dict[str, Any]:
        return self._create_issue(
            title=title,
            body=description,
            labels=[self.runbook_label, "enhancement"],
        )

    def list_fine_tuning_recommendations(
        self,
        include_closed: bool = True,
        **_: Any,
    ) -> List[Dict[str, Any]]:
        return self._list_issues(self.fine_tuning_label, include_closed=include_closed)

    def list_visibility_recommendations(
        self,
        include_closed: bool = True,
        **_: Any,
    ) -> List[Dict[str, Any]]:
        return self._list_issues(self.visibility_label, include_closed=include_closed)

    def add_comment_to_fine_tuning_recommendation(
        self,
        task_id: str,
        comment_text: str,
    ) -> Dict[str, Any]:
        return self._add_comment(task_id, comment_text)

    def add_comment_to_visibility_recommendation(
        self,
        task_id: str,
        comment_text: str,
    ) -> Dict[str, Any]:
        return self._add_comment(task_id, comment_text)

    def _ensure_label(self, name: str) -> None:
        try:
            self._http.get(f"/repos/{self.repository}/labels/{name}")
        except IntegrationError:
            try:
                self._http.post(
                    f"/repos/{self.repository}/labels",
                    json_data={
                        "name": name,
                        "color": "0E8A16" if name == self.fine_tuning_label else "1D76DB",
                        "description": f"SamiGPT {name} recommendations",
                    },
                )
                logger.info("Created GitHub label %s on %s", name, self.repository)
            except IntegrationError as e:
                logger.warning("Could not create label %s: %s", name, e)

    def _create_issue(
        self,
        *,
        title: str,
        body: str,
        labels: List[str],
    ) -> Dict[str, Any]:
        for label in labels:
            if label not in {"enhancement", "bug", "documentation", "question"}:
                self._ensure_label(label)
        payload = {
            "title": title,
            "body": body or "",
            "labels": labels,
        }
        issue = self._http.post(f"/repos/{self.repository}/issues", json_data=payload)
        if not isinstance(issue, dict):
            raise IntegrationError("GitHub create issue returned unexpected payload")
        logger.info(
            "Created GitHub issue #%s on %s: %s",
            issue.get("number"),
            self.repository,
            issue.get("html_url"),
        )
        return issue

    def _list_issues(self, label: str, *, include_closed: bool) -> List[Dict[str, Any]]:
        """
        List issues for a recommendation label.

        Filters client-side so newly labeled issues are visible immediately
        (GitHub's ``labels=`` query can lag for a short time after create).
        """
        params = {
            "state": "all" if include_closed else "open",
            "per_page": 100,
            "sort": "created",
            "direction": "desc",
        }
        results = self._http.get(f"/repos/{self.repository}/issues", params=params)
        if isinstance(results, dict) and "message" in results:
            raise IntegrationError(results.get("message") or "GitHub list issues failed")
        if not isinstance(results, list):
            return []

        matched: List[Dict[str, Any]] = []
        for item in results:
            if not isinstance(item, dict) or "pull_request" in item:
                continue
            names = {
                str(label_obj.get("name") or "")
                for label_obj in (item.get("labels") or [])
                if isinstance(label_obj, dict)
            }
            if label in names:
                matched.append(item)
        return matched

    def get_issue(self, issue_number: str) -> Dict[str, Any]:
        """Fetch one issue by number."""
        number = str(issue_number).lstrip("#")
        issue = self._http.get(f"/repos/{self.repository}/issues/{number}")
        if not isinstance(issue, dict) or not issue.get("number"):
            raise IntegrationError(f"GitHub issue #{number} not found")
        return issue

    def close_issue(self, issue_number: str, comment: Optional[str] = None) -> Dict[str, Any]:
        """Comment (optional) and close an issue."""
        number = str(issue_number).lstrip("#")
        if comment and str(comment).strip():
            self._add_comment(number, str(comment).strip())
        issue = self._http.patch(
            f"/repos/{self.repository}/issues/{number}",
            json_data={"state": "closed"},
        )
        if not isinstance(issue, dict) or not issue.get("number"):
            raise IntegrationError(f"GitHub close issue #{number} returned unexpected payload")
        return issue

    def list_issue_comments(self, issue_number: str) -> List[Dict[str, Any]]:
        """Fetch comments on one issue."""
        number = str(issue_number).lstrip("#")
        comments = self._http.get(f"/repos/{self.repository}/issues/{number}/comments")
        if isinstance(comments, dict) and "message" in comments:
            raise IntegrationError(comments.get("message") or "GitHub list comments failed")
        if not isinstance(comments, list):
            return []
        return [item for item in comments if isinstance(item, dict)]

    def _add_comment(self, issue_number: str, comment_text: str) -> Dict[str, Any]:
        number = str(issue_number).lstrip("#")
        comment = self._http.post(
            f"/repos/{self.repository}/issues/{number}/comments",
            json_data={"body": comment_text},
        )
        if not isinstance(comment, dict):
            raise IntegrationError("GitHub create comment returned unexpected payload")
        return comment
