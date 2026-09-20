"""GitHub Issues ENG client tests."""

from __future__ import annotations

from src.core.config import EngConfig, GitHubConfig, SamiConfig
from src.integrations.eng.github.github_client import GitHubClient, _parse_repository
from src.orchestrator import tools_eng


class FakeHttp:
    def __init__(self):
        self.posts = []
        self.labels = {"enhancement"}

    def get(self, endpoint, params=None):
        if endpoint.endswith("/labels/fine-tuning"):
            from src.core.errors import IntegrationError
            raise IntegrationError("GitHub API error: Not Found")
        if "/issues/" in endpoint and endpoint.endswith("/comments"):
            return []
        if endpoint.endswith("/issues"):
            return [
                {
                    "number": 7,
                    "title": "Tune rule",
                    "html_url": "https://github.com/M507/HomeLab-DaC/issues/7",
                    "state": "open",
                    "body": "details",
                    "labels": [{"name": "fine-tuning"}, {"name": "enhancement"}],
                }
            ]
        if endpoint.endswith("/M507/HomeLab-DaC") or endpoint.endswith("HomeLab-DaC"):
            return {"full_name": "M507/HomeLab-DaC"}
        return {}

    def post(self, endpoint, json_data=None, params=None):
        self.posts.append({"endpoint": endpoint, "json": json_data})
        if endpoint.endswith("/labels"):
            self.labels.add(json_data["name"])
            return {"name": json_data["name"]}
        if endpoint.endswith("/comments"):
            return {
                "id": 99,
                "body": json_data["body"],
                "html_url": "https://github.com/M507/HomeLab-DaC/issues/7#issuecomment-99",
                "user": {"login": "M507"},
            }
        return {
            "number": 7,
            "title": json_data["title"],
            "html_url": "https://github.com/M507/HomeLab-DaC/issues/7",
            "state": "open",
            "body": json_data.get("body"),
        }


def test_parse_repository_from_issues_url():
    assert _parse_repository("https://github.com/M507/HomeLab-DaC/issues") == "M507/HomeLab-DaC"
    assert _parse_repository("M507/HomeLab-DaC") == "M507/HomeLab-DaC"


def test_github_issues_create_list_comment():
    http = FakeHttp()
    client = GitHubClient(http_client=http, repository="M507/HomeLab-DaC")  # type: ignore[arg-type]
    created = tools_eng.create_fine_tuning_recommendation(
        title="Tune me",
        description="because",
        client=client,
    )
    assert created["provider"] == "github"
    assert created["issue"]["number"] == 7
    assert any(p["endpoint"].endswith("/issues") for p in http.posts)

    listed = tools_eng.list_fine_tuning_recommendations(client=client)
    assert listed["count"] == 1
    assert listed["tasks"][0]["id"] == "7"

    commented = tools_eng.add_comment_to_fine_tuning_recommendation(
        task_id="7",
        comment_text="more context",
        client=client,
    )
    assert commented["success"] is True
    assert commented["provider"] == "github"


def test_from_config_uses_repository():
    config = SamiConfig(
        eng=EngConfig(
            provider="github",
            github=GitHubConfig(
                api_token="ghp_test",
                repository="https://github.com/M507/HomeLab-DaC/issues",
            ),
        )
    )
    client = GitHubClient.from_config(config)
    assert client.repository == "M507/HomeLab-DaC"
