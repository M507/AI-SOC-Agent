import asyncio

from src.ai_controller.approval_queue.catalog import ACTION_CATALOG, get_action_spec
from src.ai_controller.approval_queue.clients import ClientBundle
from src.ai_controller.approval_queue.models import RequestStatus
from src.ai_controller.approval_queue.service import ApprovalQueue


class _FakeSIEM:
    def __init__(self):
        self.closed = []
        self.verdicts = []
        self.tags = []
        self.cases = []
        self.isolated = []
        self.released = []
        self.alerts = {
            "alert-9": {
                "id": "alert-9",
                "title": "Suspicious DNS Query",
                "severity": "medium",
                "status": "open",
                "verdict": "in-progress",
                "description": "Host queried a known scanner domain.",
                "created_at": "2026-09-20T12:00:00Z",
                "related_entities": ["host:workstation-1", "user:alice", "ip:1.2.3.4"],
                "events": [
                    {
                        "id": "evt-1",
                        "timestamp": "2026-09-20T12:00:00Z",
                        "host": "workstation-1",
                        "message": "dns query evil.example",
                    }
                ],
                "comments": [{"author": "ai", "comment": "Looks like scanner noise", "timestamp": "2026-09-20T12:01:00Z"}],
            }
        }

    def get_security_alert_by_id(self, alert_id, include_detections=True):
        alert = self.alerts.get(alert_id)
        if not alert:
            raise KeyError(alert_id)
        return dict(alert)

    def close_alert(self, alert_id, reason=None, comment=None):
        self.closed.append((alert_id, reason, comment))
        return {"alert_id": alert_id, "status": "closed", "reason": reason, "comment": comment, "alert": {}}

    def update_alert_verdict(self, alert_id, verdict, comment=None):
        self.verdicts.append((alert_id, verdict, comment))
        return {"alert_id": alert_id, "verdict": verdict}

    def tag_alert(self, alert_id, tag):
        self.tags.append((alert_id, tag))
        return {"success": True, "alert_id": alert_id, "tag": tag}

    def create_security_case(self, title=None, description=None, severity="high", tags=None, alert_id=None, identity=None):
        case = {
            "case_id": "elastic-case-1",
            "title": title,
            "description": description,
            "severity": severity,
            "tags": tags or [],
            "alert_id": alert_id,
            "identity": identity,
            "alert_attached": True,
            "status": "open",
            "case": {"id": "elastic-case-1"},
        }
        self.cases.append(case)
        return case

    def isolate_endpoint(self, endpoint_id, comment=None, hostname=None):
        self.isolated.append((endpoint_id, comment, hostname))
        return {
            "success": True,
            "provider": "elastic",
            "endpoint_id": endpoint_id,
            "hostname": hostname,
            "action_id": "act-1",
            "status": "pending",
            "comment": comment,
        }

    def release_endpoint_isolation(self, endpoint_id, comment=None, hostname=None):
        self.released.append((endpoint_id, comment, hostname))
        return {
            "success": True,
            "provider": "elastic",
            "endpoint_id": endpoint_id,
            "action_id": "act-2",
            "status": "pending",
        }


def test_catalog_covers_soc_actions():
    types = {spec.action_type for spec in ACTION_CATALOG}
    assert "close_alert" in types
    assert "identity_verify" in types
    assert "isolate_endpoint" in types
    assert "fine_tune" in types
    assert "update_verdict" not in types
    assert get_action_spec("close_alert").execution == "ready"
    assert get_action_spec("isolate_endpoint").execution == "ready"
    assert get_action_spec("isolate_endpoint").integration == "siem"
    assert get_action_spec("fine_tune").execution == "informational"
    assert get_action_spec("visibility").execution == "informational"


def test_close_alert_executes_on_originating_cluster(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    bundle = lambda cluster_id=None: ClientBundle(cluster_id=cluster_id or "lab", siem=siem)
    monkeypatch.setattr("src.ai_controller.approval_queue.service.resolve_clients", bundle)
    monkeypatch.setattr("src.ai_controller.approval_queue.enrichment.resolve_clients", bundle)
    created = queue.create(
        "close_alert",
        "Close noisy DNS alert",
        "Matches known scanner, no internal hosts involved.",
        payload={"alert_id": "alert-9", "reason": "false_positive", "comment": "scanner"},
        cluster_id="lab",
    )
    assert created.payload.get("alert", {}).get("title") == "Suspicious DNS Query"
    assert created.payload.get("hostname") == "workstation-1"
    assert "scanner" in (created.rationale or created.summary)
    done = queue.approve(created.id)
    assert done.status is RequestStatus.EXECUTED
    assert done.cluster_id == "lab"
    assert siem.closed == [("alert-9", "false_positive", "scanner")]


def test_close_alert_enriches_sparse_mcp_payload(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    bundle = lambda cluster_id=None: ClientBundle(cluster_id="lab", siem=siem)
    monkeypatch.setattr("src.ai_controller.approval_queue.service.resolve_clients", bundle)
    monkeypatch.setattr("src.ai_controller.approval_queue.enrichment.resolve_clients", bundle)
    created = queue.create_from_mcp_tool(
        "close_alert",
        {"alert_id": "alert-9"},
        cluster_id="lab",
    )
    assert created.payload["alert"]["title"] == "Suspicious DNS Query"
    assert "Suspicious DNS Query" in created.title
    assert "workstation-1" in created.summary
    assert "dns query evil.example" in created.rationale
    assert created.payload.get("username") == "alice"


def test_deny_does_not_execute(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.resolve_clients",
        lambda cluster_id=None: ClientBundle(siem=siem),
    )
    created = queue.create(
        "close_alert",
        "Close it",
        "maybe",
        payload={"alert_id": "alert-1"},
    )
    denied = queue.deny(created.id, comment="still investigating")
    assert denied.status is RequestStatus.DENIED
    assert siem.closed == []


def test_identity_yes_closes_as_benign(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.resolve_clients",
        lambda cluster_id=None: ClientBundle(cluster_id="lab", siem=siem),
    )
    created = queue.create(
        "identity_verify",
        "VPN login from 8.8.8.8",
        "New ASN for this user.",
        payload={"username": "sami", "alert_id": "alert-22", "source_ip": "8.8.8.8", "activity": "VPN login"},
        cluster_id="lab",
    )
    assert created.question
    assert "yes" in created.follow_ups
    done = queue.answer(created.id, "yes")
    assert done.decision.answer == "yes"
    assert siem.closed[0][0] == "alert-22"
    assert siem.closed[0][1] == "benign_true_positive"
    child = queue.get(done.child_request_ids[0])
    assert child.action_type == "close_alert"
    assert child.status is RequestStatus.EXECUTED


def test_identity_no_opens_elastic_case_not_iris(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()

    class _IrisMustNotRun:
        def create_case(self, *args, **kwargs):
            raise AssertionError("Is this you? must not open an IRIS/TheHive case")

    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.resolve_clients",
        lambda cluster_id=None: ClientBundle(cluster_id="lab", siem=siem, case=_IrisMustNotRun()),
    )
    created = queue.create(
        "identity_verify",
        "VPN login from 8.8.8.8",
        "New ASN for this user.",
        payload={
            "username": "sami",
            "alert_id": "alert-22",
            "source_ip": "8.8.8.8",
            "hostname": "vpn-gw",
            "activity": "VPN login",
            "timestamp": "2026-08-18T12:00:00Z",
        },
        cluster_id="lab",
    )
    done = queue.answer(created.id, "no")
    assert done.decision.answer == "no"
    child = queue.get(done.child_request_ids[0])
    assert child.action_type == "escalate"
    assert child.status is RequestStatus.EXECUTED
    assert child.payload["username"] == "sami"
    assert child.payload["source_ip"] == "8.8.8.8"
    assert siem.tags == [("alert-22", "TP")]
    assert siem.verdicts[0][:2] == ("alert-22", "true_positive")
    assert len(siem.cases) == 1
    opened = siem.cases[0]
    assert opened["alert_id"] == "alert-22"
    assert opened["identity"]["username"] == "sami"
    assert opened["identity"]["source_ip"] == "8.8.8.8"
    assert "not them" in (opened["description"] or "").lower() or "not the user" in (
        opened["description"] or ""
    ).lower() or "New ASN" in (opened["description"] or "")


def test_isolate_runs_via_elastic_cluster(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.resolve_clients",
        lambda cluster_id=None: ClientBundle(cluster_id=cluster_id or "lab", siem=siem),
    )
    created = queue.create(
        "isolate_endpoint",
        "Isolate workstation",
        "Ransomware notes on disk.",
        payload={"endpoint_id": "host-1", "hostname": "ws-1", "reason": "ransomware"},
        cluster_id="lab",
    )
    done = queue.approve(created.id)
    assert done.status is RequestStatus.EXECUTED
    assert siem.isolated == [("host-1", "ransomware", "ws-1")]


def test_isolate_waits_when_cluster_missing(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.resolve_clients",
        lambda cluster_id=None: ClientBundle(),
    )
    created = queue.create(
        "isolate_endpoint",
        "Isolate workstation",
        "Ransomware notes on disk.",
        payload={"endpoint_id": "host-1", "hostname": "ws-1"},
    )
    done = queue.approve(created.id)
    assert done.status is RequestStatus.AWAITING_INTEGRATION
    assert done.payload["endpoint_id"] == "host-1"


def test_mcp_close_alert_is_queued(tmp_path, monkeypatch):
    from src.ai_controller.approval_queue import service as queue_service
    from src.mcp.mcp_server import SamiGPTMCPServer

    queue_service.init_queue(str(tmp_path))
    monkeypatch.setattr(
        "src.core.elastic_clusters.skill_vector_for_cluster",
        lambda cluster_id=None: "MSV:1/IRIS:Y/TH:Y/SIEM:Y/EDR:Y/CTI:Y/KB:Y/ENG:Y/RB:Y/AG:Y/RU:Y",
    )
    server = SamiGPTMCPServer(siem_client=object())
    assert "create_approval_request" in server.tools

    async def _call():
        return await server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "close_alert",
                    "arguments": {"alert_id": "a-1", "reason": "false_positive", "comment": "fp"},
                },
            }
        )

    response = asyncio.run(_call())
    body = response["result"]["content"][0]["text"]
    assert "queued" in body
    assert queue_service.get_queue().counts()["pending"] == 1
    filed = queue_service.get_queue().list(status="pending")[0]
    assert filed.action_type == "close_alert"
    assert filed.payload["alert_id"] == "a-1"


def test_mcp_update_alert_verdict_runs_without_approval(tmp_path, monkeypatch):
    from src.ai_controller.approval_queue import service as queue_service
    from src.mcp.mcp_server import SamiGPTMCPServer

    queue_service.init_queue(str(tmp_path))
    monkeypatch.setattr(
        "src.core.elastic_clusters.skill_vector_for_cluster",
        lambda cluster_id=None: "MSV:1/IRIS:Y/TH:Y/SIEM:Y/EDR:Y/CTI:Y/KB:Y/ENG:Y/RB:Y/AG:Y/RU:Y",
    )
    siem = _FakeSIEM()
    server = SamiGPTMCPServer(siem_client=siem)

    async def _call():
        return await server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "update_alert_verdict",
                    "arguments": {
                        "alert_id": "a-2",
                        "verdict": "in-progress",
                        "comment": "AI working assessment",
                    },
                },
            }
        )

    response = asyncio.run(_call())
    body = response["result"]["content"][0]["text"]
    assert "queued" not in body
    assert siem.verdicts == [("a-2", "in-progress", "AI working assessment")]
    assert queue_service.get_queue().counts()["pending"] == 0


def test_gated_mcp_tool_descriptions_tell_the_model_they_queue():
    from src.mcp.mcp_server import SamiGPTMCPServer

    server = SamiGPTMCPServer(
        siem_client=object(),
        edr_client=object(),
        eng_client=object(),
    )
    gated = [
        "close_alert",
        "isolate_endpoint",
        "release_endpoint_isolation",
        "kill_process_on_endpoint",
        "collect_forensic_artifacts",
    ]
    for name in gated:
        desc = server.tools[name]["description"]
        assert "Requests view" in desc, name
        assert "does not run until" in desc, name
    for name in ("create_fine_tuning_recommendation", "create_visibility_recommendation"):
        desc = server.tools[name]["description"]
        assert "Requests view" in desc, name
        assert "informational" in desc.lower(), name
        assert "does not run until" not in desc, name
    assert "search_lab_detection_rules" in server.tools
    assert "get_lab_detection_rule" in server.tools
    verdict = server.tools["update_alert_verdict"]["description"]
    assert "does not wait for analyst approval" in verdict
    assert "queued for the Requests view" in verdict
    runbook = server.tools["execute_runbook"]["description"]
    assert "Requests-view" in runbook
    assert "informational only" in runbook


class _FakeGitHub:
    repository = "org/HomeLab-DaC"

    def __init__(self, issues=None):
        self.issues = issues or {}
        self.comments = []
        self.closed = []

    def get_issue(self, number):
        return dict(self.issues[str(number)])

    def close_issue(self, number, comment=None):
        if comment:
            self.comments.append((str(number), comment))
        issue = self.issues[str(number)]
        issue["state"] = "closed"
        self.closed.append(str(number))
        return dict(issue)


def _engineering_payload(number=42, state="open"):
    return {
        "provider": "github",
        "repository": "org/HomeLab-DaC",
        "issue": {
            "number": number,
            "url": f"https://github.com/org/HomeLab-DaC/issues/{number}",
            "state": state,
        },
    }


def test_queue_tabs_filter_soc_and_detection(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.resolve_clients",
        lambda cluster_id=None: ClientBundle(),
    )
    close = queue.create(
        "close_alert",
        "Close noisy DNS",
        "scanner",
        payload={"alert_id": "alert-9", "reason": "false_positive"},
    )
    note = queue.create(
        "fine_tune",
        "Tune encoded PS",
        "admin script",
        payload={"title": "Tune encoded PS", "description": "Exclude signed admin tool"},
    )
    queue.attach_engineering(note.id, _engineering_payload())

    soc = queue.list(status="open", queue="soc", sync_github=False)
    detection = queue.list(status="open", queue="detection", sync_github=False)
    engineering = queue.list(status="open", queue="engineering", sync_github=False)
    assert {item.id for item in soc} == {close.id}
    assert {item.id for item in detection} == {note.id}
    assert {item.id for item in engineering} == {note.id}
    counts = queue.counts()
    assert counts["actionable"] == 1
    assert counts["detection_open"] == 1
    assert counts["engineering_open"] == 1
    tabs = queue.tab_counts("soc")
    assert tabs["open"] == 1


def test_github_closed_sync_archives_open_note(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    github = _FakeGitHub(
        {
            "42": {
                "number": 42,
                "state": "closed",
                "html_url": "https://github.com/org/HomeLab-DaC/issues/42",
            }
        }
    )
    monkeypatch.setattr(ApprovalQueue, "_github_client_for", lambda self, request: github)
    note = queue.create(
        "visibility",
        "Missing DNS telemetry",
        "no coverage",
        payload={"title": "Missing DNS telemetry", "description": "Need DNS logs"},
    )
    queue.attach_engineering(note.id, _engineering_payload())
    archived = queue.list(status="open", queue="detection")
    assert archived == []
    stored = queue.get(note.id)
    assert stored.status is RequestStatus.ACKNOWLEDGED
    assert stored.archived is True
    assert stored.decision.comment == "Closed on GitHub #42"


def test_ignore_closes_github_issue_and_archives(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    github = _FakeGitHub(
        {
            "42": {
                "number": 42,
                "state": "open",
                "html_url": "https://github.com/org/HomeLab-DaC/issues/42",
            }
        }
    )
    monkeypatch.setattr(ApprovalQueue, "_github_client_for", lambda self, request: github)
    note = queue.create(
        "fine_tune",
        "Tune encoded PS",
        "admin script",
        payload={"title": "Tune encoded PS", "description": "Exclude signed admin tool"},
    )
    queue.attach_engineering(note.id, _engineering_payload())
    ignored = queue.ignore(note.id, comment="noise for this lab")
    assert ignored.status is RequestStatus.ACKNOWLEDGED
    assert ignored.archived is True
    assert ignored.decision.action == "ignore"
    assert github.closed == ["42"]
    assert github.comments
    assert "Manager decided to ignore this professionally." in github.comments[0][1]
    assert "noise for this lab" in github.comments[0][1]
    assert ignored.payload["engineering"]["issue"]["state"] == "closed"
    assert queue.list(status="open", queue="engineering", sync_github=False) == []
    archived = queue.list(status="archived", queue="engineering", sync_github=False)
    assert {item.id for item in archived} == {note.id}


def test_ignore_archives_when_github_close_fails(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))

    class _BrokenGitHub(_FakeGitHub):
        def close_issue(self, number, comment=None):
            raise RuntimeError("GitHub 502")

    github = _BrokenGitHub(
        {
            "42": {
                "number": 42,
                "state": "open",
                "html_url": "https://github.com/org/HomeLab-DaC/issues/42",
            }
        }
    )
    monkeypatch.setattr(ApprovalQueue, "_github_client_for", lambda self, request: github)
    note = queue.create(
        "fine_tune",
        "Tune encoded PS",
        "admin script",
        payload={"title": "Tune encoded PS", "description": "Exclude signed admin tool"},
    )
    queue.attach_engineering(note.id, _engineering_payload())
    ignored = queue.ignore(note.id)
    assert ignored.status is RequestStatus.ACKNOWLEDGED
    assert ignored.archived is True
    assert ignored.execution_result["github"]["success"] is False
    assert "GitHub 502" in (ignored.error or "")


def test_approve_close_alert_uses_kibana_detection_engine(tmp_path, monkeypatch):
    """Requests-tab approve must close via Kibana signals/status, not verdict-only."""
    from types import SimpleNamespace

    from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient

    calls = []

    def fake_request(**kwargs):
        url = kwargs["url"]
        body = kwargs.get("json")
        calls.append({"url": url, "json": body, "method": kwargs["method"]})
        if url.endswith("/api/detection_engine/signals/status"):
            return SimpleNamespace(
                status_code=200,
                text="",
                reason="OK",
                json=lambda: {"updated": 1, "total": 1, "failures": []},
            )
        raise AssertionError(f"unexpected {kwargs['method']} {url}")

    monkeypatch.setattr("requests.request", fake_request)
    siem = ElasticSIEMClient.from_settings(
        base_url="https://es.example:9200",
        kibana_url="https://kibana.example:5601",
        api_key="test-key",
        verify_ssl=False,
    )
    monkeypatch.setattr(
        siem,
        "get_security_alert_by_id",
        lambda alert_id, include_detections=True: {
            "id": alert_id,
            "title": "Suspicious DNS Query",
            "status": "open",
            "severity": "medium",
            "related_entities": ["host:workstation-1"],
            "events": [],
            "comments": [],
        },
    )
    monkeypatch.setattr(
        siem,
        "update_alert_verdict",
        lambda alert_id, verdict, comment=None: {
            "success": True,
            "alert_id": alert_id,
            "verdict": verdict,
            "comment": comment,
            "alert": {"id": alert_id, "status": "closed", "verdict": verdict},
        },
    )
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.resolve_clients",
        lambda cluster_id=None: ClientBundle(cluster_id=cluster_id or "lab", siem=siem),
    )
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.enrichment.resolve_clients",
        lambda cluster_id=None: ClientBundle(cluster_id=cluster_id or "lab", siem=siem),
    )

    queue = ApprovalQueue(str(tmp_path))
    created = queue.create(
        "close_alert",
        "Close scanner noise",
        "Matches known scanner.",
        payload={"alert_id": "alert-9", "reason": "false_positive", "comment": "scanner"},
        cluster_id="lab",
    )
    done = queue.approve(created.id)
    assert done.status is RequestStatus.EXECUTED
    assert done.execution_result["success"] is True
    assert done.execution_result["status"] == "closed"
    status_calls = [c for c in calls if str(c["url"]).endswith("/api/detection_engine/signals/status")]
    assert len(status_calls) == 1
    assert status_calls[0]["json"]["signal_ids"] == ["alert-9"]
    assert status_calls[0]["json"]["status"] == "closed"
    assert status_calls[0]["json"]["reason"] == "false_positive"
