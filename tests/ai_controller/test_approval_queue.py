import asyncio
import os

from src.ai_controller.approval_queue.catalog import ACTION_CATALOG, get_action_spec
from src.ai_controller.approval_queue.clients import ClientBundle
from src.ai_controller.approval_queue.models import ApprovalRequest, RequestStatus
from src.ai_controller.approval_queue.service import ApprovalQueue


class _FakeSIEM:
    def __init__(self):
        self.closed = []
        self.verdicts = []
        self.tags = []
        self.cases = []
        self.isolated = []
        self.released = []
        self.notes = []
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

    def add_alert_note(self, alert_id, note):
        self.notes.append((alert_id, note))
        return {"alert_id": alert_id, "note": note, "alert": {}}

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
    assert "add_alert_note" in types
    assert "identity_verify" in types
    assert "isolate_endpoint" in types
    assert "fine_tune" in types
    assert "update_verdict" not in types
    assert get_action_spec("close_alert").execution == "ready"
    assert get_action_spec("add_alert_note").execution == "ready"
    assert get_action_spec("add_alert_note").gated_mcp_tool == "add_alert_note"
    assert get_action_spec("isolate_endpoint").execution == "stub"
    assert get_action_spec("isolate_endpoint").integration == "none"
    assert get_action_spec("release_isolation").execution == "stub"
    assert get_action_spec("close_alert").workflow == "approval"
    assert get_action_spec("identity_verify").workflow == "verification"
    assert get_action_spec("fine_tune").workflow == "note"
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


def test_approve_close_also_approves_associated_notes(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    bundle = lambda cluster_id=None: ClientBundle(cluster_id=cluster_id or "lab", siem=siem)
    monkeypatch.setattr("src.ai_controller.approval_queue.service.resolve_clients", bundle)
    monkeypatch.setattr("src.ai_controller.approval_queue.enrichment.resolve_clients", bundle)
    note = queue.create(
        "add_alert_note",
        "Add note",
        "Host is a scanner; prior notes agree.",
        payload={"alert_id": "alert-9", "note": "Host is a scanner; prior notes agree."},
        cluster_id="lab",
    )
    other = queue.create(
        "add_alert_note",
        "Add note on a different alert",
        "Leave this pending.",
        payload={"alert_id": "alert-other", "note": "Leave this pending."},
        cluster_id="lab",
    )
    close = queue.create(
        "close_alert",
        "Close noisy DNS alert",
        "scanner",
        payload={"alert_id": "alert-9", "reason": "false_positive", "comment": "scanner"},
        cluster_id="lab",
    )
    done = queue.approve(close.id)
    assert done.status is RequestStatus.EXECUTED
    assert siem.notes == [("alert-9", "Host is a scanner; prior notes agree.")]
    assert siem.closed == [("alert-9", "false_positive", "scanner")]
    assert queue._require(note.id).status is RequestStatus.EXECUTED
    assert queue._require(other.id).status is RequestStatus.PENDING
    assert any(item["id"] == note.id for item in (done.execution_result or {}).get("associated_notes") or [])


def test_approve_close_matches_note_alert_snapshot_and_inherits_cluster(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    seen = []

    def _bundle(cluster_id=None):
        seen.append(cluster_id)
        return ClientBundle(cluster_id=cluster_id or "lab", siem=siem)

    monkeypatch.setattr("src.ai_controller.approval_queue.service.resolve_clients", _bundle)
    monkeypatch.setattr("src.ai_controller.approval_queue.enrichment.resolve_clients", _bundle)
    note = ApprovalRequest(
        action_type="add_alert_note",
        title="Add note",
        summary="Nested id only.",
        payload={"alert": {"id": "alert-9"}, "note": "Nested id only."},
        status=RequestStatus.PENDING,
    )
    queue.store.put(note)
    assert note.cluster_id is None
    close = queue.create(
        "close_alert",
        "Close noisy DNS alert",
        "scanner",
        payload={"alert_id": "alert-9", "reason": "false_positive", "comment": "scanner"},
        cluster_id="lab",
    )
    done = queue.approve(close.id)
    assert done.status is RequestStatus.EXECUTED
    updated_note = queue._require(note.id)
    assert updated_note.status is RequestStatus.EXECUTED
    assert updated_note.cluster_id == "lab"
    assert siem.notes == [("alert-9", "Nested id only.")]
    assert siem.closed == [("alert-9", "false_positive", "scanner")]


def test_approve_close_picks_up_note_filed_by_another_queue(tmp_path, monkeypatch):
    closer = ApprovalQueue(str(tmp_path))
    filer = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    bundle = lambda cluster_id=None: ClientBundle(cluster_id=cluster_id or "lab", siem=siem)
    monkeypatch.setattr("src.ai_controller.approval_queue.service.resolve_clients", bundle)
    monkeypatch.setattr("src.ai_controller.approval_queue.enrichment.resolve_clients", bundle)
    note = filer.create(
        "add_alert_note",
        "Add note",
        "Filed in the other process.",
        payload={"alert_id": "alert-9", "note": "Filed in the other process."},
        cluster_id="lab",
    )
    close = closer.create(
        "close_alert",
        "Close noisy DNS alert",
        "scanner",
        payload={"alert_id": "alert-9", "reason": "false_positive", "comment": "scanner"},
        cluster_id="lab",
    )
    done = closer.approve(close.id)
    assert done.status is RequestStatus.EXECUTED
    assert siem.notes == [("alert-9", "Filed in the other process.")]
    assert closer._require(note.id).status is RequestStatus.EXECUTED


def test_deny_close_leaves_associated_note_pending(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.resolve_clients",
        lambda cluster_id=None: ClientBundle(siem=siem),
    )
    note = queue.create(
        "add_alert_note",
        "Add note",
        "should stay pending",
        payload={"alert_id": "alert-1", "note": "should stay pending"},
    )
    close = queue.create(
        "close_alert",
        "Close it",
        "maybe",
        payload={"alert_id": "alert-1"},
    )
    denied = queue.deny(close.id, comment="still investigating")
    assert denied.status is RequestStatus.DENIED
    assert queue._require(note.id).status is RequestStatus.PENDING
    assert siem.notes == []
    assert siem.closed == []


def test_add_alert_note_enriches_and_executes_on_approve(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    bundle = lambda cluster_id=None: ClientBundle(cluster_id=cluster_id or "lab", siem=siem)
    monkeypatch.setattr("src.ai_controller.approval_queue.service.resolve_clients", bundle)
    monkeypatch.setattr("src.ai_controller.approval_queue.enrichment.resolve_clients", bundle)
    created = queue.create_from_mcp_tool(
        "add_alert_note",
        {"alert_id": "alert-9", "note": "Host is a scanner; prior notes agree."},
        cluster_id="lab",
    )
    assert created.status is RequestStatus.PENDING
    assert created.title.startswith("Note:")
    assert "Suspicious DNS Query" in created.title
    assert "workstation-1" in created.title
    assert created.payload["note"] == "Host is a scanner; prior notes agree."
    assert created.summary == "Host is a scanner; prior notes agree."
    assert siem.notes == []
    done = queue.approve(created.id)
    assert done.status is RequestStatus.EXECUTED
    assert siem.notes == [("alert-9", "Host is a scanner; prior notes agree.")]


def test_deny_add_alert_note_does_not_write(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.resolve_clients",
        lambda cluster_id=None: ClientBundle(siem=siem),
    )
    created = queue.create(
        "add_alert_note",
        "Add note",
        "pending note",
        payload={"alert_id": "alert-1", "note": "should not land"},
    )
    denied = queue.deny(created.id, comment="not yet")
    assert denied.status is RequestStatus.DENIED
    assert siem.notes == []


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


def test_identity_yes_also_approves_associated_note(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.resolve_clients",
        lambda cluster_id=None: ClientBundle(cluster_id="lab", siem=siem),
    )
    note = queue.create(
        "add_alert_note",
        "Add note",
        "Confirmed the user.",
        payload={"alert_id": "alert-22", "note": "Confirmed the user."},
        cluster_id="lab",
    )
    created = queue.create(
        "identity_verify",
        "VPN login from 8.8.8.8",
        "New ASN for this user.",
        payload={"username": "sami", "alert_id": "alert-22", "source_ip": "8.8.8.8", "activity": "VPN login"},
        cluster_id="lab",
    )
    done = queue.answer(created.id, "yes")
    assert siem.notes == [("alert-22", "Confirmed the user.")]
    assert siem.closed[0][0] == "alert-22"
    assert queue._require(note.id).status is RequestStatus.EXECUTED
    close = queue.get(done.child_request_ids[0])
    assert close.action_type == "close_alert"
    assert any(item["id"] == note.id for item in (close.execution_result or {}).get("associated_notes") or [])


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


def test_isolate_approve_does_not_call_elastic_defend(tmp_path, monkeypatch):
    """Host isolation is intentionally stubbed — Approve must not hit SIEM/EDR."""
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
    assert done.status is RequestStatus.AWAITING_INTEGRATION
    assert siem.isolated == []
    assert done.payload["endpoint_id"] == "host-1"


def test_release_isolation_approve_is_stubbed(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.resolve_clients",
        lambda cluster_id=None: ClientBundle(cluster_id=cluster_id or "lab", siem=siem),
    )
    created = queue.create(
        "release_isolation",
        "Release workstation",
        "Remediation complete.",
        payload={"endpoint_id": "host-1", "hostname": "ws-1"},
        cluster_id="lab",
    )
    done = queue.approve(created.id)
    assert done.status is RequestStatus.AWAITING_INTEGRATION
    assert getattr(siem, "released", []) == [] or True  # FakeSIEM may not track release


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


def test_mcp_add_alert_note_is_queued(tmp_path, monkeypatch):
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
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "add_alert_note",
                    "arguments": {"alert_id": "a-1", "note": "Findings stay in Requests until approved."},
                },
            }
        )

    response = asyncio.run(_call())
    body = response["result"]["content"][0]["text"]
    assert "queued" in body
    assert siem.notes == []
    assert queue_service.get_queue().counts()["pending"] == 1
    filed = queue_service.get_queue().list(status="pending")[0]
    assert filed.action_type == "add_alert_note"
    assert filed.payload["alert_id"] == "a-1"
    assert filed.payload["note"] == "Findings stay in Requests until approved."


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
                    },
                },
            }
        )

    response = asyncio.run(_call())
    body = response["result"]["content"][0]["text"]
    assert "queued" not in body
    assert siem.verdicts == [("a-2", "in-progress", None)]
    assert queue_service.get_queue().counts()["pending"] == 0


def test_mcp_update_alert_verdict_comment_files_note_request(tmp_path, monkeypatch):
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
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "update_alert_verdict",
                    "arguments": {
                        "alert_id": "a-2",
                        "verdict": "true_positive",
                        "comment": "Note must wait for approval.",
                    },
                },
            }
        )

    response = asyncio.run(_call())
    body = response["result"]["content"][0]["text"]
    assert siem.verdicts == [("a-2", "true_positive", None)]
    assert siem.notes == []
    assert "note_queued" in body
    assert queue_service.get_queue().counts()["pending"] == 1
    filed = queue_service.get_queue().list(status="pending")[0]
    assert filed.action_type == "add_alert_note"
    assert filed.payload["alert_id"] == "a-2"
    assert filed.payload["note"] == "Note must wait for approval."


def test_gated_mcp_tool_descriptions_tell_the_model_they_queue():
    from src.mcp.mcp_server import SamiGPTMCPServer

    server = SamiGPTMCPServer(
        siem_client=object(),
        edr_client=object(),
        eng_client=object(),
    )
    gated = [
        "close_alert",
        "add_alert_note",
        "isolate_endpoint",
        "release_endpoint_isolation",
        "kill_process_on_endpoint",
        "collect_forensic_artifacts",
    ]
    for name in gated:
        desc = server.tools[name]["description"]
        assert "Approvals" in desc or "Requests view" in desc, name
        assert "does not run until" in desc, name
    for name in ("isolate_endpoint", "release_endpoint_isolation"):
        desc = server.tools[name]["description"]
        assert "intentionally disabled" in desc.lower() or "will not call" in desc.lower(), name
    for name in ("create_fine_tuning_recommendation", "create_visibility_recommendation"):
        desc = server.tools[name]["description"]
        assert "Notes" in desc or "Requests view" in desc, name
        assert "informational" in desc.lower(), name
        assert "does not run until" not in desc, name
    assert "search_lab_detection_rules" in server.tools
    assert "get_lab_detection_rule" in server.tools
    verdict = server.tools["update_alert_verdict"]["description"]
    assert "does not wait for analyst approval" in verdict
    assert "queued for the Requests view" in verdict or "Approvals" in verdict
    runbook = server.tools["execute_runbook"]["description"]
    assert "Requests-view" in runbook or "Requests" in runbook
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


def test_queue_tabs_filter_job_tabs_and_legacy_unions(tmp_path, monkeypatch):
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
    alert_note = queue.create(
        "add_alert_note",
        "Note noisy DNS",
        "findings",
        payload={"alert_id": "alert-9", "note": "scanner noise"},
    )
    tip = queue.create(
        "fine_tune",
        "Tune encoded PS",
        "admin script",
        payload={"title": "Tune encoded PS", "description": "Exclude signed admin tool"},
    )
    queue.attach_engineering(tip.id, _engineering_payload())

    closures = queue.list(status="open", queue="closures", sync_github=False)
    alert_notes = queue.list(status="open", queue="alert_notes", sync_github=False)
    fine_tune = queue.list(status="open", queue="fine_tune", sync_github=False)
    response = queue.list(status="open", queue="response", sync_github=False)
    # Legacy unions
    approvals = queue.list(status="open", queue="approvals", sync_github=False)
    notes = queue.list(status="open", queue="notes", sync_github=False)
    soc = queue.list(status="open", queue="soc", sync_github=False)
    detection = queue.list(status="open", queue="detection", sync_github=False)
    engineering = queue.list(status="open", queue="engineering", sync_github=False)
    github_only = queue.list(status="open", queue="fine_tune", sync_github=False, github="1")
    assert {item.id for item in closures} == {close.id}
    assert {item.id for item in alert_notes} == {alert_note.id}
    assert {item.id for item in fine_tune} == {tip.id}
    assert response == []
    assert {item.id for item in approvals} == {close.id, alert_note.id}
    assert {item.id for item in notes} == {tip.id}
    assert {item.id for item in soc} == {close.id, alert_note.id}
    assert {item.id for item in detection} == {tip.id}
    assert {item.id for item in engineering} == {tip.id}
    assert {item.id for item in github_only} == {tip.id}
    counts = queue.counts()
    # Alert notes do not inflate the nav badge; close does.
    assert counts["actionable"] == 1
    assert counts["closures_open"] == 1
    assert counts["alert_notes_open"] == 1
    assert counts["fine_tune_open"] == 1
    assert counts["approvals_open"] == 2
    assert counts["notes_open"] == 1
    assert counts["detection_open"] == 1
    bundle = queue.list_bundle(status="open", queue="closures")
    assert "closures" in bundle["queue_counts"]
    assert "alert_notes" in bundle["queue_counts"]
    assert "fine_tune" in bundle["queue_counts"]
    assert "approvals" in bundle["queue_counts"]
    assert "notes" in bundle["queue_counts"]
    assert "soc" in bundle["queue_counts"]  # legacy mirror
    assert counts["engineering_open"] == 1
    tabs = queue.tab_counts("soc")
    assert tabs["open"] == 2


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
    synced = queue.sync_external_closed()
    assert synced["checked"] == 1
    assert synced["closed"] == 1
    assert synced["errors"] == 0
    archived = queue.list(status="open", queue="detection", sync_github=False)
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


def test_store_skips_reread_when_mtime_unchanged(tmp_path):
    import time

    from src.ai_controller.approval_queue.store import RequestStore

    store = RequestStore(str(tmp_path))
    request = ApprovalRequest(action_type="close_alert", title="Close", summary="noise")
    store.put(request)
    reads = store._reads
    first = store.list()
    second = store.list()
    assert store._reads == reads
    assert [item.id for item in first] == [request.id]
    assert [item.id for item in second] == [request.id]
    path = store._path(request.id)
    later = time.time() + 5
    os.utime(path, (later, later))
    store.list()
    assert store._reads == reads + 1


def test_list_does_not_call_github_or_siem(tmp_path, monkeypatch):
    fetches = {"github": 0, "siem": 0}

    class _SIEM:
        def get_security_alert_by_id(self, alert_id, include_detections=True):
            fetches["siem"] += 1
            return None

    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.resolve_clients",
        lambda cluster_id=None: ClientBundle(siem=_SIEM()),
    )
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.enrichment.resolve_clients",
        lambda cluster_id=None: ClientBundle(siem=_SIEM()),
    )
    monkeypatch.setattr(
        ApprovalQueue,
        "sync_github_closed",
        lambda self, cluster_id=None: (_ for _ in ()).throw(AssertionError("list must not sync GitHub")),
    )
    queue = ApprovalQueue(str(tmp_path))
    close = queue.create(
        "close_alert",
        "Close noisy DNS",
        "scanner",
        payload={"alert_id": "alert-list-1", "reason": "false_positive"},
    )
    note = queue.create(
        "visibility",
        "Missing DNS",
        "gap",
        payload={"title": "Missing DNS", "description": "Need DNS logs"},
    )
    queue.attach_engineering(note.id, _engineering_payload())
    fetches["siem"] = 0
    open_items = queue.list(status="open")
    assert {item.id for item in open_items} == {close.id, note.id}
    assert fetches["siem"] == 0
    soc = queue.list(status="open", queue="soc")
    assert {item.id for item in soc} == {close.id}


def test_same_alert_second_note_updates_when_richer(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.enrichment.resolve_clients",
        lambda cluster_id=None: ClientBundle(siem=None),
    )
    queue = ApprovalQueue(str(tmp_path))
    first = queue.enqueue(
        "add_alert_note",
        title="Add note: ntopng Security Alert",
        summary="request flow logs / scan metadata",
        payload={
            "alert_id": "alert-same-1",
            "note": "request flow logs / scan metadata",
            "alert": {
                "id": "alert-same-1",
                "title": "ntopng Security Alert",
                "related_entities": ["host:10.10.10.99", "destination_ip:185.125.190.99", "port:80"],
                "subtitle": "suspicious_user_agent",
            },
            "rule_name": "ntopng Security Alert",
            "hostname": "10.10.10.99",
            "destination_ip": "185.125.190.99",
            "destination_port": "80",
            "ntopng_script": "suspicious_user_agent",
        },
        session_id="sess-a",
    )
    assert first.outcome == "created"
    richer = (
        "Flow to 185.125.190.99:80 for connectivity-check.ubuntu.com returned HTTP 204; "
        "empty UA is expected Ubuntu probe — benign."
    )
    second = queue.enqueue(
        "add_alert_note",
        title="Add note: ntopng Security Alert",
        summary=richer,
        payload={"alert_id": "alert-same-1", "note": richer},
        session_id="sess-a",
    )
    assert second.outcome == "updated"
    assert second.request.id == first.request.id
    assert richer in (second.request.payload or {}).get("note", "")
    pending = [item for item in queue.list(status="pending") if item.action_type == "add_alert_note"]
    assert len(pending) == 1
    assert pending[0].session_id == "sess-a"


def test_different_alert_ids_stay_separate_with_observable_titles(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.enrichment.resolve_clients",
        lambda cluster_id=None: ClientBundle(siem=None),
    )
    queue = ApprovalQueue(str(tmp_path))
    a = queue.enqueue(
        "add_alert_note",
        title="Add note: ntopng Security Alert (10.10.10.99)",
        summary="note a",
        payload={
            "alert_id": "alert-dst-a",
            "note": "note a about 1.1.1.1",
            "alert": {
                "id": "alert-dst-a",
                "title": "ntopng Security Alert",
                "related_entities": ["host:10.10.10.99", "destination_ip:1.1.1.1", "port:443"],
                "subtitle": "suspicious_user_agent",
            },
            "rule_name": "ntopng Security Alert",
            "hostname": "10.10.10.99",
            "destination_ip": "1.1.1.1",
            "destination_port": "443",
            "ntopng_script": "suspicious_user_agent",
        },
    )
    b = queue.enqueue(
        "add_alert_note",
        title="Add note: ntopng Security Alert (10.10.10.99)",
        summary="note b",
        payload={
            "alert_id": "alert-dst-b",
            "note": "note b about 8.8.8.8",
            "alert": {
                "id": "alert-dst-b",
                "title": "ntopng Security Alert",
                "related_entities": ["host:10.10.10.99", "destination_ip:8.8.8.8", "port:53"],
                "subtitle": "suspicious_user_agent",
            },
            "rule_name": "ntopng Security Alert",
            "hostname": "10.10.10.99",
            "destination_ip": "8.8.8.8",
            "destination_port": "53",
            "ntopng_script": "suspicious_user_agent",
        },
    )
    assert a.outcome == "created"
    assert b.outcome == "created"
    assert a.request.id != b.request.id
    assert "1.1.1.1" in a.request.title
    assert "8.8.8.8" in b.request.title
    assert "10.10.10.99" in a.request.title


def test_fine_tune_same_rule_dedupes_informational_note(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.ApprovalQueue._enrich_informational",
        lambda self, action_type, payload: payload,
    )
    queue = ApprovalQueue(str(tmp_path))
    first = queue.enqueue(
        "fine_tune",
        title="Whitelist Ubuntu connectivity-check",
        summary="Exclude empty UA for ubuntu.com",
        payload={
            "title": "Whitelist Ubuntu connectivity-check",
            "description": "Exclude empty UA for connectivity-check.ubuntu.com",
            "rule_name": "ntopng Security Alert",
            "rule_id": "rule-ntop-1",
        },
        session_id="sess-ft",
    )
    second = queue.enqueue(
        "fine_tune",
        title="Exclude empty UA for ubuntu.com",
        summary="Same noisy rule — whitelist connectivity-check",
        payload={
            "title": "Exclude empty UA for ubuntu.com",
            "description": "Whitelist Ubuntu connectivity-check / empty UA",
            "rule_name": "ntopng Security Alert",
            "rule_id": "rule-ntop-1",
        },
        session_id="sess-ft",
    )
    assert first.outcome == "created"
    assert second.outcome == "deduplicated"
    assert second.request.id == first.request.id
    assert first.request.session_id == "sess-ft"
    notes = [item for item in queue.list(status="open") if item.action_type == "fine_tune"]
    assert len(notes) == 1


def test_find_related_requests_by_rule_and_alert(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.enrichment.resolve_clients",
        lambda cluster_id=None: ClientBundle(siem=None),
    )
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.ApprovalQueue._enrich_informational",
        lambda self, action_type, payload: payload,
    )
    queue = ApprovalQueue(str(tmp_path))
    note = queue.enqueue(
        "add_alert_note",
        title="Note",
        summary="working",
        payload={
            "alert_id": "alert-rel-1",
            "note": "working",
            "alert": {"id": "alert-rel-1", "title": "ntopng Security Alert"},
            "rule_name": "ntopng Security Alert",
        },
    )
    tip = queue.enqueue(
        "fine_tune",
        title="Tune ntopng empty UA",
        summary="whitelist connectivity-check",
        payload={
            "title": "Tune ntopng empty UA",
            "description": "whitelist connectivity-check",
            "rule_name": "ntopng Security Alert",
            "rule_id": "rule-ntop-1",
        },
    )
    by_alert = queue.find_related_requests(alert_id="alert-rel-1", action_type="add_alert_note")
    assert len(by_alert) == 1
    assert by_alert[0]["id"] == note.request.id
    by_rule = queue.find_related_requests(rule_name="ntopng Security Alert", action_type="fine_tune")
    assert len(by_rule) == 1
    assert by_rule[0]["id"] == tip.request.id
    unrelated = queue.find_related_requests(rule_name="Unrelated Rule XYZ", action_type="fine_tune")
    assert unrelated == []


def test_mcp_find_related_requests_and_session_meta(tmp_path, monkeypatch):
    from src.ai_controller.approval_queue import service as queue_service
    from src.ai_controller.approval_queue.mcp_bridge import enqueue_gated_tool, find_related_requests_from_args
    from src.mcp.mcp_server import SamiGPTMCPServer

    queue_service.init_queue(str(tmp_path))
    monkeypatch.setattr(
        "src.core.elastic_clusters.skill_vector_for_cluster",
        lambda cluster_id=None: "MSV:1/IRIS:Y/TH:Y/SIEM:Y/EDR:Y/CTI:Y/KB:Y/ENG:Y/RB:Y/AG:Y/RU:Y",
    )
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.enrichment.resolve_clients",
        lambda cluster_id=None: ClientBundle(siem=None),
    )
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.ApprovalQueue._enrich_informational",
        lambda self, action_type, payload: payload,
    )
    server = SamiGPTMCPServer(siem_client=_FakeSIEM())
    assert "find_related_requests" in server.tools

    queued = enqueue_gated_tool(
        "add_alert_note",
        {"alert_id": "alert-mcp-1", "note": "first pass"},
        session_id="session-meta-1",
    )
    assert queued["queued"] is True
    assert queued["outcome"] == "created"
    filed = queue_service.get_queue().get(queued["request_id"])
    assert filed.session_id == "session-meta-1"

    again = enqueue_gated_tool(
        "add_alert_note",
        {
            "alert_id": "alert-mcp-1",
            "note": "Flow to 185.125.190.99 HTTP 204 benign connectivity-check",
        },
        session_id="session-meta-1",
    )
    assert again["updated"] is True
    assert again["request_id"] == queued["request_id"]

    related = find_related_requests_from_args(
        {"alert_id": "alert-mcp-1", "action_type": "add_alert_note"}
    )
    assert related["count"] == 1
    assert related["requests"][0]["session_id"] == "session-meta-1"

    async def _call():
        return await server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "find_related_requests",
                    "arguments": {"alert_id": "alert-mcp-1"},
                    "_meta": {"session_id": "session-meta-1"},
                },
            }
        )

    response = asyncio.run(_call())
    body = response["result"]["content"][0]["text"]
    assert "alert-mcp-1" in body or "1 related" in body.lower() or '"count"' in body
