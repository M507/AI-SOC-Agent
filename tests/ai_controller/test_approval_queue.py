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

    def close_alert(self, alert_id, reason=None, comment=None):
        self.closed.append((alert_id, reason, comment))
        return {"alert_id": alert_id, "status": "closed", "reason": reason, "comment": comment, "alert": {}}

    def update_alert_verdict(self, alert_id, verdict, comment=None):
        self.verdicts.append((alert_id, verdict, comment))
        return {"alert_id": alert_id, "verdict": verdict}

    def tag_alert(self, alert_id, tag):
        self.tags.append((alert_id, tag))
        return {"success": True, "alert_id": alert_id, "tag": tag}


def test_catalog_covers_soc_actions():
    types = {spec.action_type for spec in ACTION_CATALOG}
    assert "close_alert" in types
    assert "identity_verify" in types
    assert "isolate_endpoint" in types
    assert "fine_tune" in types
    assert "update_verdict" not in types
    assert get_action_spec("close_alert").execution == "ready"


def test_close_alert_executes_on_originating_cluster(tmp_path, monkeypatch):
    queue = ApprovalQueue(str(tmp_path))
    siem = _FakeSIEM()
    monkeypatch.setattr(
        "src.ai_controller.approval_queue.service.resolve_clients",
        lambda cluster_id=None: ClientBundle(cluster_id=cluster_id or "lab", siem=siem),
    )
    created = queue.create(
        "close_alert",
        "Close noisy DNS alert",
        "Matches known scanner, no internal hosts involved.",
        payload={"alert_id": "alert-9", "reason": "false_positive", "comment": "scanner"},
        cluster_id="lab",
    )
    done = queue.approve(created.id)
    assert done.status is RequestStatus.EXECUTED
    assert done.cluster_id == "lab"
    assert siem.closed == [("alert-9", "false_positive", "scanner")]


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


def test_isolate_waits_for_edr(tmp_path):
    queue = ApprovalQueue(str(tmp_path))
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
        "create_fine_tuning_recommendation",
        "create_visibility_recommendation",
    ]
    for name in gated:
        desc = server.tools[name]["description"]
        assert "Requests view" in desc, name
        assert "does not run until" in desc, name
    verdict = server.tools["update_alert_verdict"]["description"]
    assert "does not wait for analyst approval" in verdict
    assert "queued for the Requests view" in verdict
    runbook = server.tools["execute_runbook"]["description"]
    assert "Requests-view" in runbook
