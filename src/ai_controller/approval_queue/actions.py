"""Action handlers. Each handler turns an approved request into a tool call or a stub."""

from __future__ import annotations

from typing import Any, Dict, Protocol

from .catalog import get_action_spec
from .clients import ClientBundle
from .models import ApprovalRequest


class ActionHandler(Protocol):
    def execute(self, request: ApprovalRequest, clients: ClientBundle) -> Dict[str, Any]:
        ...


def _missing(integration: str, message: str) -> Dict[str, Any]:
    return {
        "success": False,
        "needs_integration": True,
        "integration": integration,
        "message": message,
    }


def _require(request: ApprovalRequest, *names: str) -> None:
    missing = [name for name in names if not request.payload.get(name)]
    if missing:
        raise ValueError(f"Missing payload fields: {', '.join(missing)}")


class CloseAlertHandler:
    def execute(self, request: ApprovalRequest, clients: ClientBundle) -> Dict[str, Any]:
        _require(request, "alert_id")
        if clients.siem is None:
            return _missing("siem", "No SIEM client for this cluster. Close payload is stored.")
        from ...orchestrator import tools_siem

        return tools_siem.close_alert(
            alert_id=str(request.payload["alert_id"]),
            reason=request.payload.get("reason") or "false_positive",
            comment=request.payload.get("comment") or request.summary,
            client=clients.siem,
        )


class IsolateEndpointHandler:
    def execute(self, request: ApprovalRequest, clients: ClientBundle) -> Dict[str, Any]:
        _require(request, "endpoint_id")
        if clients.edr is None:
            return _missing("edr", "No EDR client configured. Isolation will run once Elastic Defend (or another EDR) is connected.")
        from ...orchestrator import tools_edr

        return tools_edr.isolate_endpoint(
            endpoint_id=str(request.payload["endpoint_id"]),
            client=clients.edr,
        )


class ReleaseIsolationHandler:
    def execute(self, request: ApprovalRequest, clients: ClientBundle) -> Dict[str, Any]:
        _require(request, "endpoint_id")
        if clients.edr is None:
            return _missing("edr", "No EDR client configured. Release payload is stored.")
        from ...orchestrator import tools_edr

        return tools_edr.release_endpoint_isolation(
            endpoint_id=str(request.payload["endpoint_id"]),
            client=clients.edr,
        )


class KillProcessHandler:
    def execute(self, request: ApprovalRequest, clients: ClientBundle) -> Dict[str, Any]:
        _require(request, "endpoint_id", "pid")
        if clients.edr is None:
            return _missing("edr", "No EDR client configured. Kill-process payload is stored.")
        from ...orchestrator import tools_edr

        return tools_edr.kill_process_on_endpoint(
            endpoint_id=str(request.payload["endpoint_id"]),
            pid=int(request.payload["pid"]),
            client=clients.edr,
        )


class CollectForensicsHandler:
    def execute(self, request: ApprovalRequest, clients: ClientBundle) -> Dict[str, Any]:
        _require(request, "endpoint_id")
        if clients.edr is None:
            return _missing("edr", "No EDR client configured. Forensic collection payload is stored.")
        from ...orchestrator import tools_edr

        artifact_types = request.payload.get("artifact_types") or ["processes", "network", "filesystem"]
        if isinstance(artifact_types, str):
            artifact_types = [item.strip() for item in artifact_types.split(",") if item.strip()]
        return tools_edr.collect_forensic_artifacts(
            endpoint_id=str(request.payload["endpoint_id"]),
            artifact_types=list(artifact_types),
            client=clients.edr,
        )


class FineTuneHandler:
    def execute(self, request: ApprovalRequest, clients: ClientBundle) -> Dict[str, Any]:
        _require(request, "title", "description")
        if clients.eng is None:
            return {
                "success": True,
                "stored_locally": True,
                "needs_integration": True,
                "integration": "eng",
                "message": "Fine-tune request saved in the Requests queue. Connect Trello, ClickUp, or GitHub to push it to the engineering board.",
                "title": request.payload.get("title"),
            }
        from ...orchestrator import tools_eng

        return tools_eng.create_fine_tuning_recommendation(
            title=str(request.payload["title"]),
            description=str(request.payload["description"]),
            client=clients.eng,
        )


class VisibilityHandler:
    def execute(self, request: ApprovalRequest, clients: ClientBundle) -> Dict[str, Any]:
        _require(request, "title", "description")
        if clients.eng is None:
            return {
                "success": True,
                "stored_locally": True,
                "needs_integration": True,
                "integration": "eng",
                "message": "Visibility request saved. Connect an engineering board to file it there.",
                "title": request.payload.get("title"),
            }
        from ...orchestrator import tools_eng

        return tools_eng.create_visibility_recommendation(
            title=str(request.payload["title"]),
            description=str(request.payload["description"]),
            client=clients.eng,
        )


class CreateCaseHandler:
    def execute(self, request: ApprovalRequest, clients: ClientBundle) -> Dict[str, Any]:
        _require(request, "title", "description")
        if clients.case is None:
            return _missing("case", "No case-management client (IRIS / TheHive). Case payload is stored.")
        from ...orchestrator import tools_case

        tags = request.payload.get("tags")
        if isinstance(tags, str):
            tags = [item.strip() for item in tags.split(",") if item.strip()]
        return tools_case.create_case(
            title=str(request.payload["title"]),
            description=str(request.payload["description"]),
            priority=str(request.payload.get("priority") or "medium"),
            tags=tags,
            alert_id=request.payload.get("alert_id"),
            client=clients.case,
        )


class CloseCaseHandler:
    def execute(self, request: ApprovalRequest, clients: ClientBundle) -> Dict[str, Any]:
        _require(request, "case_id")
        if clients.case is None:
            return _missing("case", "No case-management client. Close-case payload is stored.")
        from ...orchestrator import tools_case

        result = tools_case.update_case_status(
            case_id=str(request.payload["case_id"]),
            status="closed",
            client=clients.case,
        )
        comment = request.payload.get("comment")
        if comment:
            try:
                tools_case.add_case_comment(
                    case_id=str(request.payload["case_id"]),
                    content=str(comment),
                    author="SamiGPT",
                    client=clients.case,
                )
            except Exception:
                pass
        return result


class EscalateHandler:
    def execute(self, request: ApprovalRequest, clients: ClientBundle) -> Dict[str, Any]:
        results: Dict[str, Any] = {"success": True, "steps": []}
        alert_id = request.payload.get("alert_id")
        if clients.siem is None:
            results["steps"].append(
                _missing("siem", "No SIEM client for this cluster. Escalation payload is stored.")
            )
            results["success"] = False
            results["needs_integration"] = True
            results["integration"] = "siem"
            results["message"] = "No SIEM client for this cluster. Escalation payload is stored."
            return results

        from ...orchestrator import tools_siem

        if alert_id:
            try:
                results["steps"].append(
                    tools_siem.tag_alert(alert_id=str(alert_id), tag="TP", client=clients.siem)
                )
            except Exception as exc:
                results["steps"].append({"success": False, "step": "tag_alert", "error": str(exc)})
            try:
                results["steps"].append(
                    tools_siem.update_alert_verdict(
                        alert_id=str(alert_id),
                        verdict="true_positive",
                        comment=request.payload.get("description") or request.summary,
                        client=clients.siem,
                    )
                )
            except Exception as exc:
                results["steps"].append({"success": False, "step": "update_alert_verdict", "error": str(exc)})

        identity = {
            key: request.payload.get(key)
            for key in ("username", "source_ip", "hostname", "timestamp", "activity")
            if request.payload.get(key)
        }
        tags = request.payload.get("tags")
        if isinstance(tags, str):
            tags = [item.strip() for item in tags.split(",") if item.strip()]
        try:
            results["steps"].append(
                tools_siem.create_elastic_case(
                    title=request.payload.get("title") or request.title,
                    description=request.payload.get("description") or request.rationale or request.summary,
                    alert_id=str(alert_id) if alert_id else None,
                    severity=str(request.payload.get("priority") or request.payload.get("severity") or "high"),
                    tags=list(tags or []) + ["identity-verify"] if identity else tags,
                    identity=identity or None,
                    client=clients.siem,
                )
            )
        except Exception as exc:
            results["steps"].append({"success": False, "step": "create_elastic_case", "error": str(exc)})
            results["success"] = False
            results["error"] = str(exc)
        return results


class StubHandler:
    def __init__(self, integration: str, message: str) -> None:
        self.integration = integration
        self.message = message

    def execute(self, request: ApprovalRequest, clients: ClientBundle) -> Dict[str, Any]:
        spec = get_action_spec(request.action_type)
        return _missing(
            spec.integration if spec else self.integration,
            self.message,
        )


class IdentityVerifyHandler:
    """Identity questions are answered in the service; this handler is not used to execute."""

    def execute(self, request: ApprovalRequest, clients: ClientBundle) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Waiting for analyst yes/no. Follow-up runs after the answer.",
            "asks_question": True,
        }


HANDLERS: Dict[str, ActionHandler] = {
    "close_alert": CloseAlertHandler(),
    "identity_verify": IdentityVerifyHandler(),
    "isolate_endpoint": IsolateEndpointHandler(),
    "release_isolation": ReleaseIsolationHandler(),
    "kill_process": KillProcessHandler(),
    "collect_forensics": CollectForensicsHandler(),
    "fine_tune": FineTuneHandler(),
    "visibility": VisibilityHandler(),
    "create_case": CreateCaseHandler(),
    "close_case": CloseCaseHandler(),
    "escalate": EscalateHandler(),
    "block_indicator": StubHandler("none", "No block-list API connected yet. Indicator and reason are stored."),
    "disable_user": StubHandler("none", "No IAM/directory API connected yet. Disable-user payload is stored."),
    "reset_credentials": StubHandler("none", "No IAM API connected yet. Credential-reset payload is stored."),
    "contain_email": StubHandler("none", "No mail-gateway API connected yet. Contain-email payload is stored."),
}


def get_handler(action_type: str) -> ActionHandler:
    handler = HANDLERS.get(action_type)
    if handler is None:
        raise ValueError(f"No handler registered for action type {action_type!r}")
    return handler
