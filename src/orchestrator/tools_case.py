"""
LLM-callable tools for case management operations.

These functions wrap the generic CaseManagementClient interface and provide
LLM-friendly error handling and return values.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..api.case_management import (
    Case,
    CaseAssignment,
    CaseComment,
    CaseManagementClient,
    CaseObservable,
    CasePriority,
    CaseSearchQuery,
    CaseStatus,
    CaseSummary,
)
from ..core.errors import IntegrationError


def create_case(
    title: str,
    description: str,
    priority: str = "medium",
    status: str = "open",
    tags: Optional[List[str]] = None,
    alert_id: Optional[str] = None,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Create a new case.

    Tool schema:
    - name: create_case
    - description: Create a new case for investigation. Follows the case standard
      format defined in standards/case_standard.md.
    - parameters:
      - title (str, required): Case title following format: [Alert Type] - [Primary Entity] - [Date/Time]
      - description (str, required): Comprehensive case description
      - priority (str, optional): Case priority (low, medium, high, critical). Default: medium
      - status (str, optional): Case status (open, in_progress, closed). Default: open
      - tags (list[str], optional): Tags for categorization
      - alert_id (str, optional): Associated alert ID if case is created from an alert

    Args:
        title: Case title.
        description: Case description.
        priority: Case priority.
        status: Case status.
        tags: Optional tags.
        alert_id: Optional associated alert ID.
        client: The case management client.

    Returns:
        Dictionary containing created case details.

    Raises:
        IntegrationError: If case creation fails.
    """
    if client is None:
        raise IntegrationError("Case management client not provided")

    try:
        priority_enum = CasePriority(priority.lower())
        status_enum = CaseStatus(status.lower())

        new_case = Case(
            id=None,
            title=title,
            description=description,
            status=status_enum,
            priority=priority_enum,
            tags=tags,
        )

        created = client.create_case(new_case)

        return {
            "success": True,
            "case_id": created.id,
            "case": {
                "id": created.id,
                "title": created.title,
                "description": created.description,
                "status": created.status.value,
                "priority": created.priority.value,
                "tags": created.tags or [],
                "created_at": created.created_at.isoformat() if created.created_at else None,
                "updated_at": created.updated_at.isoformat() if created.updated_at else None,
            },
        }
    except ValueError as e:
        raise IntegrationError(f"Invalid priority or status: {str(e)}")
    except Exception as e:
        raise IntegrationError(f"Failed to create case: {str(e)}") from e


def review_case(
    case_id: str,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Review a case by retrieving its full details.

    Tool schema:
    - name: review_case
    - description: Retrieve and review the full details of a case including
      title, description, status, priority, observables, and comments.
    - parameters:
      - case_id (str, required): The ID of the case to review.

    Args:
        case_id: The ID of the case to review.
        client: The case management client.

    Returns:
        Dictionary containing case details in a format suitable for LLM consumption.

    Raises:
        IntegrationError: If the case cannot be retrieved.
    """
    if client is None:
        raise IntegrationError("Case management client not provided")
    
    try:
        case = client.get_case(case_id)
        timeline = client.get_case_timeline(case_id)

        return {
            "success": True,
            "case": {
                "id": case.id,
                "title": case.title,
                "description": case.description,
                "status": case.status.value,
                "priority": case.priority.value,
                "assignee": case.assignee,
                "tags": case.tags or [],
                "observables": [
                    {
                        "type": obs.type,
                        "value": obs.value,
                        "description": obs.description,
                        "tags": obs.tags or [],
                    }
                    for obs in (case.observables or [])
                ],
                "created_at": case.created_at.isoformat() if case.created_at else None,
                "updated_at": case.updated_at.isoformat() if case.updated_at else None,
            },
            "timeline": [
                {
                    "author": comment.author,
                    "content": comment.content,
                    "created_at": comment.created_at.isoformat()
                    if comment.created_at
                    else None,
                }
                for comment in timeline
            ],
        }
    except Exception as e:
        error_msg = f"Failed to review case {case_id}: {str(e)}"
        if isinstance(e, IntegrationError):
            raise
        raise IntegrationError(error_msg) from e


def list_cases(
    status: Optional[str] = None,
    limit: int = 50,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    List cases, optionally filtered by status.

    Tool schema:
    - name: list_cases
    - description: List cases from the case management system, optionally
      filtered by status (open, in_progress, closed).
    - parameters:
      - status (str, optional): Filter by status (open, in_progress, closed).
      - limit (int, optional): Maximum number of cases to return (default: 50).

    Args:
        status: Optional status filter.
        limit: Maximum number of cases to return.
        client: The case management client.

    Returns:
        Dictionary containing list of case summaries.

    Raises:
        IntegrationError: If listing cases fails.
    """
    if client is None:
        raise IntegrationError("Case management client not provided")

    try:
        status_enum = None
        if status:
            try:
                status_enum = CaseStatus(status.lower())
            except ValueError:
                raise IntegrationError(f"Invalid status: {status}")

        cases = client.list_cases(status=status_enum, limit=limit)

        # Filter out case ID 1 (default demo case) - always ignore it
        filtered_cases = [case for case in cases if str(case.id) != "1"]

        return {
            "success": True,
            "count": len(filtered_cases),
            "cases": [
                {
                    "id": case.id,
                    "title": case.title,
                    "status": case.status.value,
                    "priority": case.priority.value,
                    "assignee": case.assignee,
                    "created_at": case.created_at.isoformat()
                    if case.created_at
                    else None,
                }
                for case in filtered_cases
            ],
        }
    except IntegrationError:
        raise
    except Exception as e:
        raise IntegrationError(f"Failed to list cases: {str(e)}") from e


def search_cases(
    text: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    tags: Optional[List[str]] = None,
    assignee: Optional[str] = None,
    limit: int = 50,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Search for cases using various filters.

    Tool schema:
    - name: search_cases
    - description: Search for cases using text search, status, priority, tags,
      or assignee filters.
    - parameters:
      - text (str, optional): Text to search for in case title/description.
      - status (str, optional): Filter by status.
      - priority (str, optional): Filter by priority (low, medium, high, critical).
      - tags (list[str], optional): Filter by tags.
      - assignee (str, optional): Filter by assignee.
      - limit (int, optional): Maximum results (default: 50).

    Args:
        text: Text search query.
        status: Status filter.
        priority: Priority filter.
        tags: Tags to filter by.
        assignee: Assignee to filter by.
        limit: Maximum results.
        client: The case management client.

    Returns:
        Dictionary containing search results.

    Raises:
        IntegrationError: If search fails.
    """
    if client is None:
        raise IntegrationError("Case management client not provided")

    try:
        status_enum = None
        if status:
            try:
                status_enum = CaseStatus(status.lower())
            except ValueError:
                raise IntegrationError(f"Invalid status: {status}")

        priority_enum = None
        if priority:
            try:
                priority_enum = CasePriority(priority.lower())
            except ValueError:
                raise IntegrationError(f"Invalid priority: {priority}")

        query = CaseSearchQuery(
            text=text,
            status=status_enum,
            priority=priority_enum,
            tags=tags,
            assignee=assignee,
            limit=limit,
        )

        results = client.search_cases(query)

        return {
            "success": True,
            "count": len(results),
            "cases": [
                {
                    "id": case.id,
                    "title": case.title,
                    "status": case.status.value,
                    "priority": case.priority.value,
                    "assignee": case.assignee,
                    "created_at": case.created_at.isoformat()
                    if case.created_at
                    else None,
                }
                for case in results
            ],
        }
    except IntegrationError:
        raise
    except Exception as e:
        raise IntegrationError(f"Failed to search cases: {str(e)}") from e


def add_case_comment(
    case_id: str,
    content: str,
    author: Optional[str] = None,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Add a comment to a case.

    Tool schema:
    - name: add_case_comment
    - description: Add a comment or note to a case.
    - parameters:
      - case_id (str, required): The ID of the case.
      - content (str, required): The comment content.
      - author (str, optional): The author of the comment.

    Args:
        case_id: The case ID.
        content: The comment content.
        author: Optional author name.
        client: The case management client.

    Returns:
        Dictionary with comment details.

    Raises:
        IntegrationError: If adding comment fails.
    """
    if client is None:
        raise IntegrationError("Case management client not provided")

    try:
        comment = client.add_case_comment(case_id, content, author)

        return {
            "success": True,
            "comment": {
                "id": comment.id,
                "case_id": comment.case_id,
                "author": comment.author,
                "content": comment.content,
                "created_at": comment.created_at.isoformat()
                if comment.created_at
                else None,
            },
        }
    except Exception as e:
        raise IntegrationError(f"Failed to add comment to case {case_id}: {str(e)}") from e


def attach_observable_to_case(
    case_id: str,
    observable_type: str,
    observable_value: str,
    description: Optional[str] = None,
    tags: Optional[List[str]] = None,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Attach an observable (IP, hash, domain, etc.) to a case.

    Tool schema:
    - name: attach_observable_to_case
    - description: Attach an observable such as an IP address, file hash,
      domain, or URL to a case for tracking and analysis.
    - parameters:
      - case_id (str, required): The ID of the case.
      - observable_type (str, required): Type of observable (ip, hash, domain, url, etc.).
      - observable_value (str, required): The value of the observable.
      - description (str, optional): Description of the observable.
      - tags (list[str], optional): Tags for the observable.

    Args:
        case_id: The case ID.
        observable_type: Type of observable (ip, hash, domain, url, etc.).
        observable_value: The observable value.
        description: Optional description.
        tags: Optional tags.
        client: The case management client.

    Returns:
        Dictionary with observable details.

    Raises:
        IntegrationError: If adding observable fails.
    """
    if client is None:
        raise IntegrationError("Case management client not provided")

    try:
        observable = CaseObservable(
            type=observable_type,
            value=observable_value,
            description=description,
            tags=tags,
        )

        added = client.add_case_observable(case_id, observable)

        return {
            "success": True,
            "observable": {
                "type": added.type,
                "value": added.value,
                "description": added.description,
                "tags": added.tags or [],
            },
        }
    except Exception as e:
        raise IntegrationError(
            f"Failed to attach observable to case {case_id}: {str(e)}"
        ) from e


def update_case_status(
    case_id: str,
    status: str,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Update the status of a case.

    Tool schema:
    - name: update_case_status
    - description: Update the status of a case (open, in_progress, closed).
    - parameters:
      - case_id (str, required): The ID of the case.
      - status (str, required): New status (open, in_progress, closed).

    Args:
        case_id: The case ID.
        status: New status value.
        client: The case management client.

    Returns:
        Dictionary with updated case details.

    Raises:
        IntegrationError: If status update fails.
    """
    if client is None:
        raise IntegrationError("Case management client not provided")

    try:
        status_enum = CaseStatus(status.lower())
        updated = client.update_case_status(case_id, status_enum)

        return {
            "success": True,
            "case": {
                "id": updated.id,
                "title": updated.title,
                "status": updated.status.value,
            },
        }
    except ValueError:
        raise IntegrationError(f"Invalid status: {status}")
    except Exception as e:
        raise IntegrationError(f"Failed to update case status: {str(e)}") from e


def assign_case(
    case_id: str,
    assignee: str,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Assign a case to a user.

    Tool schema:
    - name: assign_case
    - description: Assign a case to a specific user or analyst.
    - parameters:
      - case_id (str, required): The ID of the case.
      - assignee (str, required): The username or ID of the assignee.

    Args:
        case_id: The case ID.
        assignee: The assignee username/ID.
        client: The case management client.

    Returns:
        Dictionary with assignment details.

    Raises:
        IntegrationError: If assignment fails.
    """
    if client is None:
        raise IntegrationError("Case management client not provided")

    try:
        assignment = client.assign_case(case_id, assignee)

        return {
            "success": True,
            "assignment": {
                "case_id": assignment.case_id,
                "assignee": assignment.assignee,
                "assigned_at": assignment.assigned_at.isoformat()
                if assignment.assigned_at
                else None,
            },
        }
    except Exception as e:
        raise IntegrationError(f"Failed to assign case {case_id}: {str(e)}") from e


def get_case_timeline(
    case_id: str,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get the timeline of events/comments for a case.

    Tool schema:
    - name: get_case_timeline
    - description: Retrieve the timeline of comments and events for a case,
      ordered chronologically.
    - parameters:
      - case_id (str, required): The ID of the case.

    Args:
        case_id: The case ID.
        client: The case management client.

    Returns:
        Dictionary containing timeline events.

    Raises:
        IntegrationError: If retrieving timeline fails.
    """
    if client is None:
        raise IntegrationError("Case management client not provided")

    try:
        timeline = client.get_case_timeline(case_id)

        return {
            "success": True,
            "case_id": case_id,
            "count": len(timeline),
            "timeline": [
                {
                    "author": comment.author,
                    "content": comment.content,
                    "created_at": comment.created_at.isoformat()
                    if comment.created_at
                    else None,
                }
                for comment in timeline
            ],
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get timeline for case {case_id}: {str(e)}") from e


def add_case_task(
    case_id: str,
    title: str,
    description: str,
    assignee: Optional[str] = None,
    priority: str = "medium",
    status: str = "pending",
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Add a task to a case.
    
    Tool schema:
    - name: add_case_task
    - description: Add a task to a case. Tasks represent actionable items for investigation and response, typically assigned to SOC2 or SOC3 tiers.
    - parameters:
      - case_id (str, required): The ID of the case
      - title (str, required): Task title
      - description (str, required): Task description
      - assignee (str, optional): Assignee ID or SOC tier (e.g., "SOC2", "SOC3")
      - priority (str, optional): Task priority (low, medium, high, critical). Default: medium
      - status (str, optional): Task status (pending, in_progress, completed, blocked). Default: pending
    """
    if client is None:
        raise IntegrationError("Case management client not provided")
    
    if not hasattr(client, "add_case_task"):
        raise IntegrationError("Case management client does not support tasks")
    
    try:
        result = client.add_case_task(
            case_id=case_id,
            title=title,
            description=description,
            assignee=assignee,
            priority=priority,
            status=status,
        )
        
        return {
            "success": True,
            "case_id": case_id,
            "task": result,
            "message": f"Task '{title}' added to case {case_id}"
        }
    except Exception as e:
        raise IntegrationError(f"Failed to add task to case {case_id}: {str(e)}") from e


def list_case_tasks(
    case_id: str,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    List tasks for a case.
    
    Tool schema:
    - name: list_case_tasks
    - description: List all tasks associated with a case
    - parameters:
      - case_id (str, required): The ID of the case
    """
    if client is None:
        raise IntegrationError("Case management client not provided")
    
    if not hasattr(client, "list_case_tasks"):
        raise IntegrationError("Case management client does not support tasks")
    
    try:
        tasks = client.list_case_tasks(case_id)
        
        return {
            "success": True,
            "case_id": case_id,
            "count": len(tasks),
            "tasks": tasks,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to list tasks for case {case_id}: {str(e)}") from e


def update_case_task_status(
    case_id: str,
    task_id: str,
    status: str,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Update the status of a task.
    
    Tool schema:
    - name: update_case_task_status
    - description: Update the status of a task (pending, in_progress, completed, blocked)
    - parameters:
      - case_id (str, required): The ID of the case
      - task_id (str, required): The ID of the task to update
      - status (str, required): New task status (pending, in_progress, completed, blocked)
    """
    if client is None:
        raise IntegrationError("Case management client not provided")
    
    if not hasattr(client, "update_case_task_status"):
        raise IntegrationError("Case management client does not support task status updates")
    
    try:
        valid_statuses = ["pending", "in_progress", "completed", "blocked"]
        if status.lower() not in valid_statuses:
            raise IntegrationError(f"Invalid task status: {status}. Valid statuses: {', '.join(valid_statuses)}")
        
        result = client.update_case_task_status(
            case_id=case_id,
            task_id=task_id,
            status=status,
        )
        
        return {
            "success": True,
            "case_id": case_id,
            "task_id": task_id,
            "task": result,
            "message": f"Task {task_id} status updated to '{status}'"
        }
    except Exception as e:
        raise IntegrationError(f"Failed to update task status: {str(e)}") from e


def add_case_asset(
    case_id: str,
    asset_name: str,
    asset_type: str,
    description: Optional[str] = None,
    ip_address: Optional[str] = None,
    hostname: Optional[str] = None,
    tags: Optional[List[str]] = None,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Add an asset to a case.
    
    Tool schema:
    - name: add_case_asset
    - description: Add an asset (endpoint, server, network, user account, application) to a case
    - parameters:
      - case_id (str, required): The ID of the case
      - asset_name (str, required): Asset name/identifier
      - asset_type (str, required): Asset type (endpoint, server, network, user_account, application)
      - description (str, optional): Asset description
      - ip_address (str, optional): IP address if applicable
      - hostname (str, optional): Hostname if applicable
      - tags (list[str], optional): Tags for the asset
    """
    if client is None:
        raise IntegrationError("Case management client not provided")
    
    if not hasattr(client, "add_case_asset"):
        raise IntegrationError("Case management client does not support assets")
    
    try:
        result = client.add_case_asset(
            case_id=case_id,
            asset_name=asset_name,
            asset_type=asset_type,
            description=description,
            ip_address=ip_address,
            hostname=hostname,
            tags=tags,
        )
        
        return {
            "success": True,
            "case_id": case_id,
            "asset": result,
            "message": f"Asset '{asset_name}' added to case {case_id}"
        }
    except Exception as e:
        raise IntegrationError(f"Failed to add asset to case {case_id}: {str(e)}") from e


def list_case_assets(
    case_id: str,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    List assets for a case.
    
    Tool schema:
    - name: list_case_assets
    - description: List all assets associated with a case
    - parameters:
      - case_id (str, required): The ID of the case
    """
    if client is None:
        raise IntegrationError("Case management client not provided")
    
    if not hasattr(client, "list_case_assets"):
        raise IntegrationError("Case management client does not support assets")
    
    try:
        assets = client.list_case_assets(case_id)
        
        return {
            "success": True,
            "case_id": case_id,
            "count": len(assets),
            "assets": assets,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to list assets for case {case_id}: {str(e)}") from e


def add_case_evidence(
    case_id: str,
    file_path: str,
    description: Optional[str] = None,
    evidence_type: Optional[str] = None,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Add evidence (file) to a case.
    
    Tool schema:
    - name: add_case_evidence
    - description: Upload and attach evidence (file, log, screenshot, network capture, etc.) to a case
    - parameters:
      - case_id (str, required): The ID of the case
      - file_path (str, required): Path to the evidence file
      - description (str, optional): Description of the evidence
      - evidence_type (str, optional): Type of evidence (file, screenshot, log, network_capture, memory_dump, registry, other)
    """
    if client is None:
        raise IntegrationError("Case management client not provided")
    
    if not hasattr(client, "add_case_evidence"):
        raise IntegrationError("Case management client does not support evidence")
    
    try:
        result = client.add_case_evidence(
            case_id=case_id,
            file_path=file_path,
            description=description,
            evidence_type=evidence_type,
        )
        
        return {
            "success": True,
            "case_id": case_id,
            "evidence": result,
            "message": f"Evidence file '{file_path}' added to case {case_id}"
        }
    except Exception as e:
        raise IntegrationError(f"Failed to add evidence to case {case_id}: {str(e)}") from e


def list_case_evidence(
    case_id: str,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    List evidence for a case.
    
    Tool schema:
    - name: list_case_evidence
    - description: List all evidence files associated with a case
    - parameters:
      - case_id (str, required): The ID of the case
    """
    if client is None:
        raise IntegrationError("Case management client not provided")
    
    if not hasattr(client, "list_case_evidence"):
        raise IntegrationError("Case management client does not support evidence")
    
    try:
        evidence = client.list_case_evidence(case_id)
        
        return {
            "success": True,
            "case_id": case_id,
            "count": len(evidence),
            "evidence": evidence,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to list evidence for case {case_id}: {str(e)}") from e


def update_case(
    case_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    priority: Optional[str] = None,
    status: Optional[str] = None,
    tags: Optional[List[str]] = None,
    assignee: Optional[str] = None,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Update a case with new information.
    
    Tool schema:
    - name: update_case
    - description: Update a case with new information (title, description, priority, status, tags, assignee)
    - parameters:
      - case_id (str, required): The ID of the case to update
      - title (str, optional): New case title
      - description (str, optional): New case description
      - priority (str, optional): New priority (low, medium, high, critical)
      - status (str, optional): New status (open, in_progress, closed)
      - tags (list[str], optional): New tags list
      - assignee (str, optional): New assignee
    """
    if client is None:
        raise IntegrationError("Case management client not provided")
    
    try:
        updates = {}
        if title is not None:
            updates["title"] = title
        if description is not None:
            updates["description"] = description
        if priority is not None:
            updates["priority"] = CasePriority(priority.lower())
        if status is not None:
            updates["status"] = CaseStatus(status.lower())
        if tags is not None:
            updates["tags"] = tags
        if assignee is not None:
            updates["assignee"] = assignee
        
        if not updates:
            raise IntegrationError("No updates provided")
        
        updated = client.update_case(case_id, updates)
        
        return {
            "success": True,
            "case": {
                "id": updated.id,
                "title": updated.title,
                "description": updated.description,
                "status": updated.status.value,
                "priority": updated.priority.value,
                "tags": updated.tags or [],
                "assignee": updated.assignee,
                "updated_at": updated.updated_at.isoformat() if updated.updated_at else None,
            },
        }
    except ValueError as e:
        raise IntegrationError(f"Invalid priority or status: {str(e)}")
    except Exception as e:
        raise IntegrationError(f"Failed to update case {case_id}: {str(e)}") from e


def link_cases(
    source_case_id: str,
    target_case_id: str,
    link_type: str = "related_to",
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Link two cases together.
    
    Tool schema:
    - name: link_cases
    - description: Link two cases together to indicate a relationship (e.g., duplicate, related, escalated from)
    - parameters:
      - source_case_id (str, required): The ID of the source case
      - target_case_id (str, required): The ID of the target case to link to
      - link_type (str, optional): Type of link (related_to, duplicate_of, escalated_from, child_of, blocked_by). Default: related_to
    """
    if client is None:
        raise IntegrationError("Case management client not provided")
    
    try:
        client.link_cases(source_case_id, target_case_id, link_type)
        
        return {
            "success": True,
            "source_case_id": source_case_id,
            "target_case_id": target_case_id,
            "link_type": link_type,
            "message": f"Case {source_case_id} linked to {target_case_id} with type '{link_type}'",
        }
    except Exception as e:
        raise IntegrationError(
            f"Failed to link cases {source_case_id} and {target_case_id}: {str(e)}"
        ) from e


def add_case_timeline_event(
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
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Add an event to a case timeline.
    
    Tool schema:
    - name: add_case_timeline_event
    - description: Add an event to a case timeline for tracking investigation activities and milestones
    - parameters:
      - case_id (str, required): The ID of the case
      - title (str, required): Event title
      - content (str, required): Event content/description
      - source (str, optional): Event source (e.g., "SamiGPT", "SIEM", "EDR")
      - category_id (int, optional): Event category ID
      - tags (list[str], optional): Event tags
      - color (str, optional): Event color (hex format, e.g., "#1572E899")
      - event_date (str, optional): Event date in ISO format (defaults to current time)
      - include_in_summary (bool, optional): Include event in case summary (default: true)
      - include_in_graph (bool, optional): Include event in case graph (default: true)
      - sync_iocs_assets (bool, optional): Sync with IOCs and assets (default: true)
      - asset_ids (list[int], optional): Related asset IDs
      - ioc_ids (list[int], optional): Related IOC IDs
      - custom_attributes (dict, optional): Custom attributes
      - raw (str, optional): Raw event data
      - tz (str, optional): Timezone (default: "+00:00")
    """
    if client is None:
        raise IntegrationError("Case management client not provided")
    
    if not hasattr(client, "add_case_timeline_event"):
        raise IntegrationError("Case management client does not support timeline events")
    
    try:
        result = client.add_case_timeline_event(
            case_id=case_id,
            title=title,
            content=content,
            source=source,
            category_id=category_id,
            tags=tags,
            color=color,
            event_date=event_date,
            include_in_summary=include_in_summary,
            include_in_graph=include_in_graph,
            sync_iocs_assets=sync_iocs_assets,
            asset_ids=asset_ids,
            ioc_ids=ioc_ids,
            custom_attributes=custom_attributes,
            raw=raw,
            tz=tz,
        )
        
        return {
            "success": True,
            "case_id": case_id,
            "event": result,
            "message": f"Timeline event '{title}' added to case {case_id}",
        }
    except Exception as e:
        raise IntegrationError(f"Failed to add timeline event to case {case_id}: {str(e)}") from e


def list_case_timeline_events(
    case_id: str,
    client: CaseManagementClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    List timeline events for a case.
    
    Tool schema:
    - name: list_case_timeline_events
    - description: List all timeline events associated with a case
    - parameters:
      - case_id (str, required): The ID of the case
    """
    if client is None:
        raise IntegrationError("Case management client not provided")
    
    if not hasattr(client, "list_case_timeline_events"):
        raise IntegrationError("Case management client does not support timeline events")
    
    try:
        events = client.list_case_timeline_events(case_id)
        
        return {
            "success": True,
            "case_id": case_id,
            "count": len(events),
            "events": events,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to list timeline events for case {case_id}: {str(e)}") from e

