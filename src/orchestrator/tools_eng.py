"""
Orchestrator tools for Engineering integrations (Trello, ClickUp, GitHub).
"""

from __future__ import annotations

from typing import Dict, Any, Optional, Union

from ..integrations.eng.trello.trello_client import TrelloClient
from ..integrations.eng.clickup.clickup_client import ClickUpClient
from ..integrations.eng.github.github_client import GitHubClient


def create_fine_tuning_recommendation(
    title: str,
    description: str,
    list_name: Optional[str] = None,
    labels: Optional[list[str]] = None,
    status: Optional[str] = None,
    tags: Optional[list[str]] = None,
    client: Optional[Union[TrelloClient, ClickUpClient, GitHubClient]] = None,
) -> Dict[str, Any]:
    """
    Create a fine-tuning recommendation on the fine-tuning board.
    
    Supports Trello (cards), ClickUp (tasks), and GitHub (project items).
    
    Args:
        title: Task/card title
        description: Task/card description
        list_name: Optional list name (Trello only, defaults to first list on board)
        labels: Optional list of label names (Trello only)
        status: Optional status name (ClickUp only, defaults to first status in list)
        tags: Optional list of tag names (ClickUp only)
        client: TrelloClient, ClickUpClient, or GitHubClient instance (required)
    
    Returns:
        Dictionary with task/card/project item information
    """
    if not client:
        raise ValueError("Engineering client (TrelloClient, ClickUpClient, or GitHubClient) is required")
    
    if isinstance(client, TrelloClient):
        result = client.create_fine_tuning_recommendation(
            title=title,
            description=description,
            list_name=list_name,
            labels=labels,
        )
        return {
            "success": True,
            "provider": "trello",
            "card": {
                "id": result.get("id"),
                "name": result.get("name"),
                "url": result.get("url"),
                "board_id": result.get("idBoard"),
            },
        }
    elif isinstance(client, ClickUpClient):
        result = client.create_fine_tuning_recommendation(
            title=title,
            description=description,
            status=status,
            tags=tags,
        )
        return {
            "success": True,
            "provider": "clickup",
            "task": {
                "id": result.get("id"),
                "name": result.get("name"),
                "url": result.get("url"),
                "list_id": result.get("list", {}).get("id") if isinstance(result.get("list"), dict) else None,
            },
        }
    elif isinstance(client, GitHubClient):
        result = client.create_fine_tuning_recommendation(
            title=title,
            description=description,
        )
        return {
            "success": True,
            "provider": "github",
            "project_item": {
                "id": result.get("id"),
                "note": result.get("note"),
                "url": result.get("url"),
                "project_id": result.get("project_id"),
            },
        }
    else:
        raise ValueError(f"Unsupported client type: {type(client)}")


def create_visibility_recommendation(
    title: str,
    description: str,
    list_name: Optional[str] = None,
    labels: Optional[list[str]] = None,
    status: Optional[str] = None,
    tags: Optional[list[str]] = None,
    client: Optional[Union[TrelloClient, ClickUpClient, GitHubClient]] = None,
) -> Dict[str, Any]:
    """
    Create a visibility/engineering recommendation on the engineering board.
    
    Supports Trello (cards), ClickUp (tasks), and GitHub (project items).
    
    Args:
        title: Task/card title
        description: Task/card description
        list_name: Optional list name (Trello only, defaults to first list on board)
        labels: Optional list of label names (Trello only)
        status: Optional status name (ClickUp only, defaults to first status in list)
        tags: Optional list of tag names (ClickUp only)
        client: TrelloClient, ClickUpClient, or GitHubClient instance (required)
    
    Returns:
        Dictionary with task/card/project item information
    """
    if not client:
        raise ValueError("Engineering client (TrelloClient, ClickUpClient, or GitHubClient) is required")
    
    if isinstance(client, TrelloClient):
        result = client.create_visibility_recommendation(
            title=title,
            description=description,
            list_name=list_name,
            labels=labels,
        )
        return {
            "success": True,
            "provider": "trello",
            "card": {
                "id": result.get("id"),
                "name": result.get("name"),
                "url": result.get("url"),
                "board_id": result.get("idBoard"),
            },
        }
    elif isinstance(client, ClickUpClient):
        result = client.create_visibility_recommendation(
            title=title,
            description=description,
            status=status,
            tags=tags,
        )
        return {
            "success": True,
            "provider": "clickup",
            "task": {
                "id": result.get("id"),
                "name": result.get("name"),
                "url": result.get("url"),
                "list_id": result.get("list", {}).get("id") if isinstance(result.get("list"), dict) else None,
            },
        }
    elif isinstance(client, GitHubClient):
        result = client.create_visibility_recommendation(
            title=title,
            description=description,
        )
        return {
            "success": True,
            "provider": "github",
            "project_item": {
                "id": result.get("id"),
                "note": result.get("note"),
                "url": result.get("url"),
                "project_id": result.get("project_id"),
            },
        }
    else:
        raise ValueError(f"Unsupported client type: {type(client)}")



def list_fine_tuning_recommendations(
    archived: bool = False,
    include_closed: bool = True,
    order_by: Optional[str] = None,
    reverse: bool = False,
    subtasks: bool = False,
    statuses: Optional[list[str]] = None,
    include_markdown_description: bool = False,
    client: Optional[Union[TrelloClient, ClickUpClient, GitHubClient]] = None,
) -> Dict[str, Any]:
    """
    List all fine-tuning recommendations.
    
    Currently only supports ClickUp. Trello and GitHub support can be added later.
    
    Args:
        archived: Include archived tasks (ClickUp only, default: False)
        include_closed: Include closed tasks (ClickUp only, default: True)
        order_by: Order tasks by field (ClickUp only)
        reverse: Reverse the order (ClickUp only, default: False)
        subtasks: Include subtasks (ClickUp only, default: False)
        statuses: Filter by status names (ClickUp only)
        include_markdown_description: Include markdown in descriptions (ClickUp only, default: False)
        client: TrelloClient, ClickUpClient, or GitHubClient instance (required)
    
    Returns:
        Dictionary with list of recommendations
    """
    if not client:
        raise ValueError("Engineering client (TrelloClient, ClickUpClient, or GitHubClient) is required")
    
    if isinstance(client, ClickUpClient):
        tasks = client.list_fine_tuning_recommendations(
            archived=archived,
            include_closed=include_closed,
            order_by=order_by,
            reverse=reverse,
            subtasks=subtasks,
            statuses=statuses,
            include_markdown_description=include_markdown_description,
        )
        return {
            "success": True,
            "provider": "clickup",
            "count": len(tasks),
            "tasks": [
                {
                    "id": task.get("id"),
                    "name": task.get("name"),
                    "url": task.get("url"),
                    "status": task.get("status", {}).get("status") if isinstance(task.get("status"), dict) else None,
                    "description": task.get("description", ""),
                }
                for task in tasks
            ],
        }
    else:
        raise ValueError(f"list_fine_tuning_recommendations is not supported for client type: {type(client)}")


def list_visibility_recommendations(
    archived: bool = False,
    include_closed: bool = True,
    order_by: Optional[str] = None,
    reverse: bool = False,
    subtasks: bool = False,
    statuses: Optional[list[str]] = None,
    include_markdown_description: bool = False,
    client: Optional[Union[TrelloClient, ClickUpClient, GitHubClient]] = None,
) -> Dict[str, Any]:
    """
    List all visibility/engineering recommendations.
    
    Currently only supports ClickUp. Trello and GitHub support can be added later.
    
    Args:
        archived: Include archived tasks (ClickUp only, default: False)
        include_closed: Include closed tasks (ClickUp only, default: True)
        order_by: Order tasks by field (ClickUp only)
        reverse: Reverse the order (ClickUp only, default: False)
        subtasks: Include subtasks (ClickUp only, default: False)
        statuses: Filter by status names (ClickUp only)
        include_markdown_description: Include markdown in descriptions (ClickUp only, default: False)
        client: TrelloClient, ClickUpClient, or GitHubClient instance (required)
    
    Returns:
        Dictionary with list of recommendations
    """
    if not client:
        raise ValueError("Engineering client (TrelloClient, ClickUpClient, or GitHubClient) is required")
    
    if isinstance(client, ClickUpClient):
        tasks = client.list_visibility_recommendations(
            archived=archived,
            include_closed=include_closed,
            order_by=order_by,
            reverse=reverse,
            subtasks=subtasks,
            statuses=statuses,
            include_markdown_description=include_markdown_description,
        )
        return {
            "success": True,
            "provider": "clickup",
            "count": len(tasks),
            "tasks": [
                {
                    "id": task.get("id"),
                    "name": task.get("name"),
                    "url": task.get("url"),
                    "status": task.get("status", {}).get("status") if isinstance(task.get("status"), dict) else None,
                    "description": task.get("description", ""),
                }
                for task in tasks
            ],
        }
    else:
        raise ValueError(f"list_visibility_recommendations is not supported for client type: {type(client)}")


def add_comment_to_fine_tuning_recommendation(
    task_id: str,
    comment_text: str,
    client: Optional[Union[TrelloClient, ClickUpClient, GitHubClient]] = None,
) -> Dict[str, Any]:
    """
    Add a comment to a fine-tuning recommendation task.
    
    Currently only supports ClickUp. Trello and GitHub support can be added later.
    
    Args:
        task_id: Task ID
        comment_text: Comment text/content
        client: TrelloClient, ClickUpClient, or GitHubClient instance (required)
    
    Returns:
        Dictionary with comment information
    """
    if not client:
        raise ValueError("Engineering client (TrelloClient, ClickUpClient, or GitHubClient) is required")
    
    if isinstance(client, ClickUpClient):
        comment = client.add_comment_to_fine_tuning_recommendation(
            task_id=task_id,
            comment_text=comment_text,
        )
        return {
            "success": True,
            "provider": "clickup",
            "comment": {
                "id": comment.get("id"),
                "comment_text": comment.get("comment", [{}])[0].get("text") if isinstance(comment.get("comment"), list) and comment.get("comment") else comment.get("comment_text", ""),
                "user": comment.get("user", {}).get("username") if isinstance(comment.get("user"), dict) else None,
            },
            "task_id": task_id,
            "message": f"Comment added to fine-tuning recommendation task {task_id}",
        }
    else:
        raise ValueError(f"add_comment_to_fine_tuning_recommendation is not supported for client type: {type(client)}")


def add_comment_to_visibility_recommendation(
    task_id: str,
    comment_text: str,
    client: Optional[Union[TrelloClient, ClickUpClient, GitHubClient]] = None,
) -> Dict[str, Any]:
    """
    Add a comment to a visibility/engineering recommendation task.
    
    Currently only supports ClickUp. Trello and GitHub support can be added later.
    
    Args:
        task_id: Task ID
        comment_text: Comment text/content
        client: TrelloClient, ClickUpClient, or GitHubClient instance (required)
    
    Returns:
        Dictionary with comment information
    """
    if not client:
        raise ValueError("Engineering client (TrelloClient, ClickUpClient, or GitHubClient) is required")
    
    if isinstance(client, ClickUpClient):
        comment = client.add_comment_to_visibility_recommendation(
            task_id=task_id,
            comment_text=comment_text,
        )
        return {
            "success": True,
            "provider": "clickup",
            "comment": {
                "id": comment.get("id"),
                "comment_text": comment.get("comment", [{}])[0].get("text") if isinstance(comment.get("comment"), list) and comment.get("comment") else comment.get("comment_text", ""),
                "user": comment.get("user", {}).get("username") if isinstance(comment.get("user"), dict) else None,
            },
            "task_id": task_id,
            "message": f"Comment added to visibility recommendation task {task_id}",
        }
    else:
        raise ValueError(f"add_comment_to_visibility_recommendation is not supported for client type: {type(client)}")
