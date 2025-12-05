"""
MCP (Model Context Protocol) server for SamiGPT.

This module implements an MCP server that exposes all investigation and
response skills as tools that can be invoked by LLM clients like Open WebUI,
Claude Desktop, Cline, etc.

The server implements JSON-RPC 2.0 over stdio as specified in the MCP protocol.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import warnings
from typing import Any, Dict, List, Optional, Union

# Suppress urllib3 warnings that go to stderr (which can confuse MCP clients)
warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")

from ..api.case_management import CaseManagementClient, CaseSearchQuery
from ..api.edr import EDRClient
from ..api.siem import SIEMClient
from ..api.kb import KBClient
from ..core.config import SamiConfig
from ..core.logging import configure_logging, get_logger
from ..integrations.case_management.iris.iris_client import (
    IRISCaseManagementClient,
)
from ..integrations.case_management.thehive.thehive_client import (
    TheHiveCaseManagementClient,
)
from ..integrations.siem.elastic.elastic_client import ElasticSIEMClient
from ..integrations.edr.elastic_defend.elastic_defend_client import ElasticDefendEDRClient
from ..integrations.cti.local_tip.local_tip_client import LocalTipCTIClient
from ..integrations.cti.opencti.opencti_client import OpenCTIClient
from ..integrations.kb import FileSystemKBClient
from ..integrations.eng.trello.trello_client import TrelloClient
from ..integrations.eng.clickup.clickup_client import ClickUpClient
from ..integrations.eng.github.github_client import GitHubClient
from ..orchestrator import tools_case, tools_cti, tools_edr, tools_siem, tools_kb, tools_eng
from .rules_engine import RulesEngine
from .agent_profiles import AgentProfileManager
from .runbook_manager import RunbookManager

logger = get_logger(__name__)


def configure_mcp_logging(log_dir: str = "logs") -> None:
    """
    Configure dedicated logging for the MCP server in its own directory.
    
    Creates logs/mcp/ directory with:
    - mcp_requests.log: All incoming requests
    - mcp_responses.log: All outgoing responses  
    - mcp_errors.log: All errors
    - mcp_all.log: Everything (for complete debugging)
    
    Args:
        log_dir: Base log directory (default: "logs")
    """
    mcp_log_dir = os.path.join(log_dir, "mcp")
    os.makedirs(mcp_log_dir, exist_ok=True)
    
    # Get or create MCP-specific logger
    mcp_logger = logging.getLogger("sami.mcp")
    mcp_logger.setLevel(logging.DEBUG)
    
    # Avoid duplicate handlers
    if getattr(mcp_logger, "_mcp_logging_configured", False):
        return
    
    # Detailed formatter with more context
    detailed_formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s [%(funcName)s:%(lineno)d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    
    # All MCP logs (everything)
    all_handler = logging.FileHandler(os.path.join(mcp_log_dir, "mcp_all.log"))
    all_handler.setLevel(logging.DEBUG)
    all_handler.setFormatter(detailed_formatter)
    
    # Requests log
    requests_handler = logging.FileHandler(os.path.join(mcp_log_dir, "mcp_requests.log"))
    requests_handler.setLevel(logging.INFO)
    requests_handler.setFormatter(detailed_formatter)
    
    # Responses log
    responses_handler = logging.FileHandler(os.path.join(mcp_log_dir, "mcp_responses.log"))
    responses_handler.setLevel(logging.INFO)
    responses_handler.setFormatter(detailed_formatter)
    
    # Errors log
    errors_handler = logging.FileHandler(os.path.join(mcp_log_dir, "mcp_errors.log"))
    errors_handler.setLevel(logging.ERROR)
    errors_handler.setFormatter(detailed_formatter)
    
    # Add custom filters for requests/responses based on message prefixes
    class RequestFilter(logging.Filter):
        def filter(self, record):
            msg = record.getMessage().upper()
            return "REQUEST" in msg or "EXECUTING" in msg
    
    class ResponseFilter(logging.Filter):
        def filter(self, record):
            msg = record.getMessage().upper()
            return "RESPONSE" in msg or record.levelno >= logging.ERROR
    
    requests_handler.addFilter(RequestFilter())
    responses_handler.addFilter(ResponseFilter())
    
    mcp_logger.addHandler(all_handler)
    mcp_logger.addHandler(requests_handler)
    mcp_logger.addHandler(responses_handler)
    mcp_logger.addHandler(errors_handler)
    
    # Mark as configured
    mcp_logger._mcp_logging_configured = True  # type: ignore[attr-defined]
    
    logger.info(f"MCP dedicated logging configured in: {mcp_log_dir}")


class SamiGPTMCPServer:
    """
    MCP server that exposes SamiGPT investigation skills as tools.
    
    Implements the Model Context Protocol (MCP) specification using
    JSON-RPC 2.0 over stdio.
    """

    # MCP protocol version - support both old and new versions
    PROTOCOL_VERSION = "2024-11-05"
    SUPPORTED_PROTOCOL_VERSIONS = ["2024-11-05", "2025-06-18"]
    
    # Server info
    SERVER_NAME = "sami-gpt"
    SERVER_VERSION = "1.0.0"

    def __init__(
        self,
        case_client: Optional[CaseManagementClient] = None,
        siem_client: Optional[SIEMClient] = None,
        edr_client: Optional[EDRClient] = None,
        cti_client: Optional[Any] = None,
        cti_clients: Optional[list] = None,
        kb_client: Optional[KBClient] = None,
        eng_client: Optional[Union[TrelloClient, ClickUpClient, GitHubClient]] = None,
    ):
        """
        Initialize the MCP server.

        Args:
            case_client: Case management client.
            siem_client: SIEM client.
            edr_client: EDR client.
            cti_client: CTI (Cyber Threat Intelligence) client (single, for backward compatibility).
            cti_clients: List of CTI clients (for multi-platform support).
        """
        self.case_client = case_client
        self.siem_client = siem_client
        self.edr_client = edr_client
        # Support both single client (backward compat) and multiple clients
        if cti_clients is not None:
            self.cti_clients = cti_clients
            self.cti_client = cti_clients[0] if cti_clients else None  # For backward compatibility
        else:
            self.cti_clients = [cti_client] if cti_client else []
            self.cti_client = cti_client
        # KB client defaults to filesystem-based client so it is always available
        self.kb_client: KBClient = kb_client or FileSystemKBClient()
        self.eng_client = eng_client
        self.rules_engine = RulesEngine(
            case_client=case_client,
            siem_client=siem_client,
            edr_client=edr_client,
        )
        self.agent_profile_manager = AgentProfileManager()
        self.runbook_manager = RunbookManager()
        # Track which agent profiles have already shown their SOC tier guidelines
        self._shown_agent_guidelines: Dict[str, bool] = {}
        self._initialized = False
        self._mcp_logger = logging.getLogger("sami.mcp")
        self._register_tools()

    def _register_tools(self) -> None:
        """Register all available tools."""
        self.tools: Dict[str, Dict[str, Any]] = {}

        # Case management tools
        self._register_case_tools()
        # SIEM tools
        self._register_siem_tools()
        # EDR tools
        self._register_edr_tools()
        # CTI tools
        self._register_cti_tools()
        # Rules engine tools
        self._register_rules_tools()
        # Runbook and agent profile tools
        self._register_runbook_tools()
        self._register_agent_profile_tools()
        # Knowledge base tools (client infrastructure)
        self._register_kb_tools()
        # Engineering tools (Trello)
        self._register_eng_tools()

    def _register_kb_tools(self) -> None:
        """
        Register knowledge base tools for client infrastructure.

        Available tools:
        - kb_list_clients: List available client environments based on client_env/*
        - kb_get_client_infra: Load and summarize infrastructure for a given client.
        """
        if not self.kb_client:
            self._mcp_logger.warning(
                "KB tools not registered: No KB client configured."
            )
            return

        self._mcp_logger.info("Registering 2 KB tools (client infrastructure)")

        self.tools["kb_list_clients"] = {
            "name": "kb_list_clients",
            "description": "List available client environments based on folders under client_env/*.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            },
        }

        self.tools["kb_get_client_infra"] = {
            "name": "kb_get_client_infra",
            "description": "Load and summarize client infrastructure (subnets, servers, users, naming schemas, env rules) from client_env/*.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "client_name": {
                        "type": "string",
                        "description": "Name of the client environment (e.g., 'acme_corp_client' or 'acme_corp').",
                    }
                },
                "required": ["client_name"],
            },
        }

    def _register_eng_tools(self) -> None:
        """
        Register engineering tools (Trello/ClickUp/GitHub).
        
        Available tools:
        - create_fine_tuning_recommendation: Create a fine-tuning recommendation (supports Trello, ClickUp, and GitHub)
        - create_visibility_recommendation: Create a visibility/engineering recommendation (supports Trello, ClickUp, and GitHub)
        - list_fine_tuning_recommendations: List all fine-tuning recommendations (ClickUp only)
        - list_visibility_recommendations: List all visibility/engineering recommendations (ClickUp only)
        - add_comment_to_fine_tuning_recommendation: Add a comment to a fine-tuning recommendation task (ClickUp only)
        - add_comment_to_visibility_recommendation: Add a comment to a visibility recommendation task (ClickUp only)
        """
        if not self.eng_client:
            self._mcp_logger.warning(
                "Engineering tools not registered: No engineering client configured. "
                "Configure Trello, ClickUp, or GitHub in config.json to enable engineering tools."
            )
            return

        self._mcp_logger.info("Registering 6 engineering tools (Trello/ClickUp/GitHub)")

        self.tools["create_fine_tuning_recommendation"] = {
            "name": "create_fine_tuning_recommendation",
            "description": "Create a fine-tuning recommendation on the fine-tuning board (supports Trello, ClickUp, and GitHub)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Task/card title"
                    },
                    "description": {
                        "type": "string",
                        "description": "Task/card description"
                    },
                    "list_name": {
                        "type": "string",
                        "description": "Optional list name (Trello only, defaults to first list on board)"
                    },
                    "labels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of label names (Trello only)"
                    },
                    "status": {
                        "type": "string",
                        "description": "Optional status name (ClickUp only, defaults to first status in list)"
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of tag names (ClickUp only)"
                    }
                },
                "required": ["title", "description"]
            }
        }

        self.tools["create_visibility_recommendation"] = {
            "name": "create_visibility_recommendation",
            "description": "Create a visibility/engineering recommendation on the engineering board (supports Trello, ClickUp, and GitHub)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Task/card title"
                    },
                    "description": {
                        "type": "string",
                        "description": "Task/card description"
                    },
                    "list_name": {
                        "type": "string",
                        "description": "Optional list name (Trello only, defaults to first list on board)"
                    },
                    "labels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of label names (Trello only)"
                    },
                    "status": {
                        "type": "string",
                        "description": "Optional status name (ClickUp only, defaults to first status in list)"
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of tag names (ClickUp only)"
                    }
                },
                "required": ["title", "description"]
            }
        }

        self.tools["list_fine_tuning_recommendations"] = {
            "name": "list_fine_tuning_recommendations",
            "description": "List all fine-tuning recommendation tasks from the fine-tuning board (ClickUp only)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "archived": {
                        "type": "boolean",
                        "description": "Include archived tasks (default: False)"
                    },
                    "include_closed": {
                        "type": "boolean",
                        "description": "Include closed tasks (default: True)"
                    },
                    "order_by": {
                        "type": "string",
                        "description": "Order tasks by field (e.g., 'created', 'updated', 'priority')"
                    },
                    "reverse": {
                        "type": "boolean",
                        "description": "Reverse the order (default: False)"
                    },
                    "subtasks": {
                        "type": "boolean",
                        "description": "Include subtasks (default: False)"
                    },
                    "statuses": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by status names"
                    },
                    "include_markdown_description": {
                        "type": "boolean",
                        "description": "Include markdown in descriptions (default: False)"
                    }
                },
                "required": []
            }
        }

        self.tools["list_visibility_recommendations"] = {
            "name": "list_visibility_recommendations",
            "description": "List all visibility/engineering recommendation tasks from the engineering board (ClickUp only)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "archived": {
                        "type": "boolean",
                        "description": "Include archived tasks (default: False)"
                    },
                    "include_closed": {
                        "type": "boolean",
                        "description": "Include closed tasks (default: True)"
                    },
                    "order_by": {
                        "type": "string",
                        "description": "Order tasks by field (e.g., 'created', 'updated', 'priority')"
                    },
                    "reverse": {
                        "type": "boolean",
                        "description": "Reverse the order (default: False)"
                    },
                    "subtasks": {
                        "type": "boolean",
                        "description": "Include subtasks (default: False)"
                    },
                    "statuses": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by status names"
                    },
                    "include_markdown_description": {
                        "type": "boolean",
                        "description": "Include markdown in descriptions (default: False)"
                    }
                },
                "required": []
            }
        }

        self.tools["add_comment_to_fine_tuning_recommendation"] = {
            "name": "add_comment_to_fine_tuning_recommendation",
            "description": "Add a comment to a fine-tuning recommendation task (ClickUp only)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "ClickUp task ID"
                    },
                    "comment_text": {
                        "type": "string",
                        "description": "Comment text/content"
                    }
                },
                "required": ["task_id", "comment_text"]
            }
        }

        self.tools["add_comment_to_visibility_recommendation"] = {
            "name": "add_comment_to_visibility_recommendation",
            "description": "Add a comment to a visibility/engineering recommendation task (ClickUp only)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "ClickUp task ID"
                    },
                    "comment_text": {
                        "type": "string",
                        "description": "Comment text/content"
                    }
                },
                "required": ["task_id", "comment_text"]
            }
        }

    def _register_case_tools(self) -> None:
        """
        Register case management tools.
        
        Available tools:
        - create_case: Create a new case for investigation
        - review_case: Retrieve full case details including observables and timeline
        - list_cases: List cases optionally filtered by status
        - search_cases: Search cases using multiple filters (text, status, priority, tags, assignee)
        - update_case: Update case with new information (title, description, priority, status, tags, assignee)
        - add_case_comment: Add comments/notes to cases
        - attach_observable_to_case: Attach IOCs (IPs, hashes, domains, URLs) to cases
        - update_case_status: Update case status (open, in_progress, closed)
        - assign_case: Assign cases to analysts
        - get_case_timeline: Retrieve chronological timeline of case events
        - add_case_timeline_event: Add an event to a case timeline
        - list_case_timeline_events: List all timeline events for a case
        - link_cases: Link two cases together
        - add_case_task: Add a task to a case
        - list_case_tasks: List all tasks for a case
        - add_case_asset: Add an asset to a case
        - list_case_assets: List all assets for a case
        - add_case_evidence: Upload and attach evidence to a case
        - list_case_evidence: List all evidence files for a case
        
        See TOOLS.md for detailed documentation and usage examples.
        """
        if not self.case_client:
            self._mcp_logger.warning(
                "Case management tools not registered: No case management client configured. "
                "Configure TheHive or IRIS in config.json to enable case management tools."
            )
            return
        self._mcp_logger.info(f"Registering {19} case management tools")

        self.tools["create_case"] = {
            "name": "create_case",
            "description": "Create a new case for investigation. Follows the case standard format defined in standards/case_standard.md. Use this when triaging an alert and no case exists yet.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Case title following format: [Alert Type] - [Primary Entity] - [Date/Time]. Example: 'Malware Detection - 10.10.1.2 - 2025-11-18'"
                    },
                    "description": {
                        "type": "string",
                        "description": "Comprehensive case description including alert details, initial assessment, key entities, and severity justification"
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Case priority based on severity, impact, and IOC matches. Default: medium"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["open", "in_progress", "closed"],
                        "description": "Case status. New cases should start as 'open'. Default: open"
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tags for categorization (e.g., ['malware', 'suspicious-login', 'ioc-match', 'soc1-triage'])"
                    },
                    "alert_id": {
                        "type": "string",
                        "description": "Associated alert ID if case is created from an alert"
                    }
                },
                "required": ["title", "description"]
            },
        }
        
        self.tools["review_case"] = {
            "name": "review_case",
            "description": "Retrieve and review the full details of a case including title, description, status, priority, observables, and comments.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "The ID of the case to review",
                    }
                },
                "required": ["case_id"],
            },
        }

        self.tools["list_cases"] = {
            "name": "list_cases",
            "description": "List cases from the case management system, optionally filtered by status (open, in_progress, closed).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["open", "in_progress", "closed"],
                        "description": "Filter by status",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of cases to return",
                        "default": 50,
                    },
                },
            },
        }

        self.tools["search_cases"] = {
            "name": "search_cases",
            "description": "Search for cases using text search, status, priority, tags, or assignee filters.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to search for"},
                    "status": {
                        "type": "string",
                        "enum": ["open", "in_progress", "closed"],
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tags to filter by",
                    },
                    "assignee": {"type": "string", "description": "Assignee to filter by"},
                    "limit": {"type": "integer", "default": 50},
                },
            },
        }

        self.tools["add_case_comment"] = {
            "name": "add_case_comment",
            "description": "Add a comment or note to a case.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "The ID of the case"},
                    "content": {
                        "type": "string",
                        "description": "The comment content",
                    },
                    "author": {"type": "string", "description": "The author of the comment"},
                },
                "required": ["case_id", "content"],
            },
        }

        self.tools["attach_observable_to_case"] = {
            "name": "attach_observable_to_case",
            "description": "Attach an observable such as an IP address, file hash, domain, or URL to a case for tracking and analysis.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "The ID of the case"},
                    "observable_type": {
                        "type": "string",
                        "description": "Type of observable (ip, hash, domain, url, etc.)",
                    },
                    "observable_value": {
                        "type": "string",
                        "description": "The value of the observable",
                    },
                    "description": {
                        "type": "string",
                        "description": "Description of the observable",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tags for the observable",
                    },
                },
                "required": ["case_id", "observable_type", "observable_value"],
            },
        }

        self.tools["update_case_status"] = {
            "name": "update_case_status",
            "description": "Update the status of a case (open, in_progress, closed).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "The ID of the case"},
                    "status": {
                        "type": "string",
                        "enum": ["open", "in_progress", "closed"],
                        "description": "New status",
                    },
                },
                "required": ["case_id", "status"],
            },
        }

        self.tools["assign_case"] = {
            "name": "assign_case",
            "description": "Assign a case to a specific user or analyst.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "The ID of the case"},
                    "assignee": {
                        "type": "string",
                        "description": "The username or ID of the assignee",
                    },
                },
                "required": ["case_id", "assignee"],
            },
        }

        self.tools["get_case_timeline"] = {
            "name": "get_case_timeline",
            "description": "Retrieve the timeline of comments and events for a case, ordered chronologically.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "The ID of the case",
                    }
                },
                "required": ["case_id"],
            },
        }
        
        # Task management tools
        self.tools["add_case_task"] = {
            "name": "add_case_task",
            "description": "Add a task to a case. Tasks represent actionable items for investigation and response, typically assigned to SOC2 or SOC3 tiers.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "The ID of the case"
                    },
                    "title": {
                        "type": "string",
                        "description": "Task title"
                    },
                    "description": {
                        "type": "string",
                        "description": "Task description"
                    },
                    "assignee": {
                        "type": "string",
                        "description": "Assignee ID or SOC tier (e.g., 'SOC2', 'SOC3')"
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Task priority. Default: medium"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["pending", "in_progress", "completed", "blocked"],
                        "description": "Task status. Default: pending"
                    }
                },
                "required": ["case_id", "title", "description"]
            }
        }
        
        self.tools["list_case_tasks"] = {
            "name": "list_case_tasks",
            "description": "List all tasks associated with a case",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "The ID of the case"
                    }
                },
                "required": ["case_id"]
            }
        }
        
        self.tools["update_case_task_status"] = {
            "name": "update_case_task_status",
            "description": "Update the status of a task (pending, in_progress, completed, blocked). Use this to mark tasks as in-progress when starting work and completed when finishing.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "The ID of the case"
                    },
                    "task_id": {
                        "type": "string",
                        "description": "The ID of the task to update"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["pending", "in_progress", "completed", "blocked"],
                        "description": "New task status"
                    }
                },
                "required": ["case_id", "task_id", "status"]
            }
        }
        
        # Asset management tools
        self.tools["add_case_asset"] = {
            "name": "add_case_asset",
            "description": "Add an asset (endpoint, server, network, user account, application) to a case",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "The ID of the case"
                    },
                    "asset_name": {
                        "type": "string",
                        "description": "Asset name/identifier"
                    },
                    "asset_type": {
                        "type": "string",
                        "enum": ["endpoint", "server", "network", "user_account", "application"],
                        "description": "Asset type"
                    },
                    "description": {
                        "type": "string",
                        "description": "Asset description"
                    },
                    "ip_address": {
                        "type": "string",
                        "description": "IP address if applicable"
                    },
                    "hostname": {
                        "type": "string",
                        "description": "Hostname if applicable"
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tags for the asset"
                    }
                },
                "required": ["case_id", "asset_name", "asset_type"]
            }
        }
        
        self.tools["list_case_assets"] = {
            "name": "list_case_assets",
            "description": "List all assets associated with a case",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "The ID of the case"
                    }
                },
                "required": ["case_id"]
            }
        }
        
        # Evidence management tools
        self.tools["add_case_evidence"] = {
            "name": "add_case_evidence",
            "description": "Upload and attach evidence (file, log, screenshot, network capture, etc.) to a case",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "The ID of the case"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Path to the evidence file"
                    },
                    "description": {
                        "type": "string",
                        "description": "Description of the evidence"
                    },
                    "evidence_type": {
                        "type": "string",
                        "enum": ["file", "screenshot", "log", "network_capture", "memory_dump", "registry", "other"],
                        "description": "Type of evidence"
                    }
                },
                "required": ["case_id", "file_path"]
            }
        }
        
        self.tools["list_case_evidence"] = {
            "name": "list_case_evidence",
            "description": "List all evidence files associated with a case",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "The ID of the case"
                    }
                },
                "required": ["case_id"]
            }
        }

        self.tools["update_case"] = {
            "name": "update_case",
            "description": "Update a case with new information (title, description, priority, status, tags, assignee)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "The ID of the case to update"
                    },
                    "title": {
                        "type": "string",
                        "description": "New case title"
                    },
                    "description": {
                        "type": "string",
                        "description": "New case description"
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "New priority"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["open", "in_progress", "closed"],
                        "description": "New status"
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "New tags list"
                    },
                    "assignee": {
                        "type": "string",
                        "description": "New assignee"
                    }
                },
                "required": ["case_id"]
            }
        }

        self.tools["link_cases"] = {
            "name": "link_cases",
            "description": "Link two cases together to indicate a relationship (e.g., duplicate, related, escalated from)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source_case_id": {
                        "type": "string",
                        "description": "The ID of the source case"
                    },
                    "target_case_id": {
                        "type": "string",
                        "description": "The ID of the target case to link to"
                    },
                    "link_type": {
                        "type": "string",
                        "description": "Type of link (related_to, duplicate_of, escalated_from, child_of, blocked_by)",
                        "default": "related_to"
                    }
                },
                "required": ["source_case_id", "target_case_id"]
            }
        }

        self.tools["add_case_timeline_event"] = {
            "name": "add_case_timeline_event",
            "description": "Add an event to a case timeline for tracking investigation activities and milestones",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "The ID of the case"
                    },
                    "title": {
                        "type": "string",
                        "description": "Event title"
                    },
                    "content": {
                        "type": "string",
                        "description": "Event content/description"
                    },
                    "source": {
                        "type": "string",
                        "description": "Event source (e.g., 'SamiGPT', 'SIEM', 'EDR')"
                    },
                    "category_id": {
                        "type": "integer",
                        "description": "Event category ID"
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Event tags"
                    },
                    "color": {
                        "type": "string",
                        "description": "Event color (hex format, e.g., '#1572E899')"
                    },
                    "event_date": {
                        "type": "string",
                        "description": "Event date in ISO format (defaults to current time)"
                    },
                    "include_in_summary": {
                        "type": "boolean",
                        "description": "Include event in case summary",
                        "default": True
                    },
                    "include_in_graph": {
                        "type": "boolean",
                        "description": "Include event in case graph",
                        "default": True
                    },
                    "sync_iocs_assets": {
                        "type": "boolean",
                        "description": "Sync with IOCs and assets",
                        "default": True
                    },
                    "asset_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Related asset IDs"
                    },
                    "ioc_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Related IOC IDs"
                    },
                    "custom_attributes": {
                        "type": "object",
                        "description": "Custom attributes"
                    },
                    "raw": {
                        "type": "string",
                        "description": "Raw event data"
                    },
                    "tz": {
                        "type": "string",
                        "description": "Timezone",
                        "default": "+00:00"
                    }
                },
                "required": ["case_id", "title", "content"]
            }
        }

        self.tools["list_case_timeline_events"] = {
            "name": "list_case_timeline_events",
            "description": "List all timeline events associated with a case",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "The ID of the case"
                    }
                },
                "required": ["case_id"]
            }
        }

    def _register_siem_tools(self) -> None:
        """
        Register SIEM tools.
        
        Available tools:
        - search_security_events: Search security events using vendor-specific query language
        - get_file_report: Get aggregated report about a file by hash
        - get_file_behavior_summary: Get behavior analysis (process trees, network activity, persistence)
        - get_entities_related_to_file: Get related entities (hosts, users, processes, alerts)
        - get_ip_address_report: Get IP reputation, geolocation, and related alerts
        - search_user_activity: Search security events related to a specific user
        - pivot_on_indicator: Search for all events related to an IOC (hash, IP, domain, etc.)
        - search_kql_query: Execute KQL or advanced queries for deeper investigations
        
        See TOOLS.md for detailed documentation and usage examples.
        """
        if not self.siem_client:
            self._mcp_logger.warning(
                "SIEM tools not registered: No SIEM client configured. "
                "Configure Elastic or other SIEM in config.json to enable SIEM tools."
            )
            return
        self._mcp_logger.info(f"Registering {26} SIEM tools")

        self.tools["search_security_events"] = {
            "name": "search_security_events",
            "description": "Search security events and logs across all environments using a query string.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (vendor-specific query language)",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of events to return",
                        "default": 100,
                    },
                },
                "required": ["query"],
            },
        }

        self.tools["get_file_report"] = {
            "name": "get_file_report",
            "description": "Retrieve an aggregated report about a file identified by its hash.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_hash": {
                        "type": "string",
                        "description": "The file hash (MD5, SHA256, etc.)",
                    }
                },
                "required": ["file_hash"],
            },
        }

        self.tools["get_file_behavior_summary"] = {
            "name": "get_file_behavior_summary",
            "description": "Retrieve a high-level behavior summary for a file, including process trees, network activity, and persistence mechanisms.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_hash": {"type": "string", "description": "The file hash"}
                },
                "required": ["file_hash"],
            },
        }

        self.tools["get_entities_related_to_file"] = {
            "name": "get_entities_related_to_file",
            "description": "Retrieve entities related to a file hash, such as hosts where it was seen, users who executed it, related processes, and alerts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_hash": {"type": "string", "description": "The file hash"}
                },
                "required": ["file_hash"],
            },
        }

        self.tools["get_ip_address_report"] = {
            "name": "get_ip_address_report",
            "description": "Retrieve an aggregated report about an IP address, including reputation, geolocation, and related alerts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "The IP address"}
                },
                "required": ["ip"],
            },
        }

        self.tools["search_user_activity"] = {
            "name": "search_user_activity",
            "description": "Search for security events related to a specific user, including authentication events, file access, and other activities.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "The username to search for",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of events to return",
                        "default": 100,
                    },
                },
                "required": ["username"],
            },
        }

        self.tools["pivot_on_indicator"] = {
            "name": "pivot_on_indicator",
            "description": "Given an IOC (file hash, IP address, domain, etc.), search for all related security events across environments for further investigation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "indicator": {
                        "type": "string",
                        "description": "The IOC (hash, IP, domain, etc.)",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of events to return",
                        "default": 200,
                    },
                },
                "required": ["indicator"],
            },
        }

        self.tools["search_kql_query"] = {
            "name": "search_kql_query",
            "description": "Execute a KQL (Kusto Query Language) or advanced query for deeper investigations. Supports complex queries including advanced filtering, aggregations, time-based analysis, cross-index searches, and complex joins. Supports both KQL syntax and vendor-specific query DSL (e.g., Elasticsearch Query DSL).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "kql_query": {
                        "type": "string",
                        "description": "KQL query string or advanced query DSL (JSON for Elasticsearch)",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of events to return",
                        "default": 500,
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "Optional time window in hours to limit the search",
                    },
                },
                "required": ["kql_query"],
            },
        }

        # Alert summarization / grouping tool
        self.tools["get_recent_alerts"] = {
            "name": "get_recent_alerts",
            "description": "Get recent SIEM alerts (last N hours) and smart-group similar alerts together for AI triage.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hours_back": {
                        "type": "integer",
                        "description": "How many hours to look back for alerts",
                        "default": 1,
                    },
                    "max_alerts": {
                        "type": "integer",
                        "description": "Maximum number of alerts to retrieve before grouping",
                        "default": 100,
                    },
                    "status_filter": {
                        "type": "string",
                        "description": "Filter by alert status (implementation-specific string filter)",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity (low, medium, high, critical)",
                    },
                    "hostname": {
                        "type": "string",
                        "description": "Filter alerts by hostname (matches host.name field)",
                    },
                },
            },
        }

        # Network and DNS Event Tools
        self.tools["get_network_events"] = {
            "name": "get_network_events",
            "description": "Retrieve network traffic events (firewall, netflow, proxy logs) with structured fields for analysis. Returns network events with source/destination IPs, ports, protocols, bytes, packets, and connection duration.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source_ip": {
                        "type": "string",
                        "description": "Source IP address",
                    },
                    "destination_ip": {
                        "type": "string",
                        "description": "Destination IP address",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port number",
                    },
                    "protocol": {
                        "type": "string",
                        "description": "Protocol (tcp, udp, icmp, etc.)",
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "Time window in hours",
                        "default": 24,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of events to return",
                        "default": 100,
                    },
                    "event_type": {
                        "type": "string",
                        "description": "Filter by event type (firewall, netflow, proxy, all)",
                    },
                },
            },
        }

        self.tools["get_dns_events"] = {
            "name": "get_dns_events",
            "description": "Retrieve DNS query and response events with structured fields for analysis. Returns DNS events with domain, query type, resolved IP, source IP, and response codes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name queried",
                    },
                    "ip_address": {
                        "type": "string",
                        "description": "IP that made the query",
                    },
                    "resolved_ip": {
                        "type": "string",
                        "description": "Resolved IP address",
                    },
                    "query_type": {
                        "type": "string",
                        "description": "DNS query type (A, AAAA, MX, TXT, etc.)",
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "Time window in hours",
                        "default": 24,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of events to return",
                        "default": 100,
                    },
                },
            },
        }

        # Alert Correlation Tools
        self.tools["get_alerts_by_entity"] = {
            "name": "get_alerts_by_entity",
            "description": "Retrieve alerts filtered by specific entity (IP, user, host, domain, hash) for correlation analysis. Returns alerts that contain the specified entity.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "entity_value": {
                        "type": "string",
                        "description": "Entity value (IP, user, hostname, domain, hash)",
                    },
                    "entity_type": {
                        "type": "string",
                        "description": "Entity type (auto-detected if not provided: ip, user, host, domain, hash)",
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "Lookback period in hours",
                        "default": 24,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of alerts to return",
                        "default": 50,
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity (low, medium, high, critical)",
                    },
                },
                "required": ["entity_value"],
            },
        }

        self.tools["get_alerts_by_time_window"] = {
            "name": "get_alerts_by_time_window",
            "description": "Retrieve alerts within a specific time window for temporal correlation. Returns alerts that occurred between start_time and end_time.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "start_time": {
                        "type": "string",
                        "description": "Start time (ISO format)",
                    },
                    "end_time": {
                        "type": "string",
                        "description": "End time (ISO format)",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of alerts to return",
                        "default": 100,
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity",
                    },
                    "alert_type": {
                        "type": "string",
                        "description": "Filter by alert type",
                    },
                },
                "required": ["start_time", "end_time"],
            },
        }

        self.tools["get_all_uncertain_alerts_for_host"] = {
            "name": "get_all_uncertain_alerts_for_host",
            "description": "Retrieve all alerts with verdict='uncertain' for a specific host. This is useful for pattern analysis when investigating uncertain alerts to determine if multiple uncertain alerts on the same host indicate a broader issue requiring case creation and escalation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "The hostname to search for",
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "How many hours to look back (default: 168 = 7 days)",
                        "default": 168,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of alerts to return",
                        "default": 100,
                    },
                },
                "required": ["hostname"],
            },
        }

        # Email Security Tools
        self.tools["get_email_events"] = {
            "name": "get_email_events",
            "description": "Retrieve email security events with structured fields for phishing analysis. Returns email events with sender, recipient, subject, headers, authentication, URLs, and attachments.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sender_email": {
                        "type": "string",
                        "description": "Sender email address",
                    },
                    "recipient_email": {
                        "type": "string",
                        "description": "Recipient email address",
                    },
                    "subject": {
                        "type": "string",
                        "description": "Email subject (partial match)",
                    },
                    "email_id": {
                        "type": "string",
                        "description": "Email message ID",
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "Time window in hours",
                        "default": 24,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of events to return",
                        "default": 100,
                    },
                    "event_type": {
                        "type": "string",
                        "description": "Filter by event type (delivered, blocked, quarantined, all)",
                    },
                },
            },
        }

        # Alert Management Tools
        self.tools["get_security_alerts"] = {
            "name": "get_security_alerts",
            "description": "Get security alerts directly from the SIEM platform.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hours_back": {
                        "type": "integer",
                        "description": "How many hours to look back",
                        "default": 24,
                    },
                    "max_alerts": {
                        "type": "integer",
                        "description": "Maximum number of alerts to return",
                        "default": 10,
                    },
                    "status_filter": {
                        "type": "string",
                        "description": "Filter by status",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity (low, medium, high, critical)",
                    },
                },
            },
        }

        self.tools["get_security_alert_by_id"] = {
            "name": "get_security_alert_by_id",
            "description": "Get detailed information about a specific security alert by its ID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "The ID of the alert",
                    },
                    "include_detections": {
                        "type": "boolean",
                        "description": "Whether to include detection details",
                        "default": True,
                    },
                },
                "required": ["alert_id"],
            },
        }

        self.tools["get_siem_event_by_id"] = {
            "name": "get_siem_event_by_id",
            "description": "Retrieve a specific security event by its unique identifier (event ID). This tool allows you to get the exact event details when you know the event ID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "event_id": {
                        "type": "string",
                        "description": "The unique identifier of the event to retrieve",
                    },
                },
                "required": ["event_id"],
            },
        }

        self.tools["close_alert"] = {
            "name": "close_alert",
            "description": "Close a security alert in the SIEM platform. Use this when an alert has been determined to be a false positive or benign true positive during triage.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "The ID of the alert to close",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for closing (e.g., 'false_positive', 'benign_true_positive')",
                    },
                    "comment": {
                        "type": "string",
                        "description": "Comment explaining why the alert is being closed",
                    },
                },
                "required": ["alert_id"],
            },
        }

        self.tools["update_alert_verdict"] = {
            "name": "update_alert_verdict",
            "description": "Update the verdict for a security alert. Use this to set or update the verdict field (e.g., 'in-progress', 'false_positive', 'benign_true_positive', 'true_positive', 'uncertain'). This is the preferred method for setting verdicts as it clearly indicates the intent to update the verdict rather than close the alert.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "The ID of the alert to update",
                    },
                    "verdict": {
                        "type": "string",
                        "description": "The verdict value. Valid values: 'in-progress', 'false_positive', 'benign_true_positive', 'true_positive', 'uncertain'",
                        "enum": ["in-progress", "false_positive", "benign_true_positive", "true_positive", "uncertain"],
                    },
                    "comment": {
                        "type": "string",
                        "description": "Optional comment explaining the verdict",
                    },
                },
                "required": ["alert_id", "verdict"],
            },
        }

        self.tools["tag_alert"] = {
            "name": "tag_alert",
            "description": "Tag a security alert in the SIEM platform with a classification. Use this to mark alerts as FP (False Positive), TP (True Positive), or NMI (Need More Investigation).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "The ID of the alert to tag",
                    },
                    "tag": {
                        "type": "string",
                        "description": "The tag to apply. Must be one of: 'FP' (False Positive), 'TP' (True Positive), or 'NMI' (Need More Investigation)",
                        "enum": ["FP", "TP", "NMI"],
                    },
                },
                "required": ["alert_id", "tag"],
            },
        }

        self.tools["add_alert_note"] = {
            "name": "add_alert_note",
            "description": "Add a note or comment to a security alert in the SIEM platform. Use this to document investigation findings, recommendations for detection rule improvements, case numbers, or other relevant information about the alert.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "The ID of the alert to add a note to",
                    },
                    "note": {
                        "type": "string",
                        "description": "The note/comment text to add. Should include investigation findings, case numbers (if applicable), and recommendations for detection rule improvements.",
                    },
                },
                "required": ["alert_id", "note"],
            },
        }

        # Entity & Intelligence Tools
        self.tools["lookup_entity"] = {
            "name": "lookup_entity",
            "description": "Look up an entity (IP address, domain, hash, user, etc.) in the SIEM for enrichment.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "entity_value": {
                        "type": "string",
                        "description": "Value to look up",
                    },
                    "entity_type": {
                        "type": "string",
                        "description": "Type of entity (ip, domain, hash, user, etc.)",
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "How many hours of historical data",
                        "default": 24,
                    },
                },
                "required": ["entity_value"],
            },
        }

        self.tools["get_ioc_matches"] = {
            "name": "get_ioc_matches",
            "description": "Get Indicators of Compromise (IoC) matches from the SIEM.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hours_back": {
                        "type": "integer",
                        "description": "How many hours back to look",
                        "default": 24,
                    },
                    "max_matches": {
                        "type": "integer",
                        "description": "Maximum number of matches",
                        "default": 20,
                    },
                    "ioc_type": {
                        "type": "string",
                        "description": "Filter by IoC type (ip, domain, hash, url, etc.)",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity level",
                    },
                },
            },
        }

        self.tools["get_threat_intel"] = {
            "name": "get_threat_intel",
            "description": "Get answers to security questions using integrated threat intelligence.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The security or threat intelligence question",
                    },
                    "context": {
                        "type": "object",
                        "description": "Additional context (indicators, events, etc.)",
                    },
                },
                "required": ["query"],
            },
        }

        # Detection Rule Management
        self.tools["list_security_rules"] = {
            "name": "list_security_rules",
            "description": "List all security detection rules configured in the SIEM platform.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "enabled_only": {
                        "type": "boolean",
                        "description": "Only return enabled rules",
                        "default": False,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of rules",
                        "default": 100,
                    },
                },
            },
        }

        self.tools["search_security_rules"] = {
            "name": "search_security_rules",
            "description": "Search for security detection rules by name, description, or other criteria.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (supports regex patterns)",
                    },
                    "category": {
                        "type": "string",
                        "description": "Filter by rule category",
                    },
                    "enabled_only": {
                        "type": "boolean",
                        "description": "Only search enabled rules",
                        "default": False,
                    },
                },
                "required": ["query"],
            },
        }

        self.tools["get_rule_detections"] = {
            "name": "get_rule_detections",
            "description": "Retrieve historical detections generated by a specific security detection rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "Unique ID of the rule",
                    },
                    "alert_state": {
                        "type": "string",
                        "description": "Filter by alert state",
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "How many hours back",
                        "default": 24,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of detections",
                        "default": 50,
                    },
                },
                "required": ["rule_id"],
            },
        }

        self.tools["list_rule_errors"] = {
            "name": "list_rule_errors",
            "description": "List execution errors for a specific security detection rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "Unique ID of the rule",
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "How many hours back to look",
                        "default": 24,
                    },
                },
                "required": ["rule_id"],
            },
        }

    def _register_edr_tools(self) -> None:
        """
        Register EDR tools.
        
        Available tools:
        - get_endpoint_summary: Get endpoint overview (hostname, platform, isolation status)
        - get_detection_details: Get detailed detection information
        - isolate_endpoint: Isolate endpoint from network (CRITICAL ACTION - use with caution)
        - release_endpoint_isolation: Release endpoint from isolation
        - kill_process_on_endpoint: Terminate process on endpoint (DISRUPTIVE - use with caution)
        - collect_forensic_artifacts: Initiate forensic artifact collection
        
        See TOOLS.md for detailed documentation and usage examples.
        """
        if not self.edr_client:
            self._mcp_logger.warning(
                "EDR tools not registered: No EDR client configured. "
                "Configure EDR platform in config.json to enable EDR tools."
            )
            return
        self._mcp_logger.info(f"Registering {6} EDR tools")

        self.tools["get_endpoint_summary"] = {
            "name": "get_endpoint_summary",
            "description": "Retrieve summary information about an endpoint including hostname, platform, last seen time, primary user, and isolation status.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "endpoint_id": {
                        "type": "string",
                        "description": "The endpoint ID",
                    }
                },
                "required": ["endpoint_id"],
            },
        }

        self.tools["get_detection_details"] = {
            "name": "get_detection_details",
            "description": "Retrieve detailed information about a specific detection including type, severity, description, associated file hash, and process.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "detection_id": {
                        "type": "string",
                        "description": "The detection ID",
                    }
                },
                "required": ["detection_id"],
            },
        }

        self.tools["isolate_endpoint"] = {
            "name": "isolate_endpoint",
            "description": "Isolate an endpoint from the network to prevent further compromise or lateral movement. This is a critical response action.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "endpoint_id": {
                        "type": "string",
                        "description": "The endpoint ID to isolate",
                    }
                },
                "required": ["endpoint_id"],
            },
        }

        self.tools["release_endpoint_isolation"] = {
            "name": "release_endpoint_isolation",
            "description": "Release an endpoint from network isolation, restoring normal network connectivity.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "endpoint_id": {
                        "type": "string",
                        "description": "The endpoint ID to release",
                    }
                },
                "required": ["endpoint_id"],
            },
        }

        self.tools["kill_process_on_endpoint"] = {
            "name": "kill_process_on_endpoint",
            "description": "Terminate a specific process running on an endpoint by its process ID. Use with caution as this is a disruptive action.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "endpoint_id": {
                        "type": "string",
                        "description": "The endpoint ID",
                    },
                    "pid": {
                        "type": "integer",
                        "description": "The process ID to kill",
                    },
                },
                "required": ["endpoint_id", "pid"],
            },
        }

        self.tools["collect_forensic_artifacts"] = {
            "name": "collect_forensic_artifacts",
            "description": "Initiate collection of forensic artifacts from an endpoint, such as process lists, network connections, file system artifacts, etc.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "endpoint_id": {
                        "type": "string",
                        "description": "The endpoint ID",
                    },
                    "artifact_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of artifact types to collect (e.g., ['processes', 'network', 'filesystem'])",
                    },
                },
                "required": ["endpoint_id", "artifact_types"],
            },
        }

    def _register_cti_tools(self) -> None:
        """
        Register CTI (Cyber Threat Intelligence) tools.
        
        Available tools:
        - lookup_hash_ti: Look up a file hash in the threat intelligence platform
        
        See TOOLS.md for detailed documentation and usage examples.
        """
        if not self.cti_client:
            self._mcp_logger.warning(
                "CTI tools not registered: No CTI client configured. "
                "Configure CTI platform in config.json to enable CTI tools."
            )
            return
        self._mcp_logger.info(f"Registering {1} CTI tool")

        self.tools["lookup_hash_ti"] = {
            "name": "lookup_hash_ti",
            "description": (
                "Look up a file hash (MD5, SHA1, SHA256, SHA512) in threat intelligence platforms to determine if it's malicious, suspicious, or benign. "
                "Returns threat scores, classifications, indicators, labels, and MITRE ATT&CK kill chain phases. "
                "Use this to: (1) Check if a hash is known malicious - look for 'classification: malicious', high threat_score (>70), or labels like 'malware', 'trojan', 'ransomware'. "
                "(2) Assess threat level - threat_score 0-30=benign, 31-60=suspicious, 61-100=malicious. "
                "(3) Understand attack context - review kill_chain_phases and labels to understand the threat type and attack stage. "
                "Response includes: found (boolean), threat_score (0-100), classification (malicious/suspicious/benign), labels (array of threat types), indicators (array with scores and patterns). "
                "If found=false and no indicators, the hash is likely benign/unknown. If found=true with indicators, analyze the threat_score and labels to determine severity."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hash_value": {
                        "type": "string",
                        "description": "The hash value to look up (MD5, SHA1, SHA256, SHA512). Use this to check if a file hash is known malicious.",
                    }
                },
                "required": ["hash_value"],
            },
        }

    def _register_rules_tools(self) -> None:
        """
        Register rules engine tools.
        
        Available tools:
        - list_rules: List all available investigation rules/workflows
        - execute_rule: Execute an automated investigation workflow that chains multiple skills
        
        Rules enable automated playbooks that combine case management, SIEM, and EDR operations.
        See TOOLS.md for detailed documentation and usage examples.
        """
        self._mcp_logger.info("Registering 2 rules engine tools")
        self.tools["list_rules"] = {
            "name": "list_rules",
            "description": "List all available investigation rules/workflows.",
            "inputSchema": {"type": "object", "properties": {}},
        }

        self.tools["execute_rule"] = {
            "name": "execute_rule",
            "description": "Execute an investigation rule/workflow that chains together multiple skills.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "rule_name": {
                        "type": "string",
                        "description": "Name of the rule to execute",
                    },
                    "context": {
                        "type": "object",
                        "description": "Optional context variables to pass to the rule",
                    },
                },
                "required": ["rule_name"],
            },
        }

    def _register_runbook_tools(self) -> None:
        """
        Register runbook execution tools.
        
        Available tools:
        - list_runbooks: List available investigation runbooks
        - get_runbook: Get details of a specific runbook
        - execute_runbook: Execute a runbook (provides runbook content as context for AI)
        
        Runbooks provide structured investigation procedures organized by SOC tier.
        See run_books/ directory for available runbooks.
        """
        self._mcp_logger.info("Registering 3 runbook tools")
        self.tools["list_runbooks"] = {
            "name": "list_runbooks",
            "description": "List available investigation runbooks, optionally filtered by SOC tier or category.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "soc_tier": {
                        "type": "string",
                        "enum": ["soc1", "soc2", "soc3"],
                        "description": "Filter by SOC tier"
                    },
                    "category": {
                        "type": "string",
                        "enum": ["triage", "investigation", "response", "forensics", "correlation", "enrichment", "remediation"],
                        "description": "Filter by category"
                    }
                }
            }
        }
        
        self.tools["get_runbook"] = {
            "name": "get_runbook",
            "description": "Get details and content of a specific runbook.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "runbook_name": {
                        "type": "string",
                        "description": "Name of the runbook (e.g., 'initial_alert_triage' or 'soc1/triage/initial_alert_triage')"
                    }
                },
                "required": ["runbook_name"]
            }
        }
        
        self.tools["execute_runbook"] = {
            "name": "execute_runbook",
            "description": "Execute an investigation runbook. The runbook content will be provided as context for you to follow step-by-step. Use the appropriate MCP tools for each step as specified in the runbook.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "runbook_name": {
                        "type": "string",
                        "description": "Name of the runbook to execute (e.g., 'initial_alert_triage', 'malware_deep_analysis')"
                    },
                    "case_id": {
                        "type": "string",
                        "description": "Case ID for the investigation"
                    },
                    "alert_id": {
                        "type": "string",
                        "description": "Alert ID from SIEM"
                    },
                    "soc_tier": {
                        "type": "string",
                        "enum": ["soc1", "soc2", "soc3"],
                        "description": "SOC tier (auto-detected from runbook if not provided)"
                    }
                },
                "required": ["runbook_name"]
            }
        }

    def _register_agent_profile_tools(self) -> None:
        """
        Register agent profile tools.
        
        Available tools:
        - list_agent_profiles: List all configured agent profiles
        - get_agent_profile: Get details of a specific agent profile
        - route_case_to_agent: Route a case/alert to the appropriate agent
        - execute_as_agent: Execute an investigation as a specific agent (auto-selects runbook)
        
        Agent profiles define SOC tier capabilities and available runbooks for autonomous agents.
        """
        self._mcp_logger.info("Registering 4 agent profile tools")
        self.tools["list_agent_profiles"] = {
            "name": "list_agent_profiles",
            "description": "List all configured agent profiles with their capabilities and runbooks.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }
        
        self.tools["get_agent_profile"] = {
            "name": "get_agent_profile",
            "description": "Get details of a specific agent profile including capabilities, runbooks, and decision authority.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Agent ID (e.g., 'soc1_triage_agent', 'soc2_investigation_agent', 'soc3_response_agent')"
                    }
                },
                "required": ["agent_id"]
            }
        }
        
        self.tools["route_case_to_agent"] = {
            "name": "route_case_to_agent",
            "description": "Route a case/alert to the appropriate agent based on routing rules and case characteristics.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {
                        "type": "string",
                        "description": "Case ID to route"
                    },
                    "alert_id": {
                        "type": "string",
                        "description": "Alert ID to route"
                    },
                    "alert_type": {
                        "type": "string",
                        "description": "Type of alert (e.g., 'suspicious_login', 'malware_detection')"
                    },
                    "case_status": {
                        "type": "string",
                        "description": "Current case status (used for routing decisions)"
                    }
                }
            }
        }
        
        self.tools["execute_as_agent"] = {
            "name": "execute_as_agent",
            "description": "Execute an investigation as a specific agent. The agent will automatically select and execute the appropriate runbook based on its profile and the case/alert type.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Agent ID to execute as (e.g., 'soc1_triage_agent', 'soc2_investigation_agent', 'soc3_response_agent')"
                    },
                    "case_id": {
                        "type": "string",
                        "description": "Case ID for investigation"
                    },
                    "alert_id": {
                        "type": "string",
                        "description": "Alert ID from SIEM"
                    },
                    "runbook_name": {
                        "type": "string",
                        "description": "Optional: Specific runbook to execute (overrides auto-selection)"
                    }
                },
                "required": ["agent_id"]
            }
        }

    def _handle_list_runbooks(
        self, soc_tier: Optional[str] = None, category: Optional[str] = None
    ) -> Dict[str, Any]:
        """Handle list_runbooks tool call."""
        runbooks = self.runbook_manager.list_runbooks(soc_tier=soc_tier, category=category)
        return {"runbooks": runbooks, "count": len(runbooks)}
    
    def _handle_get_runbook(self, runbook_name: str) -> Dict[str, Any]:
        """Handle get_runbook tool call."""
        runbook_path = self.runbook_manager.find_runbook(runbook_name)
        if not runbook_path:
            return {
                "success": False,
                "error": f"Runbook not found: {runbook_name}"
            }
        
        content = self.runbook_manager.read_runbook(runbook_path)
        metadata = self.runbook_manager.parse_runbook_metadata(runbook_path, content)
        workflow_steps = self.runbook_manager.extract_workflow_steps(content)
        
        # Get relative path
        rel_path = os.path.relpath(runbook_path, self.runbook_manager.runbooks_dir)
        runbook_id = rel_path[:-3]  # Remove .md extension
        
        return {
            "success": True,
            "runbook_name": runbook_id,
            "path": runbook_path,
            "soc_tier": metadata.get("soc_tier"),
            "category": metadata.get("category"),
            "objective": metadata.get("objective"),
            "scope": metadata.get("scope"),
            "tools": metadata.get("tools", []),
            "inputs": metadata.get("inputs", []),
            "step_count": metadata.get("step_count", len(workflow_steps)),
            "workflow_steps": workflow_steps,
            "content": content  # Full markdown content
        }
    
    def _handle_execute_runbook(
        self,
        runbook_name: str,
        case_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        soc_tier: Optional[str] = None
    ) -> Dict[str, Any]:
        """Handle execute_runbook tool call."""
        # Find runbook
        runbook_path = self.runbook_manager.find_runbook(runbook_name, soc_tier=soc_tier)
        if not runbook_path:
            return {
                "success": False,
                "error": f"Runbook not found: {runbook_name}"
            }
        
        # Read and parse runbook
        content = self.runbook_manager.read_runbook(runbook_path)
        metadata = self.runbook_manager.parse_runbook_metadata(runbook_path, content)
        workflow_steps = self.runbook_manager.extract_workflow_steps(content)
        
        # Get relative path
        rel_path = os.path.relpath(runbook_path, self.runbook_manager.runbooks_dir)
        runbook_id = rel_path[:-3]
        
        # Determine SOC tier
        detected_tier = metadata.get("soc_tier") or soc_tier
        
        # Load and prepend SOC tier guidelines to runbook content if available
        if detected_tier:
            try:
                guidelines_runbook_name = f"{detected_tier}/guidelines"
                guidelines_path = self.runbook_manager.find_runbook(
                    guidelines_runbook_name,
                    soc_tier=detected_tier,
                )
                if guidelines_path:
                    guidelines_content = self.runbook_manager.read_runbook(guidelines_path)
                    # Prepend guidelines to runbook content so AI always sees them
                    content = f"{guidelines_content}\n\n---\n\n{content}"
            except Exception:
                # Do not fail execution if guidelines cannot be loaded
                self._mcp_logger.debug(
                    f"Could not load guidelines for tier {detected_tier}",
                )
        
        # Check if case needs to be created
        # NOTE: For triage runbooks (especially initial_alert_triage), the runbook itself
        # will determine if a case should be created after quick assessment (Step 2a).
        # Only auto-create cases if:
        # 1. A case_id is explicitly provided (case already exists)
        # 2. The runbook is NOT a triage runbook that performs quick assessment
        case_created = False
        is_triage_runbook = "triage" in runbook_id.lower() or "initial_alert_triage" in runbook_id.lower()
        
        if not case_id and alert_id and self.case_client:
            # Check if case exists for this alert
            try:
                search_results = self.case_client.search_cases(
                    CaseSearchQuery(text=alert_id, limit=10)
                )
                if search_results:
                    # Use existing case
                    case_id = search_results[0].id
                elif not is_triage_runbook:
                    # Only auto-create case for non-triage runbooks
                    # Triage runbooks will create cases themselves after quick assessment
                    # Create new case following case standard
                    from datetime import datetime
                    from ..api.case_management import Case, CaseStatus, CasePriority
                    
                    # Get alert details if available
                    alert_type = "Security Alert"
                    primary_entity = alert_id[:20] + "..." if len(alert_id) > 20 else alert_id
                    
                    if self.siem_client:
                        try:
                            alert_result = tools_siem.get_security_alert_by_id(
                                alert_id=alert_id,
                                client=self.siem_client
                            )
                            if alert_result and "alert" in alert_result:
                                alert = alert_result["alert"]
                                if isinstance(alert, dict):
                                    alert_type = alert.get("title") or alert.get("alert_type", "Security Alert")
                                    if alert.get("related_entities"):
                                        entities = alert["related_entities"]
                                        if entities:
                                            primary_entity = str(entities[0]).split(":")[-1] if ":" in str(entities[0]) else str(entities[0])
                        except Exception:
                            pass  # Continue with defaults
                    
                    # Generate title following case standard format
                    date_str = datetime.utcnow().strftime("%Y-%m-%d")
                    title = f"{alert_type} - {primary_entity} - {date_str}"
                    
                    # Build description following case standard
                    description = f"""**Alert ID**: {alert_id}
**Alert Type**: {alert_type}
**Created**: {datetime.utcnow().isoformat()}

## Initial Assessment
Case created during runbook execution: {runbook_id}
Initial triage in progress.

## Key Entities
To be populated during investigation.

## Investigation Status
- Status: Initial triage
- SOC Tier: {detected_tier or 'unknown'}
- Runbook: {runbook_id}
"""
                    
                    # Determine priority based on alert if available
                    priority = CasePriority.MEDIUM
                    if self.siem_client:
                        try:
                            alert_result = tools_siem.get_security_alert_by_id(
                                alert_id=alert_id,
                                client=self.siem_client
                            )
                            if alert_result and "alert" in alert_result:
                                alert = alert_result["alert"]
                                if isinstance(alert, dict):
                                    severity = alert.get("severity", "").lower()
                                    if severity in ["high", "critical"]:
                                        priority = CasePriority.HIGH
                                    elif severity == "low":
                                        priority = CasePriority.LOW
                        except Exception:
                            pass
                    
                    # Create case
                    new_case = Case(
                        id=None,
                        title=title,
                        description=description,
                        status=CaseStatus.OPEN,
                        priority=priority,
                        tags=[detected_tier + "-triage" if detected_tier else "triage", runbook_id.split("/")[-1]],
                        observables=None,
                    )
                    
                    created_case = self.case_client.create_case(new_case)
                    case_id = created_case.id or ""
                    case_created = True
                    
                    # Add initial note
                    try:
                        self.case_client.add_case_comment(
                            case_id=case_id,
                            content=f"Case created from alert {alert_id}. Executing runbook: {runbook_id}",
                            author="SamiGPT Agent"
                        )
                    except Exception:
                        pass
            except Exception as e:
                self._mcp_logger.warning(f"Failed to create/find case for alert {alert_id}: {e}")
                # Continue without case_id - runbook can still execute
        
        # Prepare execution context
        execution_instructions = (
            f"You are executing the runbook: {runbook_id} (SOC Tier: {detected_tier or 'unknown'}). "
            f"Objective: {metadata.get('objective', 'Investigation')}. "
        )
        
        if case_id:
            execution_instructions += f"A case has been {'created' if case_created else 'identified'} with ID: {case_id}. "
        elif alert_id:
            execution_instructions += f"Alert ID: {alert_id}. "
            if self.case_client:
                if is_triage_runbook:
                    execution_instructions += (
                        "IMPORTANT: Follow Step 2a (Quick Assessment) in the runbook FIRST. "
                        "Only create a case using create_case tool if the quick assessment determines "
                        "that case creation is needed (uncertain, suspicious, or requires tracking). "
                        "If the alert is clearly FP/BTP with high confidence, close the alert directly "
                        "using close_alert without creating a case. "
                    )
                else:
                    execution_instructions += "IMPORTANT: Create a case using create_case tool if one doesn't exist, following the case standard in standards/case_standard.md. "
        
        execution_instructions += (
            f"Follow the workflow steps in the runbook below. Use the appropriate MCP tools for each step. "
            f"Document your progress and findings in case comments as specified in the runbook. "
            f"Attach all observables (IOCs) to the case using attach_observable_to_case. "
            f"Follow the case standard format for all documentation."
        )
        
        return {
            "success": True,
            "runbook_name": runbook_id,
            "soc_tier": detected_tier,
            "objective": metadata.get("objective"),
            "execution_instructions": execution_instructions,
            "runbook_content": content,  # Full markdown for AI context
            "workflow_summary": [
                {"step": step["step_number"], "title": step["title"]}
                for step in workflow_steps
            ],
            "tools_available": metadata.get("tools", []),
            "inputs_provided": {
                "case_id": case_id,
                "alert_id": alert_id
            },
            "inputs_required": metadata.get("inputs", []),
            "case_created": case_created,
            "status": "ready_for_execution"
        }
    
    def _handle_get_agent_profile(self, agent_id: str) -> Dict[str, Any]:
        """Handle get_agent_profile tool call."""
        profile = self.agent_profile_manager.get_profile(agent_id)
        if not profile:
            return {
                "success": False,
                "error": f"Agent profile not found: {agent_id}"
            }
        
        return {
            "success": True,
            "agent_id": agent_id,
            "name": profile.name,
            "tier": profile.tier,
            "description": profile.description,
            "capabilities": profile.capabilities,
            "runbooks": profile.runbooks,
            "decision_authority": {
                "close_false_positives": profile.decision_authority.close_false_positives,
                "close_benign_true_positives": profile.decision_authority.close_benign_true_positives,
                "escalate_to_soc2": profile.decision_authority.escalate_to_soc2,
                "escalate_to_soc3": profile.decision_authority.escalate_to_soc3,
                "containment_actions": profile.decision_authority.containment_actions,
                "forensic_collection": profile.decision_authority.forensic_collection
            },
            "auto_select_runbook": profile.auto_select_runbook,
            "max_concurrent_cases": profile.max_concurrent_cases
        }
    
    def _handle_route_case_to_agent(
        self,
        case_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        alert_type: Optional[str] = None,
        case_status: Optional[str] = None
    ) -> Dict[str, Any]:
        """Handle route_case_to_agent tool call."""
        # Get case status if case_id provided
        if case_id and self.case_client and not case_status:
            try:
                case = self.case_client.get_case(case_id)
                case_status = case.status.value if hasattr(case.status, 'value') else str(case.status)
            except Exception:
                pass  # Continue without case status
        
        agent_id = self.agent_profile_manager.route_to_agent(
            case_id=case_id,
            alert_id=alert_id,
            alert_type=alert_type,
            case_status=case_status
        )
        
        if agent_id:
            profile = self.agent_profile_manager.get_profile(agent_id)
            return {
                "success": True,
                "agent_id": agent_id,
                "agent_name": profile.name if profile else None,
                "tier": profile.tier if profile else None,
                "routing_reason": "Based on routing rules and case/alert characteristics"
            }
        else:
            return {
                "success": False,
                "error": "Could not determine appropriate agent"
            }
    
    def _handle_execute_as_agent(
        self,
        agent_id: str,
        case_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        runbook_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Handle execute_as_agent tool call."""
        profile = self.agent_profile_manager.get_profile(agent_id)
        if not profile:
            return {
                "success": False,
                "error": f"Agent profile not found: {agent_id}"
            }
        
        # Get alert/case details if provided
        alert_details = {}
        alert_type = None
        
        if alert_id and self.siem_client:
            try:
                # Use the tool function which handles the client properly
                alert_result = tools_siem.get_security_alert_by_id(
                    alert_id=alert_id,
                    client=self.siem_client
                )
                if alert_result and "alert" in alert_result:
                    alert = alert_result["alert"]
                    if isinstance(alert, dict):
                        alert_type = alert.get("alert_type") or alert.get("title", "")
                        alert_details["severity"] = alert.get("severity")
                        alert_details["title"] = alert.get("title")
                    else:
                        if hasattr(alert, 'alert_type'):
                            alert_type = alert.alert_type
                        if hasattr(alert, 'severity'):
                            alert_details["severity"] = alert.severity
                        if hasattr(alert, 'title'):
                            alert_details["title"] = alert.title
            except Exception:
                pass  # Continue without alert details
        
        # Auto-select runbook if not specified
        if not runbook_name and profile.auto_select_runbook:
            runbook_name = profile.select_runbook_for_alert(
                alert_type=alert_type or "",
                alert_details=alert_details
            )
        
        if not runbook_name:
            return {
                "success": False,
                "error": "Could not determine appropriate runbook. Please specify runbook_name."
            }
        
        # Verify agent can execute this runbook
        if not profile.can_execute_runbook(runbook_name):
            return {
                "success": False,
                "error": f"Agent {agent_id} (tier: {profile.tier}) cannot execute runbook {runbook_name}"
            }

        # Optionally load SOC tier guidelines for this agent on first execution
        guidelines_content: Optional[str] = None
        if not self._shown_agent_guidelines.get(agent_id):
            guidelines_runbook_name = f"{profile.tier}/guidelines"
            try:
                guidelines_path = self.runbook_manager.find_runbook(
                    guidelines_runbook_name,
                    soc_tier=profile.tier,
                )
                if guidelines_path:
                    guidelines_content = self.runbook_manager.read_runbook(guidelines_path)
                    # Mark as shown for this agent profile within this server process
                    self._shown_agent_guidelines[agent_id] = True
            except Exception:
                # Do not fail execution if guidelines cannot be loaded
                self._mcp_logger.debug(
                    f"Could not load guidelines for agent {agent_id} (tier: {profile.tier})",
                )

        # Execute runbook (reuse execute_runbook logic)
        runbook_result = self._handle_execute_runbook(
            runbook_name=runbook_name,
            case_id=case_id,
            alert_id=alert_id,
            soc_tier=profile.tier
        )
        
        if not runbook_result.get("success"):
            return runbook_result

        result: Dict[str, Any] = {
            "success": True,
            "agent_id": agent_id,
            "agent_name": profile.name,
            "tier": profile.tier,
            "runbook_executed": runbook_name,
            "runbook_result": runbook_result,
        }

        # When guidelines are available and this is the first execution for the agent,
        # include them so MCP users see them before following the runbook.
        if guidelines_content is not None:
            result["profile_guidelines"] = {
                "agent_id": agent_id,
                "tier": profile.tier,
                "path": f"{profile.tier}/guidelines",
                "content": guidelines_content,
                "first_run_for_agent": True,
            }
        
        return result

    def _create_response(
        self, request_id: Optional[Any], result: Optional[Any] = None, error: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a JSON-RPC 2.0 response.
        
        Args:
            request_id: Request ID from the original request (can be None for notifications)
            result: Result data (for success responses)
            error: Error data (for error responses)
            
        Returns:
            JSON-RPC 2.0 response dictionary
        """
        response: Dict[str, Any] = {"jsonrpc": "2.0"}
        
        if error:
            response["error"] = error
        elif result is not None:
            response["result"] = result
        
        # Only include id if it's a valid value (string or number, not None/null)
        # Per JSON-RPC 2.0, id should be included if present in request and is valid
        # Some clients require id to be a string or number, not null
        if request_id is not None:
            # Ensure id is a valid type (string, int, or float)
            if isinstance(request_id, (str, int, float)):
                response["id"] = request_id
            # If it's not a valid type, convert to string as fallback
            else:
                response["id"] = str(request_id)
            
        return response

    def _create_error_response(
        self, request_id: Optional[Any], code: int, message: str, data: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Create a JSON-RPC 2.0 error response.
        
        Args:
            request_id: Request ID
            code: Error code (JSON-RPC 2.0 standard codes)
            message: Error message
            data: Optional additional error data
            
        Returns:
            Error response dictionary
        """
        error: Dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return self._create_response(request_id, error=error)

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle an MCP request.

        Args:
            request: MCP request dictionary.

        Returns:
            MCP response dictionary.
        """
        # Log raw request for debugging
        self._mcp_logger.debug(f"Raw request received: {json.dumps(request)[:1000]}")
        
        method = request.get("method")
        params = request.get("params", {})
        
        # Get id, but only if it's present and valid (not null)
        # Use 'id' in request to check presence, then get value
        request_id = None
        if "id" in request:
            id_value = request["id"]
            # Only use id if it's a valid value (not None/null)
            if id_value is not None:
                request_id = id_value
        
        # Check if this is a notification (no id) or a request (has id)
        is_notification = "id" not in request or request.get("id") is None
        
        # Log request with full context
        if is_notification:
            self._mcp_logger.info(
                f"NOTIFICATION received: method={method}, params={json.dumps(params)[:500]}"
            )
        else:
            self._mcp_logger.info(
                f"REQUEST [id={request_id}] method={method}, params={json.dumps(params)[:500]}"
            )

        # Handle notifications (no response needed)
        if is_notification:
            if method == "notifications/initialized":
                self._mcp_logger.info("Client sent initialized notification - this is expected after server sends it")
                # Notifications don't get responses
                return None
            else:
                self._mcp_logger.warning(f"Unknown notification method: {method}")
                # Notifications don't get responses
                return None

        try:
            if method == "initialize":
                return await self._handle_initialize(request_id, params)
            elif method == "tools/list":
                return await self._handle_tools_list(request_id)
            elif method == "tools/call":
                return await self._handle_tools_call(request_id, params)
            else:
                self._mcp_logger.warning(f"Unknown method: {method}")
                return self._create_error_response(
                    request_id,
                    -32601,
                    f"Method not found: {method}",
                )
        except Exception as e:
            self._mcp_logger.error(
                f"RESPONSE [id={request_id}] Error handling request: {e}",
                exc_info=True,
            )
            logger.error(f"Error handling request: {e}", exc_info=True)
            return self._create_error_response(
                request_id,
                -32603,
                f"Internal error: {str(e)}",
            )

    async def _handle_initialize(
        self, request_id: Optional[Any], params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle initialize request."""
        # Log incoming protocol version
        client_protocol = params.get("protocolVersion", "unknown")
        self._mcp_logger.info(
            f"Initialize request: client protocol={client_protocol}, client_info={params.get('clientInfo', {})}"
        )
        
        # Use the client's protocol version if supported, otherwise use our default
        protocol_version = self.PROTOCOL_VERSION
        if client_protocol in self.SUPPORTED_PROTOCOL_VERSIONS:
            protocol_version = client_protocol
            self._mcp_logger.info(f"Using client's protocol version: {protocol_version}")
        else:
            self._mcp_logger.warning(
                f"Client protocol version {client_protocol} not explicitly supported, using {protocol_version}"
            )
        
        self._initialized = True
        self._mcp_logger.info(f"RESPONSE [id={request_id}] initialize successful")
        
        return self._create_response(
            request_id,
            result={
                "protocolVersion": protocol_version,
                        "capabilities": {
                            "tools": {},
                        },
                        "serverInfo": {
                    "name": self.SERVER_NAME,
                    "version": self.SERVER_VERSION,
                        },
                    },
        )

    async def _handle_tools_list(self, request_id: Optional[Any]) -> Dict[str, Any]:
        """Handle tools/list request."""
        # Allow tools/list even if not initialized (some clients do this)
        if not self._initialized:
            self._mcp_logger.warning(
                f"tools/list called before initialization complete (id={request_id})"
            )
        
        try:
            # Convert tools dict to list
            tools_list = []
            for tool_name, tool_def in self.tools.items():
                if isinstance(tool_def, dict):
                    tools_list.append(tool_def)
                else:
                    # Fallback if tool_def is not a dict
                    tools_list.append({
                        "name": tool_name,
                        "description": str(tool_def),
                        "inputSchema": {"type": "object", "properties": {}}
                    })
            
            self._mcp_logger.info(
                f"RESPONSE [id={request_id}] tools/list: {len(tools_list)} tools available"
            )
            
            return self._create_response(
                request_id,
                result={"tools": tools_list},
            )
        except Exception as e:
            self._mcp_logger.error(
                f"Error creating tools/list response: {e}", exc_info=True
            )
            logger.error(f"Error creating tools/list response: {e}", exc_info=True)
            raise

    async def _handle_tools_call(
        self, request_id: Optional[Any], params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle tools/call request."""
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})

        if not tool_name:
            return self._create_error_response(
                request_id,
                -32602,
                "Invalid params: 'name' is required",
            )

        if tool_name not in self.tools:
            self._mcp_logger.error(
                f"RESPONSE [id={request_id}] Tool not found: {tool_name}"
            )
            return self._create_error_response(
                request_id,
                -32601,
                f"Tool not found: {tool_name}",
            )

        # Execute the tool
        self._mcp_logger.info(
            f"EXECUTING [id={request_id}] tool={tool_name}, args={json.dumps(tool_args)[:500]}"
        )
        
        try:
            result = await self._execute_tool(tool_name, tool_args)

            # Format result according to MCP spec: content array with text items
            result_text = json.dumps(result, indent=2)
            result_preview = result_text[:500] if len(result_text) > 500 else result_text
            
            self._mcp_logger.info(
                f"RESPONSE [id={request_id}] tool={tool_name} completed: {result_preview}"
            )
            
            return self._create_response(
                request_id,
                result={
                    "content": [
                        {
                            "type": "text",
                            "text": result_text,
                        }
                    ],
                },
            )
        except Exception as e:
            self._mcp_logger.error(
                f"Tool {tool_name} execution failed: {e}", exc_info=True
            )
            return self._create_error_response(
                request_id,
                -32603,
                f"Tool execution failed: {str(e)}",
            )

    async def _execute_tool(self, tool_name: str, args: Dict[str, Any]) -> Any:
        """
        Execute a tool by name.

        Args:
            tool_name: Name of the tool to execute.
            args: Tool arguments.

        Returns:
            Tool result.
        """
        self._mcp_logger.debug(
            f"Executing tool: {tool_name} with args: {json.dumps(args)[:500]}"
        )
        
        # Case management tools
        if tool_name == "create_case" and self.case_client:
            result = tools_case.create_case(
                title=args["title"],
                description=args["description"],
                priority=args.get("priority", "medium"),
                status=args.get("status", "open"),
                tags=args.get("tags"),
                alert_id=args.get("alert_id"),
                client=self.case_client,
            )
            self._mcp_logger.info(
                f"Tool {tool_name} executed: case created with ID {result.get('case', {}).get('id')}"
            )
            return result
        elif tool_name == "review_case" and self.case_client:
            result = tools_case.review_case(args["case_id"], self.case_client)
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "list_cases" and self.case_client:
            result = tools_case.list_cases(
                status=args.get("status"),
                limit=args.get("limit", 50),
                client=self.case_client,
            )
            self._mcp_logger.debug(
                f"Tool {tool_name} completed: {len(result.get('cases', []))} cases found"
            )
            return result
        elif tool_name == "search_cases" and self.case_client:
            result = tools_case.search_cases(
                text=args.get("text"),
                status=args.get("status"),
                priority=args.get("priority"),
                tags=args.get("tags"),
                assignee=args.get("assignee"),
                limit=args.get("limit", 50),
                client=self.case_client,
            )
            self._mcp_logger.debug(
                f"Tool {tool_name} completed: {len(result.get('cases', []))} cases found"
            )
            return result
        elif tool_name == "add_case_comment" and self.case_client:
            result = tools_case.add_case_comment(
                case_id=args["case_id"],
                content=args["content"],
                author=args.get("author"),
                client=self.case_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "attach_observable_to_case" and self.case_client:
            result = tools_case.attach_observable_to_case(
                case_id=args["case_id"],
                observable_type=args["observable_type"],
                observable_value=args["observable_value"],
                description=args.get("description"),
                tags=args.get("tags"),
                client=self.case_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "update_case_status" and self.case_client:
            result = tools_case.update_case_status(
                case_id=args["case_id"],
                status=args["status"],
                client=self.case_client,
            )
            self._mcp_logger.debug(
                f"Tool {tool_name} completed: case {args['case_id']} status updated to {args['status']}"
            )
            return result
        elif tool_name == "assign_case" and self.case_client:
            result = tools_case.assign_case(
                case_id=args["case_id"],
                assignee=args["assignee"],
                client=self.case_client,
            )
            self._mcp_logger.debug(
                f"Tool {tool_name} completed: case {args['case_id']} assigned to {args['assignee']}"
            )
            return result
        elif tool_name == "get_case_timeline" and self.case_client:
            result = tools_case.get_case_timeline(
                case_id=args["case_id"],
                client=self.case_client,
            )
            self._mcp_logger.debug(
                f"Tool {tool_name} completed: {len(result.get('timeline', []))} events found"
            )
            return result
        elif tool_name == "add_case_task" and self.case_client:
            result = tools_case.add_case_task(
                case_id=args["case_id"],
                title=args["title"],
                description=args["description"],
                assignee=args.get("assignee"),
                priority=args.get("priority", "medium"),
                status=args.get("status", "pending"),
                client=self.case_client,
            )
            self._mcp_logger.info(f"Tool {tool_name} executed: task '{args['title']}' added to case {args['case_id']}")
            return result
        elif tool_name == "list_case_tasks" and self.case_client:
            result = tools_case.list_case_tasks(args["case_id"], self.case_client)
            self._mcp_logger.debug(f"Tool {tool_name} completed: {result.get('count', 0)} tasks found")
            return result
        elif tool_name == "update_case_task_status" and self.case_client:
            result = tools_case.update_case_task_status(
                case_id=args["case_id"],
                task_id=args["task_id"],
                status=args["status"],
                client=self.case_client,
            )
            self._mcp_logger.info(f"Tool {tool_name} executed: task {args['task_id']} status updated to '{args['status']}'")
            return result
        elif tool_name == "add_case_asset" and self.case_client:
            result = tools_case.add_case_asset(
                case_id=args["case_id"],
                asset_name=args["asset_name"],
                asset_type=args["asset_type"],
                description=args.get("description"),
                ip_address=args.get("ip_address"),
                hostname=args.get("hostname"),
                tags=args.get("tags"),
                client=self.case_client,
            )
            self._mcp_logger.info(f"Tool {tool_name} executed: asset '{args['asset_name']}' added to case {args['case_id']}")
            return result
        elif tool_name == "list_case_assets" and self.case_client:
            result = tools_case.list_case_assets(args["case_id"], self.case_client)
            self._mcp_logger.debug(f"Tool {tool_name} completed: {result.get('count', 0)} assets found")
            return result
        elif tool_name == "add_case_evidence" and self.case_client:
            result = tools_case.add_case_evidence(
                case_id=args["case_id"],
                file_path=args["file_path"],
                description=args.get("description"),
                evidence_type=args.get("evidence_type"),
                client=self.case_client,
            )
            self._mcp_logger.info(f"Tool {tool_name} executed: evidence '{args['file_path']}' added to case {args['case_id']}")
            return result
        elif tool_name == "list_case_evidence" and self.case_client:
            result = tools_case.list_case_evidence(args["case_id"], self.case_client)
            self._mcp_logger.debug(f"Tool {tool_name} completed: {result.get('count', 0)} evidence files found")
            return result
        elif tool_name == "update_case" and self.case_client:
            result = tools_case.update_case(
                case_id=args["case_id"],
                title=args.get("title"),
                description=args.get("description"),
                priority=args.get("priority"),
                status=args.get("status"),
                tags=args.get("tags"),
                assignee=args.get("assignee"),
                client=self.case_client,
            )
            self._mcp_logger.info(f"Tool {tool_name} executed: case {args['case_id']} updated")
            return result
        elif tool_name == "link_cases" and self.case_client:
            result = tools_case.link_cases(
                source_case_id=args["source_case_id"],
                target_case_id=args["target_case_id"],
                link_type=args.get("link_type", "related_to"),
                client=self.case_client,
            )
            self._mcp_logger.info(f"Tool {tool_name} executed: case {args['source_case_id']} linked to {args['target_case_id']}")
            return result
        elif tool_name == "add_case_timeline_event" and self.case_client:
            result = tools_case.add_case_timeline_event(
                case_id=args["case_id"],
                title=args["title"],
                content=args["content"],
                source=args.get("source"),
                category_id=args.get("category_id"),
                tags=args.get("tags"),
                color=args.get("color"),
                event_date=args.get("event_date"),
                include_in_summary=args.get("include_in_summary", True),
                include_in_graph=args.get("include_in_graph", True),
                sync_iocs_assets=args.get("sync_iocs_assets", True),
                asset_ids=args.get("asset_ids"),
                ioc_ids=args.get("ioc_ids"),
                custom_attributes=args.get("custom_attributes"),
                raw=args.get("raw"),
                tz=args.get("tz"),
                client=self.case_client,
            )
            self._mcp_logger.info(f"Tool {tool_name} executed: timeline event '{args['title']}' added to case {args['case_id']}")
            return result
        elif tool_name == "list_case_timeline_events" and self.case_client:
            result = tools_case.list_case_timeline_events(args["case_id"], self.case_client)
            self._mcp_logger.debug(f"Tool {tool_name} completed: {result.get('count', 0)} timeline events found")
            return result

        # SIEM tools
        elif tool_name == "search_security_events" and self.siem_client:
            result = tools_siem.search_security_events(
                query=args["query"],
                limit=args.get("limit", 100),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_file_report" and self.siem_client:
            result = tools_siem.get_file_report(
                file_hash=args["file_hash"],
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_file_behavior_summary" and self.siem_client:
            result = tools_siem.get_file_behavior_summary(
                file_hash=args["file_hash"],
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_entities_related_to_file" and self.siem_client:
            result = tools_siem.get_entities_related_to_file(
                file_hash=args["file_hash"],
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_ip_address_report" and self.siem_client:
            result = tools_siem.get_ip_address_report(
                ip=args["ip"],
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "search_user_activity" and self.siem_client:
            result = tools_siem.search_user_activity(
                username=args["username"],
                limit=args.get("limit", 100),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "pivot_on_indicator" and self.siem_client:
            result = tools_siem.pivot_on_indicator(
                indicator=args["indicator"],
                limit=args.get("limit", 200),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "search_kql_query" and self.siem_client:
            result = tools_siem.search_kql_query(
                kql_query=args["kql_query"],
                limit=args.get("limit", 500),
                hours_back=args.get("hours_back"),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_recent_alerts" and self.siem_client:
            result = tools_siem.get_recent_alerts(
                hours_back=args.get("hours_back", 1),
                max_alerts=args.get("max_alerts", 100),
                status_filter=args.get("status_filter"),
                severity=args.get("severity"),
                hostname=args.get("hostname"),
                client=self.siem_client,
            )
            self._mcp_logger.debug(
                f"Tool {tool_name} completed: {result.get('group_count', 0)} groups from {result.get('total_alerts', 0)} alerts"
            )
            return result
        elif tool_name == "get_security_alerts" and self.siem_client:
            result = tools_siem.get_security_alerts(
                hours_back=args.get("hours_back", 24),
                max_alerts=args.get("max_alerts", 10),
                status_filter=args.get("status_filter"),
                severity=args.get("severity"),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_security_alert_by_id" and self.siem_client:
            result = tools_siem.get_security_alert_by_id(
                alert_id=args["alert_id"],
                include_detections=args.get("include_detections", True),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_siem_event_by_id" and self.siem_client:
            result = tools_siem.get_siem_event_by_id(
                event_id=args["event_id"],
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "close_alert" and self.siem_client:
            result = tools_siem.close_alert(
                alert_id=args["alert_id"],
                reason=args.get("reason"),
                comment=args.get("comment"),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "update_alert_verdict" and self.siem_client:
            result = tools_siem.update_alert_verdict(
                alert_id=args["alert_id"],
                verdict=args["verdict"],
                comment=args.get("comment"),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "tag_alert" and self.siem_client:
            result = tools_siem.tag_alert(
                alert_id=args["alert_id"],
                tag=args["tag"],
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "add_alert_note" and self.siem_client:
            result = tools_siem.add_alert_note(
                alert_id=args["alert_id"],
                note=args["note"],
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "lookup_entity" and self.siem_client:
            result = tools_siem.lookup_entity(
                entity_value=args["entity_value"],
                entity_type=args.get("entity_type"),
                hours_back=args.get("hours_back", 24),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_ioc_matches" and self.siem_client:
            result = tools_siem.get_ioc_matches(
                hours_back=args.get("hours_back", 24),
                max_matches=args.get("max_matches", 20),
                ioc_type=args.get("ioc_type"),
                severity=args.get("severity"),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_threat_intel" and self.siem_client:
            result = tools_siem.get_threat_intel(
                query=args["query"],
                context=args.get("context"),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "list_security_rules" and self.siem_client:
            result = tools_siem.list_security_rules(
                enabled_only=args.get("enabled_only", False),
                limit=args.get("limit", 100),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "search_security_rules" and self.siem_client:
            result = tools_siem.search_security_rules(
                query=args["query"],
                category=args.get("category"),
                enabled_only=args.get("enabled_only", False),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_rule_detections" and self.siem_client:
            result = tools_siem.get_rule_detections(
                rule_id=args["rule_id"],
                alert_state=args.get("alert_state"),
                hours_back=args.get("hours_back", 24),
                limit=args.get("limit", 50),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "list_rule_errors" and self.siem_client:
            result = tools_siem.list_rule_errors(
                rule_id=args["rule_id"],
                hours_back=args.get("hours_back", 24),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_network_events" and self.siem_client:
            result = tools_siem.get_network_events(
                source_ip=args.get("source_ip"),
                destination_ip=args.get("destination_ip"),
                port=args.get("port"),
                protocol=args.get("protocol"),
                hours_back=args.get("hours_back", 24),
                limit=args.get("limit", 100),
                event_type=args.get("event_type"),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_dns_events" and self.siem_client:
            result = tools_siem.get_dns_events(
                domain=args.get("domain"),
                ip_address=args.get("ip_address"),
                resolved_ip=args.get("resolved_ip"),
                query_type=args.get("query_type"),
                hours_back=args.get("hours_back", 24),
                limit=args.get("limit", 100),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_alerts_by_entity" and self.siem_client:
            result = tools_siem.get_alerts_by_entity(
                entity_value=args["entity_value"],
                entity_type=args.get("entity_type"),
                hours_back=args.get("hours_back", 24),
                limit=args.get("limit", 50),
                severity=args.get("severity"),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_alerts_by_time_window" and self.siem_client:
            result = tools_siem.get_alerts_by_time_window(
                start_time=args["start_time"],
                end_time=args["end_time"],
                limit=args.get("limit", 100),
                severity=args.get("severity"),
                alert_type=args.get("alert_type"),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_all_uncertain_alerts_for_host" and self.siem_client:
            result = tools_siem.get_all_uncertain_alerts_for_host(
                hostname=args["hostname"],
                hours_back=args.get("hours_back", 168),
                limit=args.get("limit", 100),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_email_events" and self.siem_client:
            result = tools_siem.get_email_events(
                sender_email=args.get("sender_email"),
                recipient_email=args.get("recipient_email"),
                subject=args.get("subject"),
                email_id=args.get("email_id"),
                hours_back=args.get("hours_back", 24),
                limit=args.get("limit", 100),
                event_type=args.get("event_type"),
                client=self.siem_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result

        # EDR tools
        elif tool_name == "get_endpoint_summary" and self.edr_client:
            result = tools_edr.get_endpoint_summary(
                endpoint_id=args["endpoint_id"],
                client=self.edr_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "get_detection_details" and self.edr_client:
            result = tools_edr.get_detection_details(
                detection_id=args["detection_id"],
                client=self.edr_client,
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result
        elif tool_name == "isolate_endpoint" and self.edr_client:
            result = tools_edr.isolate_endpoint(
                endpoint_id=args["endpoint_id"],
                client=self.edr_client,
            )
            self._mcp_logger.warning(
                f"Tool {tool_name} executed: endpoint {args['endpoint_id']} isolated"
            )
            return result
        elif tool_name == "release_endpoint_isolation" and self.edr_client:
            result = tools_edr.release_endpoint_isolation(
                endpoint_id=args["endpoint_id"],
                client=self.edr_client,
            )
            self._mcp_logger.info(
                f"Tool {tool_name} executed: endpoint {args['endpoint_id']} isolation released"
            )
            return result
        elif tool_name == "kill_process_on_endpoint" and self.edr_client:
            result = tools_edr.kill_process_on_endpoint(
                endpoint_id=args["endpoint_id"],
                pid=args["pid"],
                client=self.edr_client,
            )
            self._mcp_logger.warning(
                f"Tool {tool_name} executed: process {args['pid']} killed on endpoint {args['endpoint_id']}"
            )
            return result
        elif tool_name == "collect_forensic_artifacts" and self.edr_client:
            result = tools_edr.collect_forensic_artifacts(
                endpoint_id=args["endpoint_id"],
                artifact_types=args["artifact_types"],
                client=self.edr_client,
            )
            self._mcp_logger.info(
                f"Tool {tool_name} executed: collecting {args['artifact_types']} from endpoint {args['endpoint_id']}"
            )
            return result

        # CTI tools
        elif tool_name == "lookup_hash_ti" and (self.cti_client or self.cti_clients):
            # Use multiple clients if available, otherwise fall back to single client
            result = tools_cti.lookup_hash_ti(
                hash_value=args["hash_value"],
                client=self.cti_client,  # For backward compatibility
                clients=self.cti_clients if self.cti_clients else None,  # Pass list of clients
            )
            self._mcp_logger.debug(f"Tool {tool_name} completed successfully")
            return result

        # Rules engine tools
        elif tool_name == "list_rules":
            result = {"rules": self.rules_engine.list_rules()}
            self._mcp_logger.debug(
                f"Tool {tool_name} completed: {len(result['rules'])} rules found"
            )
            return result
        elif tool_name == "execute_rule":
            result = self.rules_engine.execute_rule(
                rule_name=args["rule_name"],
                context=args.get("context"),
            )
            self._mcp_logger.info(
                f"Tool {tool_name} executed: rule '{args['rule_name']}' completed"
            )
            return result

        # Knowledge base tools (client infrastructure)
        elif tool_name == "kb_list_clients" and self.kb_client:
            result = tools_kb.list_kb_clients(client=self.kb_client)
            self._mcp_logger.debug(
                f"Tool {tool_name} completed: {result.get('count', 0)} clients found"
            )
            return result
        elif tool_name == "kb_get_client_infra" and self.kb_client:
            result = tools_kb.get_client_infra(
                client_name=args["client_name"],
                client=self.kb_client,
            )
            self._mcp_logger.debug(
                f"Tool {tool_name} completed for client {result.get('client_name')}"
            )
            return result

        # Engineering tools (Trello/ClickUp)
        elif tool_name == "create_fine_tuning_recommendation" and self.eng_client:
            result = tools_eng.create_fine_tuning_recommendation(
                title=args["title"],
                description=args["description"],
                list_name=args.get("list_name"),
                labels=args.get("labels"),
                status=args.get("status"),
                tags=args.get("tags"),
                client=self.eng_client,
            )
            provider = result.get("provider", "unknown")
            self._mcp_logger.info(
                f"Tool {tool_name} executed: fine-tuning recommendation '{args['title']}' created ({provider})"
            )
            return result
        elif tool_name == "create_visibility_recommendation" and self.eng_client:
            result = tools_eng.create_visibility_recommendation(
                title=args["title"],
                description=args["description"],
                list_name=args.get("list_name"),
                labels=args.get("labels"),
                status=args.get("status"),
                tags=args.get("tags"),
                client=self.eng_client,
            )
            provider = result.get("provider", "unknown")
            self._mcp_logger.info(
                f"Tool {tool_name} executed: visibility recommendation '{args['title']}' created ({provider})"
            )
            return result
        elif tool_name == "list_fine_tuning_recommendations" and self.eng_client:
            result = tools_eng.list_fine_tuning_recommendations(
                archived=args.get("archived", False),
                include_closed=args.get("include_closed", True),
                order_by=args.get("order_by"),
                reverse=args.get("reverse", False),
                subtasks=args.get("subtasks", False),
                statuses=args.get("statuses"),
                include_markdown_description=args.get("include_markdown_description", False),
                client=self.eng_client,
            )
            count = result.get("count", 0)
            self._mcp_logger.info(
                f"Tool {tool_name} executed: found {count} fine-tuning recommendations"
            )
            return result
        elif tool_name == "list_visibility_recommendations" and self.eng_client:
            result = tools_eng.list_visibility_recommendations(
                archived=args.get("archived", False),
                include_closed=args.get("include_closed", True),
                order_by=args.get("order_by"),
                reverse=args.get("reverse", False),
                subtasks=args.get("subtasks", False),
                statuses=args.get("statuses"),
                include_markdown_description=args.get("include_markdown_description", False),
                client=self.eng_client,
            )
            count = result.get("count", 0)
            self._mcp_logger.info(
                f"Tool {tool_name} executed: found {count} visibility recommendations"
            )
            return result
        elif tool_name == "add_comment_to_fine_tuning_recommendation" and self.eng_client:
            result = tools_eng.add_comment_to_fine_tuning_recommendation(
                task_id=args["task_id"],
                comment_text=args["comment_text"],
                client=self.eng_client,
            )
            self._mcp_logger.info(
                f"Tool {tool_name} executed: comment added to fine-tuning recommendation task {args['task_id']}"
            )
            return result
        elif tool_name == "add_comment_to_visibility_recommendation" and self.eng_client:
            result = tools_eng.add_comment_to_visibility_recommendation(
                task_id=args["task_id"],
                comment_text=args["comment_text"],
                client=self.eng_client,
            )
            self._mcp_logger.info(
                f"Tool {tool_name} executed: comment added to visibility recommendation task {args['task_id']}"
            )
            return result

        # Runbook tools
        elif tool_name == "list_runbooks":
            result = self._handle_list_runbooks(
                soc_tier=args.get("soc_tier"),
                category=args.get("category")
            )
            self._mcp_logger.debug(
                f"Tool {tool_name} completed: {result.get('count', 0)} runbooks found"
            )
            return result
        elif tool_name == "get_runbook":
            result = self._handle_get_runbook(runbook_name=args["runbook_name"])
            self._mcp_logger.debug(f"Tool {tool_name} completed: {args['runbook_name']}")
            return result
        elif tool_name == "execute_runbook":
            result = self._handle_execute_runbook(
                runbook_name=args["runbook_name"],
                case_id=args.get("case_id"),
                alert_id=args.get("alert_id"),
                soc_tier=args.get("soc_tier")
            )
            self._mcp_logger.info(
                f"Tool {tool_name} executed: runbook '{args['runbook_name']}' provided for execution"
            )
            return result

        # Agent profile tools
        elif tool_name == "list_agent_profiles":
            result = {"profiles": self.agent_profile_manager.list_profiles(), "count": len(self.agent_profile_manager.profiles)}
            self._mcp_logger.debug(
                f"Tool {tool_name} completed: {result['count']} agent profiles found"
            )
            return result
        elif tool_name == "get_agent_profile":
            result = self._handle_get_agent_profile(agent_id=args["agent_id"])
            self._mcp_logger.debug(f"Tool {tool_name} completed: {args['agent_id']}")
            return result
        elif tool_name == "route_case_to_agent":
            result = self._handle_route_case_to_agent(
                case_id=args.get("case_id"),
                alert_id=args.get("alert_id"),
                alert_type=args.get("alert_type"),
                case_status=args.get("case_status")
            )
            self._mcp_logger.info(f"Tool {tool_name} executed: routed to {result.get('agent_id')}")
            return result
        elif tool_name == "execute_as_agent":
            result = self._handle_execute_as_agent(
                agent_id=args["agent_id"],
                case_id=args.get("case_id"),
                alert_id=args.get("alert_id"),
                runbook_name=args.get("runbook_name")
            )
            self._mcp_logger.info(
                f"Tool {tool_name} executed: agent '{args['agent_id']}' executing runbook"
            )
            return result
        else:
            self._mcp_logger.error(
                f"Tool not available or client not configured: {tool_name}"
            )
            raise ValueError(f"Tool not available: {tool_name}")


async def _read_stdio():
    """
    Read lines from stdin asynchronously.
    
    Uses a thread-based approach that works with both pipes and TTY stdin,
    which is required for MCP server compatibility.
    """
    import queue
    import threading
    
    mcp_logger = logging.getLogger("sami.mcp")
    mcp_logger.debug("Starting stdin reader")
    
    line_queue: queue.Queue = queue.Queue()
    
    def read_stdin():
        """Read from stdin synchronously in a background thread."""
        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    line_queue.put(None)  # Signal EOF
                    break
                line_queue.put(line.rstrip('\n\r'))
        except Exception as e:
            line_queue.put(e)
        except (EOFError, BrokenPipeError):
            line_queue.put(None)  # Signal EOF
    
    thread = threading.Thread(target=read_stdin, daemon=True)
    thread.start()
    
    while True:
        try:
            # Poll the queue for items
            try:
                item = line_queue.get_nowait()
            except queue.Empty:
                # Check if thread is still alive
                if not thread.is_alive():
                    mcp_logger.debug("stdin reader thread died")
                    break
                # Wait a bit before checking again
                await asyncio.sleep(0.01)
                continue
                
            if item is None:  # EOF
                mcp_logger.debug("stdin closed (EOF)")
                break
            if isinstance(item, Exception):
                raise item
            if item:  # Skip empty lines
                mcp_logger.debug(f"Received line from stdin ({len(item)} chars): {item[:200]}...")
                # Try to parse and log structure if it's JSON
                try:
                    parsed = json.loads(item)
                    mcp_logger.debug(f"Parsed JSON structure - method: {parsed.get('method')}, has_id: {'id' in parsed}, id_value: {parsed.get('id')}")
                except:
                    pass  # Not JSON, that's okay
                yield item
        except asyncio.CancelledError:
            mcp_logger.debug("stdin reader cancelled")
            break
        except Exception as e:
            mcp_logger.error(f"Error reading from stdin: {e}", exc_info=True)
            logger.error(f"Error reading from stdin: {e}", exc_info=True)
            break


async def main() -> None:
    """Main entry point for the MCP server."""
    # Load configuration from JSON file only (ignore .env)
    import json
    from pathlib import Path
    from ..core.config_storage import _dict_to_config
    
    # Find config.json relative to project root (where this file is located)
    # This ensures it works regardless of the current working directory
    # Path: src/mcp/mcp_server.py -> src/mcp/ -> src/ -> project root
    project_root = Path(__file__).parent.parent.parent
    config_file = project_root / "config.json"
    config = None
    
    try:
        if config_file.exists():
            with open(config_file, "r") as f:
                data = json.load(f)
            config = _dict_to_config(data)
            logger.info(f"Configuration loaded successfully from {config_file}")
        else:
            logger.warning(f"config.json not found at {config_file}, using defaults")
            from ..core.config import LoggingConfig
            config = SamiConfig(
                thehive=None,
                iris=None,
                elastic=None,
                edr=None,
                logging=LoggingConfig(),
            )
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {config_file}: {e}", exc_info=True)
        from ..core.config import LoggingConfig
        config = SamiConfig(
            thehive=None,
            iris=None,
            elastic=None,
            edr=None,
            logging=LoggingConfig(),
        )
    except Exception as e:
        logger.error(f"Failed to load {config_file}, using defaults: {e}", exc_info=True)
        from ..core.config import LoggingConfig
        config = SamiConfig(
            thehive=None,
            iris=None,
            elastic=None,
            edr=None,
            logging=LoggingConfig(),
        )
    
    configure_logging(config.logging)
    
    # Configure dedicated MCP logging
    mcp_log_dir = config.logging.log_dir if config.logging else "logs"
    configure_mcp_logging(mcp_log_dir)

    logger.info("Starting SamiGPT MCP Server...")
    mcp_logger = logging.getLogger("sami.mcp")
    mcp_logger.info("=" * 80)
    mcp_logger.info("MCP Server Starting")
    mcp_logger.info("=" * 80)

    # Initialize clients
    case_client = None
    
    # Log configuration status
    mcp_logger.info("Configuration Status:")
    mcp_logger.info(f"  IRIS configured: {config.iris is not None}")
    if config.iris:
        mcp_logger.info(f"    IRIS URL: {config.iris.base_url}")
        mcp_logger.info(f"    IRIS API key: {'*' * 20}...{config.iris.api_key[-10:] if len(config.iris.api_key) > 10 else '***'}")
    mcp_logger.info(f"  TheHive configured: {config.thehive is not None}")
    mcp_logger.info(f"  Elastic configured: {config.elastic is not None}")
    mcp_logger.info(f"  EDR configured: {config.edr is not None}")
    mcp_logger.info(f"  CTI configured: {config.cti is not None}")
    
    # Prioritize IRIS if both are configured
    if config.iris:
        try:
            mcp_logger.info("Attempting to initialize IRIS case management client...")
            case_client = IRISCaseManagementClient.from_config(config)
            logger.info("IRIS case management client initialized")
            mcp_logger.info("✓ IRIS case management client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize IRIS client: {e}")
            mcp_logger.error(f"✗ Failed to initialize IRIS client: {e}", exc_info=True)
    elif config.thehive:
        try:
            mcp_logger.info("Attempting to initialize TheHive case management client...")
            case_client = TheHiveCaseManagementClient.from_config(config)
            logger.info("TheHive case management client initialized")
            mcp_logger.info("✓ TheHive case management client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize TheHive client: {e}")
            mcp_logger.error(f"✗ Failed to initialize TheHive client: {e}", exc_info=True)
    else:
        mcp_logger.warning("No case management system configured (neither IRIS nor TheHive)")

    # Initialize SIEM client
    siem_client = None
    if config.elastic:
        try:
            mcp_logger.info("Attempting to initialize Elastic SIEM client...")
            siem_client = ElasticSIEMClient.from_config(config)
            logger.info("Elastic SIEM client initialized")
            mcp_logger.info("✓ Elastic SIEM client initialized successfully")
            if config.elastic:
                mcp_logger.info(f"    Elastic URL: {config.elastic.base_url}")
                mcp_logger.info(f"    Elastic API key: {'*' * 20}...{config.elastic.api_key[-10:] if config.elastic.api_key and len(config.elastic.api_key) > 10 else '***'}")
        except Exception as e:
            logger.error(f"Failed to initialize Elastic SIEM client: {e}")
            mcp_logger.error(f"✗ Failed to initialize Elastic SIEM client: {e}", exc_info=True)
    
    # Initialize EDR client
    edr_client = None
    if config.edr:
        if config.edr.edr_type == "elastic_defend":
            try:
                mcp_logger.info("Attempting to initialize Elastic Defend EDR client...")
                edr_client = ElasticDefendEDRClient.from_config(config)
                logger.info("Elastic Defend EDR client initialized")
                mcp_logger.info("✓ Elastic Defend EDR client initialized successfully")
                if config.edr:
                    mcp_logger.info(f"    EDR URL: {config.edr.base_url}")
                    mcp_logger.info(f"    EDR Type: {config.edr.edr_type}")
                    mcp_logger.info(f"    EDR API key: {'*' * 20}...{config.edr.api_key[-10:] if config.edr.api_key and len(config.edr.api_key) > 10 else '***'}")
            except Exception as e:
                logger.error(f"Failed to initialize Elastic Defend EDR client: {e}")
                mcp_logger.error(f"✗ Failed to initialize Elastic Defend EDR client: {e}", exc_info=True)
        else:
            logger.info(
                f"EDR configuration found ({config.edr.edr_type}), but integration not yet implemented"
            )
            mcp_logger.warning(
                f"EDR type '{config.edr.edr_type}' is not yet implemented. Only 'elastic_defend' is supported."
            )

    # Initialize CTI client(s) - support both single and multiple platforms
    cti_clients = []
    cti_client = None  # For backward compatibility
    
    # Check for main CTI config
    if config.cti:
        if config.cti.cti_type == "local_tip":
            try:
                mcp_logger.info("Attempting to initialize Local TIP CTI client...")
                local_tip_client = LocalTipCTIClient.from_config(config)
                cti_clients.append(local_tip_client)
                cti_client = local_tip_client  # For backward compatibility
                logger.info("Local TIP CTI client initialized")
                mcp_logger.info("✓ Local TIP CTI client initialized successfully")
                mcp_logger.info(f"    CTI URL: {config.cti.base_url}")
                mcp_logger.info(f"    CTI Type: {config.cti.cti_type}")
            except Exception as e:
                logger.error(f"Failed to initialize Local TIP CTI client: {e}")
                mcp_logger.error(f"✗ Failed to initialize Local TIP CTI client: {e}", exc_info=True)
        elif config.cti.cti_type == "opencti":
            try:
                mcp_logger.info("Attempting to initialize OpenCTI client...")
                opencti_client = OpenCTIClient.from_config(config)
                cti_clients.append(opencti_client)
                cti_client = opencti_client  # For backward compatibility
                logger.info("OpenCTI client initialized")
                mcp_logger.info("✓ OpenCTI client initialized successfully")
                mcp_logger.info(f"    CTI URL: {config.cti.base_url}")
                mcp_logger.info(f"    CTI Type: {config.cti.cti_type}")
            except Exception as e:
                logger.error(f"Failed to initialize OpenCTI client: {e}")
                mcp_logger.error(f"✗ Failed to initialize OpenCTI client: {e}", exc_info=True)
        else:
            logger.info(
                f"CTI configuration found ({config.cti.cti_type}), but integration not yet implemented"
            )
            mcp_logger.warning(
                f"CTI type '{config.cti.cti_type}' is not yet implemented. Supported types: 'local_tip', 'opencti'."
            )
    
    # Check for additional CTI config (cti_opencti) to support both platforms
    # This allows config.json to have both "cti" (local_tip) and "cti_opencti" (opencti)
    config_dict = None
    try:
        from ..core.config_storage import load_config_from_file
        import json
        import os
        config_file = os.getenv("SAMIGPT_CONFIG_FILE", "config.json")
        if os.path.exists(config_file):
            with open(config_file, "r") as f:
                config_dict = json.load(f)
    except Exception:
        pass  # If we can't load config dict, that's okay
    
    if config_dict and "cti_opencti" in config_dict:
        cti_opencti_config = config_dict["cti_opencti"]
        if cti_opencti_config.get("cti_type") == "opencti":
            try:
                # Create a temporary config with OpenCTI settings
                from ..core.config import CTIConfig, SamiConfig
                opencti_config = CTIConfig(
                    cti_type="opencti",
                    base_url=cti_opencti_config.get("base_url"),
                    api_key=cti_opencti_config.get("api_key"),
                    timeout_seconds=cti_opencti_config.get("timeout_seconds", 30),
                    verify_ssl=cti_opencti_config.get("verify_ssl", True),
                )
                temp_config = SamiConfig(cti=opencti_config)
                
                mcp_logger.info("Attempting to initialize additional OpenCTI client...")
                opencti_client = OpenCTIClient.from_config(temp_config)
                # Only add if we don't already have an OpenCTI client
                if not any("OpenCTI" in c.__class__.__name__ for c in cti_clients):
                    cti_clients.append(opencti_client)
                    logger.info("Additional OpenCTI client initialized")
                    mcp_logger.info("✓ Additional OpenCTI client initialized successfully")
                    mcp_logger.info(f"    CTI URL: {opencti_config.base_url}")
            except Exception as e:
                logger.error(f"Failed to initialize additional OpenCTI client: {e}")
                mcp_logger.error(f"✗ Failed to initialize additional OpenCTI client: {e}", exc_info=True)
    
    # Also check for cti_local_tip if main cti is opencti
    if config_dict and "cti_local_tip" in config_dict:
        cti_local_tip_config = config_dict["cti_local_tip"]
        if cti_local_tip_config.get("cti_type") == "local_tip":
            try:
                from ..core.config import CTIConfig, SamiConfig
                local_tip_config = CTIConfig(
                    cti_type="local_tip",
                    base_url=cti_local_tip_config.get("base_url"),
                    api_key=cti_local_tip_config.get("api_key"),
                    timeout_seconds=cti_local_tip_config.get("timeout_seconds", 30),
                    verify_ssl=cti_local_tip_config.get("verify_ssl", False),
                )
                temp_config = SamiConfig(cti=local_tip_config)
                
                mcp_logger.info("Attempting to initialize additional Local TIP client...")
                local_tip_client = LocalTipCTIClient.from_config(temp_config)
                # Only add if we don't already have a Local TIP client
                if not any("LocalTip" in c.__class__.__name__ for c in cti_clients):
                    cti_clients.append(local_tip_client)
                    logger.info("Additional Local TIP client initialized")
                    mcp_logger.info("✓ Additional Local TIP client initialized successfully")
                    mcp_logger.info(f"    CTI URL: {local_tip_config.base_url}")
            except Exception as e:
                logger.error(f"Failed to initialize additional Local TIP client: {e}")
                mcp_logger.error(f"✗ Failed to initialize additional Local TIP client: {e}", exc_info=True)
    
    if len(cti_clients) > 1:
        mcp_logger.info(f"✓ Multiple CTI platforms configured: {len(cti_clients)} platforms will be queried concurrently")

    # Initialize Engineering client (Trello, ClickUp, or GitHub)
    eng_client = None
    if config.eng:
        provider = config.eng.provider.lower() if config.eng.provider else "trello"
        
        if provider == "github" and config.eng.github:
            try:
                eng_client = GitHubClient.from_config(config)
                mcp_logger.info("✓ GitHub (Engineering) client initialized")
            except Exception as e:
                mcp_logger.warning(f"Failed to initialize GitHub client: {e}")
        elif provider == "clickup" and config.eng.clickup:
            try:
                eng_client = ClickUpClient.from_config(config)
                mcp_logger.info("✓ ClickUp (Engineering) client initialized")
            except Exception as e:
                mcp_logger.warning(f"Failed to initialize ClickUp client: {e}")
        elif provider == "trello" and config.eng.trello:
            try:
                eng_client = TrelloClient.from_config(config)
                mcp_logger.info("✓ Trello (Engineering) client initialized")
            except Exception as e:
                mcp_logger.warning(f"Failed to initialize Trello client: {e}")
        else:
            # Try to auto-detect based on what's configured (priority: GitHub > ClickUp > Trello)
            if config.eng.github:
                try:
                    eng_client = GitHubClient.from_config(config)
                    mcp_logger.info("✓ GitHub (Engineering) client initialized (auto-detected)")
                except Exception as e:
                    mcp_logger.warning(f"Failed to initialize GitHub client: {e}")
            elif config.eng.clickup:
                try:
                    eng_client = ClickUpClient.from_config(config)
                    mcp_logger.info("✓ ClickUp (Engineering) client initialized (auto-detected)")
                except Exception as e:
                    mcp_logger.warning(f"Failed to initialize ClickUp client: {e}")
            elif config.eng.trello:
                try:
                    eng_client = TrelloClient.from_config(config)
                    mcp_logger.info("✓ Trello (Engineering) client initialized (auto-detected)")
                except Exception as e:
                    mcp_logger.warning(f"Failed to initialize Trello client: {e}")

    # Create MCP server
    server = SamiGPTMCPServer(
        case_client=case_client,
        siem_client=siem_client,
        edr_client=edr_client,
        cti_client=cti_client,  # For backward compatibility
        cti_clients=cti_clients if len(cti_clients) > 0 else None,  # Pass list of clients
        eng_client=eng_client,
    )

    # Log tool registration summary
    total_tools = len(server.tools)
    logger.info(f"MCP server initialized with {total_tools} tools")
    mcp_logger.info("=" * 80)
    mcp_logger.info(f"Tool Registration Summary:")
    mcp_logger.info(f"  Total tools available: {total_tools}")
    mcp_logger.info(f"  Case Management: {'✓ Configured' if case_client else '✗ Not configured (8 tools unavailable)'}")
    mcp_logger.info(f"  SIEM: {'✓ Configured' if siem_client else '✗ Not configured (16 tools unavailable)'}")
    mcp_logger.info(f"  EDR: {'✓ Configured' if edr_client else '✗ Not configured (6 tools unavailable)'}")
    mcp_logger.info(f"  CTI: {'✓ Configured' if cti_client else '✗ Not configured (1 tool unavailable)'}")
    eng_provider = "None"
    if eng_client:
        if isinstance(eng_client, GitHubClient):
            eng_provider = "GitHub"
        elif isinstance(eng_client, ClickUpClient):
            eng_provider = "ClickUp"
        elif isinstance(eng_client, TrelloClient):
            eng_provider = "Trello"
    mcp_logger.info(f"  Engineering ({eng_provider}): {'✓ Configured' if eng_client else '✗ Not configured (2 tools unavailable)'}")
    mcp_logger.info(f"  Rules Engine: ✓ Always available (2 tools)")
    mcp_logger.info("=" * 80)
    
    if total_tools == 2:
        mcp_logger.warning(
            "⚠️  Only rules engine tools are available. "
            "Configure integrations in config.json to enable case management, SIEM, and EDR tools. "
            "Use the web configuration UI: python -m src.web.config_server"
        )

    # Run MCP server (stdio mode)
    try:
        async for line in _read_stdio():
            try:
                if not line or not line.strip():
                    continue
                    
                # Parse JSON request
                try:
                    request = json.loads(line)
                except json.JSONDecodeError as e:
                    mcp_logger.error(
                        f"Invalid JSON received: {line[:200]}... Error: {e}"
                    )
                    logger.error(f"Invalid JSON: {line[:100]}... Error: {e}")
                    # Send error response for parse errors
                    error_response = {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32700,
                            "message": "Parse error",
                        },
                    }
                    sys.stdout.write(json.dumps(error_response, ensure_ascii=False) + "\n")
                    sys.stdout.flush()
                    continue
                
                # Log what we're about to process
                mcp_logger.debug(f"Processing request: {json.dumps(request)[:500]}")
                
                response = await server.handle_request(request)
                
                # Handle notifications (they don't get responses)
                if response is None:
                    mcp_logger.debug("Request was a notification, no response sent")
                    continue
                
                # Ensure response is properly formatted and sent
                if response:
                    try:
                        # Log response before sending
                        response_preview = json.dumps(response, ensure_ascii=False)[:500]
                        mcp_logger.debug(f"Preparing to send response: {response_preview}")
                        
                        # Serialize response to JSON (ensure_ascii=False for proper Unicode)
                        response_json = json.dumps(response, ensure_ascii=False)
                        # Write directly to stdout with explicit newline and flush
                        sys.stdout.write(response_json + "\n")
                        sys.stdout.flush()
                        
                        # Log successful response sending
                        # Extract request_id properly (only if valid)
                        request_id = None
                        if "id" in request and request["id"] is not None:
                            request_id = request["id"]
                        method = request.get("method")
                        
                        mcp_logger.info(
                            f"RESPONSE [id={request_id}] {method} sent successfully: {len(response_json)} bytes"
                        )
                        
                        if method == "tools/list":
                            tools_count = len(response.get("result", {}).get("tools", []))
                            mcp_logger.info(
                                f"RESPONSE [id={request_id}] tools/list sent successfully with {tools_count} tools"
                            )
                        
                        # After initialize response, send initialized notification
                        if method == "initialize":
                            initialized_notification = {
                                "jsonrpc": "2.0",
                                "method": "notifications/initialized",
                                "params": {}
                            }
                            notification_json = json.dumps(initialized_notification, ensure_ascii=False)
                            mcp_logger.info(
                                f"Sending initialized notification (no id field): {notification_json}"
                            )
                            sys.stdout.write(notification_json + "\n")
                            sys.stdout.flush()
                            mcp_logger.debug("Initialized notification sent successfully")
                    except (TypeError, ValueError) as json_error:
                        # JSON serialization error
                        mcp_logger.error(
                            f"JSON serialization error for response: {json_error}",
                            exc_info=True,
                        )
                        logger.error(f"JSON serialization error: {json_error}", exc_info=True)
                        # Send error response
                        # Extract request_id properly (only if valid)
                        request_id = None
                        if isinstance(request, dict) and "id" in request and request["id"] is not None:
                            request_id = request["id"]
                        error_response = server._create_error_response(
                            request_id,
                            -32603,
                            f"Internal error: Failed to serialize response: {str(json_error)}",
                        )
                        sys.stdout.write(
                            json.dumps(error_response, ensure_ascii=False) + "\n"
                        )
                        sys.stdout.flush()
                else:
                    # No response returned - should not happen
                    mcp_logger.warning(
                        f"No response returned for request: {request.get('method')}"
                    )
                    
            except Exception as e:
                mcp_logger.error(
                    f"Error processing request: {e}", exc_info=True
                )
                logger.error(f"Error processing request: {e}", exc_info=True)
                # Send error response
                # Extract request_id properly (only if valid)
                request_id = None
                if isinstance(request, dict) and "id" in request:
                    req_id = request["id"]
                    # Only include id if it's a valid value (string or number, not None/null)
                    if req_id is not None:
                        request_id = req_id
                
                error_response = server._create_error_response(
                    request_id,
                    -32603,
                    f"Internal error: {str(e)}",
                )
                
                try:
                    sys.stdout.write(
                        json.dumps(error_response, ensure_ascii=False) + "\n"
                    )
                    sys.stdout.flush()
                except Exception as print_error:
                    # Last resort - write raw error
                    mcp_logger.critical(f"Failed to send error response: {print_error}")
                    logger.critical(f"Failed to send error response: {print_error}")
    except KeyboardInterrupt:
        mcp_logger = logging.getLogger("sami.mcp")
        mcp_logger.info("=" * 80)
        mcp_logger.info("MCP Server Shutting Down (KeyboardInterrupt)")
        mcp_logger.info("=" * 80)
        logger.info("MCP server shutting down...")
    except Exception as e:
        mcp_logger = logging.getLogger("sami.mcp")
        mcp_logger.critical(f"FATAL ERROR in MCP server: {e}", exc_info=True)
        logger.error(f"Fatal error in MCP server: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
