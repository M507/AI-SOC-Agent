"""
Web server for AI Controller.

Provides a web interface for managing and executing agent commands,
with real-time updates via WebSocket.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..agent_executor import AgentExecutor, ExecutionResult
from ..session_manager import SessionManager, Session, SessionType, SessionStatus, AutorunConfig
from ...core.logging import get_logger

logger = get_logger("sami.ai_controller.web.server")

# Create FastAPI app
app = FastAPI(
    title="SamiGPT AI Controller",
    description="Web interface for managing and executing agent commands",
    version="1.0.0",
)

# Initialize components
executor: Optional[AgentExecutor] = None
session_manager: Optional[SessionManager] = None

# UI behavior flags (e.g., controlled by CLI flags like --debug)
UI_DEBUG_MODE: bool = False

# WebSocket connections by session ID
active_connections: Dict[str, List[WebSocket]] = {}

# Currently running execution tasks keyed by session ID (for cancellation)
running_tasks: Dict[str, asyncio.Task] = {}

# Autorun scheduler state
autorun_scheduler_task: Optional[asyncio.Task] = None
running_autoruns: set[str] = set()


class CommandRequest(BaseModel):
    """Request to execute a command."""
    command: str
    session_id: Optional[str] = None
    session_name: Optional[str] = None


class AutorunCreateRequest(BaseModel):
    """Request to create an autorun."""
    name: str
    command: str
    interval_seconds: int
    condition_function: Optional[str] = None  # Function/tool name to check before executing


class AutorunUpdateRequest(BaseModel):
    """Request to update an autorun."""
    enabled: Optional[bool] = None
    interval_seconds: Optional[int] = None
    name: Optional[str] = None
    condition_function: Optional[str] = None  # Function/tool name to check before executing


class UIConfigUpdate(BaseModel):
    """Request to update UI configuration flags."""
    ui_debug: Optional[bool] = None


def initialize(config_storage_dir: Optional[str] = None, debug_ui: bool = False):
    """Initialize the web server components."""
    global executor, session_manager, UI_DEBUG_MODE
    
    try:
        if config_storage_dir:
            session_manager = SessionManager(storage_dir=config_storage_dir)
        else:
            session_manager = SessionManager()
        
        # Load config for executor
        from ...core.config_storage import load_config_from_file
        config = load_config_from_file()
        executor = AgentExecutor(config)
        
        UI_DEBUG_MODE = debug_ui
        logger.info(
            "AI Controller web server initialized (ui_debug_mode=%s, storage_dir=%s)",
            UI_DEBUG_MODE,
            config_storage_dir or "default",
        )
    except Exception as e:
        logger.exception("Error initializing web server components")
        raise


async def _run_autorun(autorun: AutorunConfig):
    """
    Execute a single autorun:
    - Checks condition function if configured (skips if condition returns empty)
    - Creates an AUTORUN session
    - Executes the configured starting prompt
    - Records output in the session entries
    - Updates last_run / next_run on the autorun config
    """
    if not executor or not session_manager:
        logger.warning("Executor or session manager not initialized; skipping autorun %s", autorun.id)
        return

    try:
        logger.info("Executing autorun %s (%s)", autorun.id, autorun.name)

        # Use a persistent AUTORUN session for this autorun
        # Reload latest config to get any updated session_id
        fresh_autorun = session_manager.get_autorun(autorun.id) or autorun

        # Get or create session first (needed for condition logging)
        session_id = fresh_autorun.session_id
        session = session_manager.get_session(session_id) if session_id else None

        # If the session was deleted or never created, create a new one and persist it
        if not session:
            session_name = f"Autorun: {fresh_autorun.name}"
            logger.debug("Creating new AUTORUN session for autorun %s (%s)", fresh_autorun.id, session_name)
            session = session_manager.create_session(session_name, SessionType.AUTORUN)
            session_manager.update_autorun(fresh_autorun.id, session_id=session.id)
            session_id = session.id

        # Check condition function if configured
        # Validate that condition_function is not None and not empty string
        condition_function = fresh_autorun.condition_function
        if condition_function and condition_function.strip():
            logger.info("Checking condition function '%s' for autorun %s (%s)", 
                       condition_function, fresh_autorun.id, fresh_autorun.name)
            condition_result, condition_details = await _check_autorun_condition(condition_function, executor)
            
            # Add condition check entry to session
            condition_command_str = f"[CONDITION CHECK] {condition_function}"
            condition_entry = session_manager.add_entry(session_id, condition_command_str)
            
            # Create result for condition check.
            #
            # Debug mode controls how much JSON detail we keep. In non‑debug mode
            # we only want the high‑level evaluation string to appear in the chat
            # (e.g. "✗ CONDITION FAILED: No uninvestigated alerts found ...").
            if UI_DEBUG_MODE:
                # Verbose debug mode: include all details for troubleshooting.
                condition_result_dict = {
                    "success": condition_result,
                    "condition_function": condition_function,
                    "should_proceed": condition_result,
                    "details": condition_details,
                    "output": condition_details.get("output"),
                    "evaluation": condition_details.get("evaluation", ""),
                    "command_executed": condition_details.get("command_executed"),
                    "execution_success": condition_details.get("execution_success"),
                    "output_type": condition_details.get("output_type"),
                    "uninvestigated_alerts": condition_details.get("uninvestigated_alerts"),
                    "total_alerts": condition_details.get("total_alerts"),
                    "groups_count": condition_details.get("groups_count"),
                }
                if "error" in condition_details:
                    condition_result_dict["error"] = condition_details.get("error")
            else:
                # Non-debug mode: slimmer payload. We deliberately set `output`
                # to the evaluation string so the frontend shows only that text
                # in the chat instead of raw JSON or nested tool output.
                condition_result_dict = {
                    "success": condition_result,
                    "condition_function": condition_function,
                    "should_proceed": condition_result,
                    "evaluation": condition_details.get("evaluation", ""),
                    "output": condition_details.get("evaluation", ""),
                }
                # Only include key metrics if available
                if condition_details.get("uninvestigated_alerts") is not None:
                    condition_result_dict["uninvestigated_alerts"] = condition_details.get("uninvestigated_alerts")
            
            session_manager.update_entry(
                session_id,
                condition_entry.id,
                result=condition_result_dict,
                status=SessionStatus.COMPLETED,
            )
            
            # Broadcast condition check result
            await broadcast_to_session(session_id, {
                "type": "execution_completed",
                "entry_id": condition_entry.id,
                "result": condition_result_dict,
            })
            
            if not condition_result:
                logger.info(
                    "Condition function '%s' returned empty result for autorun %s (%s). Skipping execution.",
                    condition_function,
                    fresh_autorun.id,
                    fresh_autorun.name
                )
                # Update schedule but don't execute
                now = datetime.now()
                next_run = now + timedelta(seconds=fresh_autorun.interval_seconds)
                session_manager.update_autorun(
                    fresh_autorun.id,
                    last_run=now,
                    next_run=next_run,
                )
                return
            else:
                logger.info(
                    "Condition function '%s' returned content for autorun %s (%s). Proceeding with execution.",
                    condition_function,
                    fresh_autorun.id,
                    fresh_autorun.name
                )
        else:
            logger.warning(
                "Autorun %s (%s) has no condition function configured (value: %s) - proceeding without condition check. "
                "This autorun will execute regardless of conditions.",
                fresh_autorun.id, 
                fresh_autorun.name,
                repr(condition_function)
            )

        # Parse and execute command
        command_str = fresh_autorun.command
        logger.debug("Parsed autorun command for %s: %s", fresh_autorun.id, command_str)
        command = executor.parse_command(command_str)

        # Add entry and mark session as running
        entry = session_manager.add_entry(session_id, command_str)
        session_manager.update_session_status(session_id, SessionStatus.RUNNING)

        # Broadcast that autorun execution started for any connected clients
        await broadcast_to_session(session_id, {
            "type": "execution_started",
            "entry_id": entry.id,
            "command": command_str,
        })

        result: Optional[ExecutionResult] = await executor.execute_command(command)

        # Update entry and session status
        status = SessionStatus.COMPLETED if result and result.success else SessionStatus.FAILED
        session_manager.update_entry(
            session_id,
            entry.id,
            result=result.to_dict() if result else None,
            status=status,
        )
        session_manager.update_session_status(session_id, status)

        # Broadcast result so any open terminals update live
        await broadcast_to_session(session_id, {
            "type": "execution_completed",
            "entry_id": entry.id,
            "result": result.to_dict() if result else None,
        })

        # Update autorun schedule (last_run / next_run)
        now = datetime.now()
        next_run = now + timedelta(seconds=fresh_autorun.interval_seconds)
        session_manager.update_autorun(
            fresh_autorun.id,
            last_run=now,
            next_run=next_run,
        )

        logger.info(
            "Completed autorun %s (%s) with status %s; next run at %s (session_id=%s)",
            fresh_autorun.id,
            fresh_autorun.name,
            status.value,
            next_run.isoformat(),
            session_id,
        )
    except Exception as e:
        logger.exception("Error executing autorun %s (%s): %s", autorun.id, autorun.name, e)
        # Best-effort: still push next_run forward to avoid tight failure loops
        try:
            now = datetime.now()
            next_run = now + timedelta(seconds=autorun.interval_seconds)
            session_manager.update_autorun(
                autorun.id,
                last_run=now,
                next_run=next_run,
            )
        except Exception:
            logger.warning("Failed to update schedule for autorun %s after error", autorun.id)
    finally:
        running_autoruns.discard(autorun.id)


async def _check_autorun_condition(condition_function: str, executor: AgentExecutor) -> Tuple[bool, Dict[str, Any]]:
    """
    Check if an autorun condition function returns content.
    
    Returns:
        tuple: (should_proceed: bool, details: dict)
        - should_proceed: True if the function returns non-empty content (should proceed),
          False if it returns empty/None (should skip execution)
        - details: Dictionary with verbose information about the condition check
    """
    details = {
        "condition_function": condition_function,
        "command_executed": None,
        "execution_success": False,
        "output": None,
        "output_type": None,
        "evaluation": "",
        "uninvestigated_alerts": None,
        "total_alerts": None,
        "groups_count": None,
        "cases_count": None,
    }
    
    try:
        # SPECIAL-CASE: get_recent_alerts should be executed directly at the Python level,
        #               not via the AI agent / cursor-agent. This avoids consuming AI
        #               tokens just to check if there is work to do.
        if condition_function == "get_recent_alerts":
            try:
                # Import here to avoid heavy imports at module load
                from ...core.config_storage import load_config_from_file
                from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient
                from src.orchestrator.tools_siem import get_recent_alerts
            except Exception as e:
                logger.exception("Failed to import dependencies for get_recent_alerts condition: %s", e)
                details["evaluation"] = "✗ CONDITION ERROR: Failed to import get_recent_alerts dependencies"
                details["error"] = str(e)
                return False, details

            try:
                config = load_config_from_file()
                if not getattr(config, "elastic", None):
                    msg = "Elastic SIEM is not configured; cannot evaluate get_recent_alerts condition"
                    logger.warning(msg)
                    details["evaluation"] = f"✗ CONDITION ERROR: {msg}"
                    details["error"] = msg
                    return False, details

                # Build SIEM client directly from config
                siem_client = ElasticSIEMClient.from_config(config)
                details["command_executed"] = "python:get_recent_alerts(hours_back=1, max_alerts=100)"

                logger.debug("Executing get_recent_alerts condition directly via SIEM client")
                output = get_recent_alerts(hours_back=1, max_alerts=100, client=siem_client)
                details["execution_success"] = True
                details["output"] = output
                details["output_type"] = type(output).__name__ if output is not None else "None"
            except Exception as e:
                logger.exception("Error executing get_recent_alerts condition directly: %s", e)
                details["evaluation"] = "✗ CONDITION ERROR: Failed to execute get_recent_alerts condition"
                details["error"] = str(e)
                return False, details

        elif condition_function == "list_cases":
            try:
                # Import here to avoid heavy imports at module load
                from ...core.config_storage import load_config_from_file
                from src.integrations.case_management.iris.iris_client import IRISCaseManagementClient
                from src.integrations.case_management.thehive.thehive_client import TheHiveCaseManagementClient
                from src.orchestrator.tools_case import list_cases
            except Exception as e:
                logger.exception("Failed to import dependencies for list_cases condition: %s", e)
                details["evaluation"] = "✗ CONDITION ERROR: Failed to import list_cases dependencies"
                details["error"] = str(e)
                return False, details

            try:
                config = load_config_from_file()
                # Prioritize IRIS if both are configured (same as mcp_server.py)
                case_client = None
                if getattr(config, "iris", None):
                    case_client = IRISCaseManagementClient.from_config(config)
                    details["command_executed"] = "python:list_cases(status='open', limit=50) [IRIS]"
                elif getattr(config, "thehive", None):
                    case_client = TheHiveCaseManagementClient.from_config(config)
                    details["command_executed"] = "python:list_cases(status='open', limit=50) [TheHive]"
                else:
                    msg = "Case management system (IRIS or TheHive) is not configured; cannot evaluate list_cases condition"
                    logger.warning(msg)
                    details["evaluation"] = f"✗ CONDITION ERROR: {msg}"
                    details["error"] = msg
                    return False, details

                logger.debug("Executing list_cases condition directly via case management client")
                output = list_cases(status="open", limit=50, client=case_client)
                details["execution_success"] = True
                details["output"] = output
                details["output_type"] = type(output).__name__ if output is not None else "None"
            except Exception as e:
                logger.exception("Error executing list_cases condition directly: %s", e)
                details["evaluation"] = "✗ CONDITION ERROR: Failed to execute list_cases condition"
                details["error"] = str(e)
                return False, details

        else:
            # Generic fallback: use the AgentExecutor to run the condition tool.
            # NOTE: This path may involve the external AI agent for unknown commands,
            #       so prefer explicit Python-level implementations for conditions.
            # Parse the condition function as a command
            # Support formats like:
            # - "get_recent_alerts"
            # - "run get_recent_alerts"
            # - "run get_recent_alerts with hours_back=1"
            condition_command_str = condition_function
            if not condition_command_str.startswith("run "):
                condition_command_str = f"run {condition_function}"
            
            details["command_executed"] = condition_command_str
            logger.debug("Parsing condition command: %s", condition_command_str)
            condition_command = executor.parse_command(condition_command_str)
            
            # Execute the condition function
            logger.debug("Executing condition function via AgentExecutor: %s", condition_function)
            result = await executor.execute_command(condition_command)
            
            details["execution_success"] = result is not None and result.success
            
            if not result or not result.success:
                logger.debug("Condition function '%s' failed or returned no result", condition_function)
                details["evaluation"] = f"Condition function '{condition_function}' failed or returned no result"
                if result:
                    details["error"] = result.error
                return False, details
            
            # Check if the output has content
            output = result.output
            details["output"] = output
            details["output_type"] = type(output).__name__ if output is not None else "None"
            
            if output is None:
                logger.debug("Condition function '%s' returned None", condition_function)
                details["evaluation"] = "Condition function returned None - no content to proceed"
                return False, details

        # Handle case where output might be wrapped (e.g., from ExecutionResult.to_dict())
        if isinstance(output, dict) and "raw" in output and len(output) == 2 and "text" in output:
            # Output was wrapped as string representation, extract if possible
            # For now, treat wrapped output as having content (conservative approach)
            logger.debug("Condition function '%s' returned wrapped output", condition_function)
            details["evaluation"] = (
                "✓ CONDITION PASSED: Wrapped output (raw/text) returned. "
                "Proceeding with autorun execution."
            )
            return True, details
        
        # Handle different output formats
        # If it's a dict, check for common content indicators
        if isinstance(output, dict):
            # Check for get_recent_alerts specific format - focus on uninvestigated_alerts
            if "uninvestigated_alerts" in output:
                uninvestigated_alerts = output.get("uninvestigated_alerts", 0)
                total_alerts = output.get("total_alerts", 0)
                groups = output.get("groups", [])
                groups_count = len(groups) if isinstance(groups, list) else 0
                
                details["uninvestigated_alerts"] = uninvestigated_alerts
                details["total_alerts"] = total_alerts
                details["groups_count"] = groups_count
                
                if uninvestigated_alerts > 0:
                    logger.debug("Condition function '%s' returned %d uninvestigated alerts - proceeding", 
                               condition_function, uninvestigated_alerts)
                    details["evaluation"] = (
                        f"✓ CONDITION PASSED: Found {uninvestigated_alerts} uninvestigated alert(s) "
                        f"(total: {total_alerts}, groups: {groups_count}). Proceeding with autorun execution."
                    )
                    return True, details
                else:
                    logger.debug("Condition function '%s' returned 0 uninvestigated alerts - skipping execution", condition_function)
                    details["evaluation"] = (
                        f"✗ CONDITION FAILED: No uninvestigated alerts found "
                        f"(total: {total_alerts}, groups: {groups_count}). Skipping autorun execution."
                    )
                    return False, details
            
            # Check for groups (fallback for get_recent_alerts if uninvestigated_alerts not present)
            if "groups" in output:
                groups = output.get("groups", [])
                groups_count = len(groups) if isinstance(groups, list) else 0
                details["groups_count"] = groups_count
                
                if groups_count > 0:
                    logger.debug("Condition function '%s' returned %d alert groups", condition_function, groups_count)
                    details["evaluation"] = f"✓ CONDITION PASSED: Found {groups_count} alert group(s). Proceeding with autorun execution."
                    return True, details
                else:
                    logger.debug("Condition function '%s' returned no alert groups", condition_function)
                    details["evaluation"] = "✗ CONDITION FAILED: No alert groups found. Skipping autorun execution."
                    return False, details
            
            # Check for list_cases specific format - focus on cases count
            if "cases" in output and "count" in output:
                cases = output.get("cases", [])
                cases_count = output.get("count", 0)
                
                details["cases_count"] = cases_count
                
                if cases_count > 0:
                    logger.debug("Condition function '%s' returned %d case(s) - proceeding", 
                               condition_function, cases_count)
                    details["evaluation"] = (
                        f"✓ CONDITION PASSED: Found {cases_count} open case(s). "
                        "Proceeding with autorun execution."
                    )
                    return True, details
                else:
                    logger.debug("Condition function '%s' returned 0 cases - skipping execution", condition_function)
                    details["evaluation"] = (
                        f"✗ CONDITION FAILED: No open cases found. Skipping autorun execution."
                    )
                    return False, details
            
            # Check for common keys that indicate content
            if "alerts" in output:
                alerts = output.get("alerts", [])
                alerts_count = len(alerts) if isinstance(alerts, list) else 0
                if alerts_count > 0:
                    logger.debug("Condition function '%s' returned %d alerts", condition_function, alerts_count)
                    details["evaluation"] = f"✓ CONDITION PASSED: Found {alerts_count} alert(s). Proceeding with autorun execution."
                    return True, details
                else:
                    logger.debug("Condition function '%s' returned empty alerts list", condition_function)
                    details["evaluation"] = "✗ CONDITION FAILED: Empty alerts list. Skipping autorun execution."
                    return False, details
            
            if "events" in output:
                events = output.get("events", [])
                events_count = len(events) if isinstance(events, list) else 0
                if events_count > 0:
                    logger.debug("Condition function '%s' returned %d events", condition_function, events_count)
                    details["evaluation"] = f"✓ CONDITION PASSED: Found {events_count} event(s). Proceeding with autorun execution."
                    return True, details
                else:
                    logger.debug("Condition function '%s' returned empty events list", condition_function)
                    details["evaluation"] = "✗ CONDITION FAILED: Empty events list. Skipping autorun execution."
                    return False, details
            
            if "results" in output:
                results = output.get("results", [])
                results_count = len(results) if isinstance(results, list) else 0
                if results_count > 0:
                    logger.debug("Condition function '%s' returned %d results", condition_function, results_count)
                    details["evaluation"] = f"✓ CONDITION PASSED: Found {results_count} result(s). Proceeding with autorun execution."
                    return True, details
                else:
                    logger.debug("Condition function '%s' returned empty results list", condition_function)
                    details["evaluation"] = "✗ CONDITION FAILED: Empty results list. Skipping autorun execution."
                    return False, details
            
            # Check if dict has any non-empty values
            has_content = any(
                v is not None and v != "" and v != [] and v != {}
                for v in output.values()
            )
            if has_content:
                logger.debug("Condition function '%s' returned dict with content", condition_function)
                details["evaluation"] = "✓ CONDITION PASSED: Dictionary contains non-empty values. Proceeding with autorun execution."
                return True, details
            else:
                logger.debug("Condition function '%s' returned empty dict", condition_function)
                details["evaluation"] = "✗ CONDITION FAILED: Dictionary is empty or contains only empty values. Skipping autorun execution."
                return False, details
        
        # If it's a list, check if it has items
        if isinstance(output, list):
            list_count = len(output)
            if list_count > 0:
                logger.debug("Condition function '%s' returned list with %d items", condition_function, list_count)
                details["evaluation"] = f"✓ CONDITION PASSED: List contains {list_count} item(s). Proceeding with autorun execution."
                return True, details
            else:
                logger.debug("Condition function '%s' returned empty list", condition_function)
                details["evaluation"] = "✗ CONDITION FAILED: List is empty. Skipping autorun execution."
                return False, details
        
        # If it's a string, check if it's non-empty
        if isinstance(output, str):
            if output.strip():
                logger.debug("Condition function '%s' returned non-empty string", condition_function)
                details["evaluation"] = f"✓ CONDITION PASSED: Non-empty string returned (length: {len(output)}). Proceeding with autorun execution."
                return True, details
            else:
                logger.debug("Condition function '%s' returned empty string", condition_function)
                details["evaluation"] = "✗ CONDITION FAILED: Empty string returned. Skipping autorun execution."
                return False, details
        
        # For other types, check if truthy
        if output:
            logger.debug("Condition function '%s' returned truthy value", condition_function)
            details["evaluation"] = f"✓ CONDITION PASSED: Truthy value returned (type: {type(output).__name__}). Proceeding with autorun execution."
            return True, details
        else:
            logger.debug("Condition function '%s' returned falsy value", condition_function)
            details["evaluation"] = f"✗ CONDITION FAILED: Falsy value returned (type: {type(output).__name__}). Skipping autorun execution."
            return False, details
            
    except Exception as e:
        logger.exception("Error checking condition function '%s': %s", condition_function, e)
        details["error"] = str(e)
        details["evaluation"] = f"✗ CONDITION ERROR: Exception occurred - {str(e)}. Skipping autorun execution for safety."
        # On error, default to skipping execution to be safe
        return False, details


async def autorun_scheduler_loop():
    """
    Background loop that periodically checks for enabled autoruns and runs them
    when their next_run is due.
    """
    logger.info("Starting autorun scheduler loop")
    while True:
        try:
            if not session_manager or not executor:
                await asyncio.sleep(5)
                continue

            now = datetime.now()
            autoruns = session_manager.list_autoruns(enabled_only=True)

            for autorun in autoruns:
                # If no schedule yet, initialize next_run to now
                if not autorun.next_run:
                    session_manager.update_autorun(
                        autorun.id,
                        next_run=now + timedelta(seconds=autorun.interval_seconds),
                    )
                    continue

                # Run when next_run is due or in the past, and not already running
                if autorun.id in running_autoruns:
                    continue

                if autorun.next_run <= now:
                    running_autoruns.add(autorun.id)
                    asyncio.create_task(_run_autorun(autorun))
        except Exception as e:
            logger.exception("Error in autorun scheduler loop: %s", e)

        # Poll interval
        await asyncio.sleep(5)


@app.on_event("startup")
async def on_startup():
    """Start background tasks such as the autorun scheduler."""
    global autorun_scheduler_task
    if autorun_scheduler_task is None:
        autorun_scheduler_task = asyncio.create_task(autorun_scheduler_loop())
        logger.info("Autorun scheduler task started")


@app.on_event("shutdown")
async def on_shutdown():
    """Cleanly stop background tasks."""
    global autorun_scheduler_task
    if autorun_scheduler_task:
        autorun_scheduler_task.cancel()
        autorun_scheduler_task = None


# Determine paths
WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"
TEMPLATES_DIR = WEB_DIR / "templates"

# Create directories if they don't exist
STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

# Mount static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


async def broadcast_to_session(session_id: str, message: dict):
    """Broadcast a message to all WebSocket connections for a session."""
    if session_id in active_connections:
        disconnected = []
        for connection in active_connections[session_id]:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error sending message to WebSocket: {e}")
                disconnected.append(connection)
        
        # Remove disconnected connections
        for conn in disconnected:
            active_connections[session_id].remove(conn)


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main controller interface."""
    html_path = TEMPLATES_DIR / "index.html"
    if html_path.exists():
        with open(html_path, "r") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>AI Controller</h1><p>index.html not found</p>")


@app.get("/api/config")
async def get_ui_config():
    """Return UI-related configuration flags (e.g., debug mode)."""
    return JSONResponse(
        content={
            "success": True,
            "ui_debug": UI_DEBUG_MODE,
        }
    )


@app.post("/api/config")
async def update_ui_config(config: UIConfigUpdate):
    """Update UI-related configuration flags (currently debug mode)."""
    global UI_DEBUG_MODE
    
    if config.ui_debug is not None:
        UI_DEBUG_MODE = config.ui_debug
        logger.info("UI debug mode updated via API: %s", UI_DEBUG_MODE)
    
    return JSONResponse(
        content={
            "success": True,
            "ui_debug": UI_DEBUG_MODE,
        }
    )


@app.get("/api/sessions")
async def list_sessions(session_type: Optional[str] = None):
    """List all sessions."""
    if not session_manager:
        raise HTTPException(status_code=500, detail="Session manager not initialized")
    
    sessions = session_manager.list_sessions()
    if session_type:
        try:
            type_enum = SessionType(session_type)
            sessions = [s for s in sessions if s.session_type == type_enum]
        except ValueError:
            pass
    
    logger.debug(
        "Listing sessions (requested_type=%s, returned_count=%d)",
        session_type,
        len(sessions),
    )
    return JSONResponse(content={
        "success": True,
        "sessions": [s.to_dict() for s in sessions]
    })


@app.post("/api/sessions")
async def create_session(request: Request):
    """Create a new session."""
    if not session_manager:
        raise HTTPException(status_code=500, detail="Session manager not initialized")
    
    data = await request.json()
    name = data.get("name", "New Session")
    session_type = SessionType(data.get("session_type", "manual"))
    
    session = session_manager.create_session(name, session_type)
    
    return JSONResponse(content={
        "success": True,
        "session": session.to_dict()
    })


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    """Get a session by ID."""
    if not session_manager:
        raise HTTPException(status_code=500, detail="Session manager not initialized")
    
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return JSONResponse(content={
        "success": True,
        "session": session.to_dict()
    })


@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str):
    """Delete a session and clean up all associated resources."""
    if not session_manager:
        raise HTTPException(status_code=500, detail="Session manager not initialized")
    
    # Cancel any running tasks for this session
    task = running_tasks.get(session_id)
    if task and not task.done():
        task.cancel()
        logger.info(f"Deleting session {session_id}, cancelling running task")

    # Best-effort: cancel any underlying external process (e.g., cursor-agent)
    if executor:
        try:
            logger.info("Deleting session %s, attempting to cancel external execution process", session_id)
            executor.cancel_current_execution()
        except Exception as e:
            logger.warning("Error cancelling external execution while deleting session %s: %s", session_id, e)
    
    # Close all WebSocket connections for this session
    if session_id in active_connections:
        connections = active_connections[session_id].copy()
        for connection in connections:
            try:
                await connection.close()
            except Exception as e:
                logger.warning(f"Error closing WebSocket for session {session_id}: {e}")
        del active_connections[session_id]
    
    # Clean up task tracking
    running_tasks.pop(session_id, None)
    
    # Delete the session (removes file and cache)
    try:
        logger.info(f"Attempting to delete session {session_id}")
        session_manager.delete_session(session_id)
        
        # Verify file was actually deleted
        session_file = session_manager.sessions_dir / f"{session_id}.json"
        if session_file.exists():
            logger.warning(f"Session file still exists after delete: {session_file}")
            # Try to delete again
            try:
                session_file.unlink()
                logger.info(f"Force deleted session file: {session_file}")
            except Exception as e:
                logger.error(f"Failed to force delete session file: {e}")
        else:
            logger.info(f"Session file successfully deleted: {session_file}")
        
        logger.info(f"Deleted session {session_id} and cleaned up all resources")
        return JSONResponse(content={"success": True, "message": f"Session {session_id} deleted"})
    except ValueError as e:
        logger.error(f"Session {session_id} not found for deletion: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception(f"Unexpected error deleting session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete session: {str(e)}")


@app.post("/api/sessions/{session_id}/stop")
async def stop_session(session_id: str):
    """Best-effort stop for a running session (similar to Ctrl+C)."""
    if not session_manager:
        raise HTTPException(status_code=500, detail="Session manager not initialized")
    
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Cancel any running task for this session
    task = running_tasks.get(session_id)
    if task and not task.done():
        task.cancel()
        logger.info(f"Stop requested for session {session_id}, cancelling running task")
        # Note: The task's finally block will clean up running_tasks entry
    else:
        logger.info(f"Stop requested for session {session_id}, but no active task found")

    # Always attempt to cancel any underlying external process (e.g., cursor-agent),
    # since there is at most one such process tracked globally in the executor.
    if executor:
        try:
            executor.cancel_current_execution()
        except Exception as e:
            logger.warning(f"Error cancelling external execution for session {session_id}: {e}")
    
    # Mark session as stopped to reflect user's intent
    session_manager.update_session_status(session_id, SessionStatus.STOPPED)
    
    # Broadcast stop event to any connected WebSocket clients
    await broadcast_to_session(session_id, {
        "type": "execution_stopped",
        "message": "Session stopped by user"
    })
    
    return JSONResponse(content={"success": True, "status": "stopped"})


@app.post("/api/sessions/{session_id}/execute")
async def execute_command(session_id: str, command_request: CommandRequest):
    """Execute a command in a session."""
    if not executor or not session_manager:
        raise HTTPException(status_code=500, detail="Server not initialized")
    
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Parse command
    command = executor.parse_command(command_request.command)
    
    # Add entry to session
    entry = session_manager.add_entry(session_id, command_request.command)
    
    # Broadcast that execution started
    await broadcast_to_session(session_id, {
        "type": "execution_started",
        "entry_id": entry.id,
        "command": command_request.command
    })
    
    # Execute command asynchronously
    async def execute_and_update():
        try:
            session_manager.update_session_status(session_id, SessionStatus.RUNNING)
            
            result = await executor.execute_command(command)
            
            # Update entry
            session_manager.update_entry(
                session_id,
                entry.id,
                result=result.to_dict() if result else None,
                status=SessionStatus.COMPLETED if result and result.success else SessionStatus.FAILED
            )
            
            # Update session status
            final_status = SessionStatus.COMPLETED if result and result.success else SessionStatus.FAILED
            session_manager.update_session_status(session_id, final_status)
            
            # Broadcast result
            await broadcast_to_session(session_id, {
                "type": "execution_completed",
                "entry_id": entry.id,
                "result": result.to_dict() if result else None
            })
        except asyncio.CancelledError:
            # Task was cancelled (user clicked Stop / closed tab)
            logger.info(f"Execution task for session {session_id} was cancelled")
            
            # Only update session if it still exists (might be deleted during cancellation)
            try:
                session = session_manager.get_session(session_id)
                if session:
                    session_manager.update_entry(
                        session_id,
                        entry.id,
                        status=SessionStatus.STOPPED
                    )
                    session_manager.update_session_status(session_id, SessionStatus.STOPPED)
                    
                    await broadcast_to_session(session_id, {
                        "type": "execution_failed",
                        "entry_id": entry.id,
                        "error": "Execution stopped by user"
                    })
            except Exception as e:
                logger.warning(f"Session {session_id} may have been deleted during cancellation: {e}")
        except Exception as e:
            logger.exception(f"Error executing command in session {session_id}")
            
            # Only update session if it still exists (might be deleted)
            try:
                session = session_manager.get_session(session_id)
                if session:
                    session_manager.update_entry(
                        session_id,
                        entry.id,
                        status=SessionStatus.FAILED
                    )
                    session_manager.update_session_status(session_id, SessionStatus.FAILED)
                    
                    await broadcast_to_session(session_id, {
                        "type": "execution_failed",
                        "entry_id": entry.id,
                        "error": str(e)
                    })
            except Exception as update_error:
                logger.warning(f"Session {session_id} may have been deleted during error handling: {update_error}")
        finally:
            # Clear running task reference
            if session_id in running_tasks:
                running_tasks.pop(session_id, None)
    
    # Run in background and track task for potential cancellation
    task = asyncio.create_task(execute_and_update())
    running_tasks[session_id] = task
    
    return JSONResponse(content={
        "success": True,
        "entry_id": entry.id,
        "message": "Command execution started"
    })


@app.websocket("/ws/sessions/{session_id}")
async def websocket_session(websocket: WebSocket, session_id: str):
    """WebSocket endpoint for real-time session updates."""
    await websocket.accept()
    
    # Add to active connections
    if session_id not in active_connections:
        active_connections[session_id] = []
    active_connections[session_id].append(websocket)
    
    logger.info(f"WebSocket connected for session {session_id}")
    
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Handle different message types
            if message.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for session {session_id}")
    except Exception as e:
        logger.exception(f"Error in WebSocket for session {session_id}: {e}")
    finally:
        # Remove from active connections
        if session_id in active_connections:
            if websocket in active_connections[session_id]:
                active_connections[session_id].remove(websocket)
            if not active_connections[session_id]:
                del active_connections[session_id]


# Autorun endpoints
@app.get("/api/autoruns")
async def list_autoruns(enabled_only: bool = False):
    """List all autoruns."""
    if not session_manager:
        raise HTTPException(status_code=500, detail="Session manager not initialized")
    
    autoruns = session_manager.list_autoruns(enabled_only=enabled_only)
    
    return JSONResponse(content={
        "success": True,
        "autoruns": [a.to_dict() for a in autoruns]
    })


@app.post("/api/autoruns")
async def create_autorun(autorun_request: AutorunCreateRequest):
    """Create a new autorun."""
    if not session_manager:
        raise HTTPException(status_code=500, detail="Session manager not initialized")
    
    autorun = session_manager.create_autorun(
        name=autorun_request.name,
        command=autorun_request.command,
        interval_seconds=autorun_request.interval_seconds,
        condition_function=autorun_request.condition_function
    )
    
    return JSONResponse(content={
        "success": True,
        "autorun": autorun.to_dict()
    })


@app.get("/api/autoruns/{autorun_id}")
async def get_autorun(autorun_id: str):
    """Get an autorun by ID."""
    if not session_manager:
        raise HTTPException(status_code=500, detail="Session manager not initialized")
    
    autorun = session_manager.get_autorun(autorun_id)
    if not autorun:
        raise HTTPException(status_code=404, detail="Autorun not found")
    
    return JSONResponse(content={
        "success": True,
        "autorun": autorun.to_dict()
    })


@app.put("/api/autoruns/{autorun_id}")
async def update_autorun(autorun_id: str, autorun_update: AutorunUpdateRequest):
    """Update an autorun."""
    if not session_manager:
        raise HTTPException(status_code=500, detail="Session manager not initialized")
    
    update_data = autorun_update.dict(exclude_unset=True)
    try:
        session_manager.update_autorun(autorun_id, **update_data)
        autorun = session_manager.get_autorun(autorun_id)
        return JSONResponse(content={
            "success": True,
            "autorun": autorun.to_dict()
        })
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/autoruns/{autorun_id}/clear")
async def clear_autorun_session(autorun_id: str):
    """Clear all entries from an autorun's backing session."""
    if not session_manager:
        raise HTTPException(status_code=500, detail="Session manager not initialized")
    
    try:
        autorun = session_manager.get_autorun(autorun_id)
        if not autorun:
            raise ValueError(f"Autorun {autorun_id} not found")
        
        if not autorun.session_id:
            raise ValueError(f"Autorun {autorun_id} has no associated session")
        
        logger.info("Clearing session entries for autorun %s (session_id=%s)", autorun_id, autorun.session_id)
        
        # Clear all entries from the autorun's backing session
        session_manager.clear_session_entries(autorun.session_id)
        
        return JSONResponse(content={"success": True})
    except ValueError as e:
        logger.error("Error clearing autorun session: %s", e)
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error clearing autorun session %s: %s", autorun_id, e)
        raise HTTPException(status_code=500, detail=f"Failed to clear autorun session: {str(e)}")


@app.delete("/api/autoruns/{autorun_id}")
async def delete_autorun(autorun_id: str):
    """Delete an autorun and clean up its associated session/process if present."""
    if not session_manager:
        raise HTTPException(status_code=500, detail="Session manager not initialized")
    
    try:
        autorun = session_manager.get_autorun(autorun_id)
        if not autorun:
            raise ValueError(f"Autorun {autorun_id} not found")

        logger.info("Deleting autorun %s (session_id=%s)", autorun_id, autorun.session_id)

        # Best-effort: if this autorun is currently scheduled as running, stop any underlying execution
        if autorun_id in running_autoruns:
            logger.info("Autorun %s is currently running; attempting to cancel execution", autorun_id)
            if executor:
                try:
                    executor.cancel_current_execution()
                except Exception as e:
                    logger.warning("Failed to cancel external execution for autorun %s: %s", autorun_id, e)
            running_autoruns.discard(autorun_id)

        # Delete autorun configuration and its dedicated session (handled in SessionManager)
        session_manager.delete_autorun(autorun_id)

        return JSONResponse(content={"success": True})
    except ValueError as e:
        logger.error("Autorun %s not found for deletion: %s", autorun_id, e)
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error deleting autorun %s: %s", autorun_id, e)
        raise HTTPException(status_code=500, detail=f"Failed to delete autorun: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    
    # Initialize
    initialize()
    
    print("Starting SamiGPT AI Controller...")
    uvicorn.run(app, host="0.0.0.0", port=8081)

