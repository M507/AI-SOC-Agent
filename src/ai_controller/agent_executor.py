"""
Agent executor for parsing and executing agent commands.

Supports commands like:
- "run lookup_hash_ti on <hash>"
- "run get_security_alerts"
- etc.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple
from enum import Enum

from ..core.config import SamiConfig
from ..core.config_storage import load_config_from_file
from ..core.logging import get_logger

logger = get_logger("sami.ai_controller.agent_executor")


class CommandType(Enum):
    """Types of commands that can be executed."""
    RUN_TOOL = "run_tool"
    RUN_RUNBOOK = "run_runbook"
    RUN_AGENT = "run_agent"
    UNKNOWN = "unknown"


@dataclass
class Command:
    """Represents a parsed command."""
    raw: str
    command_type: CommandType
    tool_name: Optional[str] = None
    arguments: Dict[str, Any] = None
    agent_name: Optional[str] = None
    runbook_name: Optional[str] = None
    
    def __post_init__(self):
        if self.arguments is None:
            self.arguments = {}


@dataclass
class ExecutionResult:
    """Result of an agent execution."""
    success: bool
    output: Any
    error: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        if self.timestamp:
            result["timestamp"] = self.timestamp.isoformat()
        
        # Ensure output is JSON-serializable
        if result.get("output") is not None:
            try:
                # Try to serialize to ensure it's JSON-compatible
                json.dumps(result["output"])
            except (TypeError, ValueError):
                # If not serializable, convert to string representation
                result["output"] = {
                    "raw": str(result["output"]),
                    "text": str(result["output"])
                }
        
        return result


class AgentExecutor:
    """Executes agent commands and manages tool execution."""
    
    def __init__(self, config: Optional[SamiConfig] = None):
        """Initialize the agent executor."""
        self.config = config or load_config_from_file()
        # Track currently running external process (e.g., cursor-agent) so we can cancel it
        self._current_process: Optional[subprocess.Popen] = None
        self._tool_registry: Dict[str, Callable] = {}
        self._initialize_tools()
    
    def _initialize_tools(self):
        """Initialize the tool registry with available tools."""
        # Import tools from orchestrator
        from ..orchestrator import tools_cti, tools_case, tools_edr, tools_siem, tools_kb
        
        # CTI tools
        self._tool_registry["lookup_hash_ti"] = tools_cti.lookup_hash_ti
        # Add more tools as needed
        
        # For now, we'll dynamically import tools as needed
        logger.info(f"Initialized agent executor with {len(self._tool_registry)} tools")
    
    def parse_command(self, command_str: str) -> Command:
        """
        Parse a command string into a Command object.
        
        Supported formats:
        - "run <tool_name> on <arg_value>"
        - "run <tool_name> with <arg_key>=<arg_value>"
        - "run <tool_name> <arg_value>"
        - "run <agent_name> agent on <target>"
        - "run <runbook_name> runbook on <target>"
        
        Supports quoted strings for tool names and values.
        """
        command_str = command_str.strip()
        
        # Helper to strip quotes
        def strip_quotes(s: str) -> str:
            s = s.strip()
            if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
                return s[1:-1]
            return s
        
        # Pattern: "run <tool_name> on <value>" (supports quoted tool names and values)
        # First try with optional quotes around tool name
        match = re.match(r'^run\s+("?)([\w_]+)\1\s+on\s+(.+)$', command_str, re.IGNORECASE)
        if match:
            tool_or_agent = match.group(2)  # The tool name (without quotes)
            value = match.group(3).strip()  # The value after "on"
            value = strip_quotes(value)
        else:
            # Try without quotes around tool name
            match = re.match(r'^run\s+(\w+)\s+on\s+(.+)$', command_str, re.IGNORECASE)
            if match:
                tool_or_agent = match.group(1)
                value = match.group(2).strip()
                value = strip_quotes(value)
        
        if match:
            
            # Check if it's an agent
            if tool_or_agent.endswith("_agent") or tool_or_agent in ["soc1", "soc2", "soc3"]:
                return Command(
                    raw=command_str,
                    command_type=CommandType.RUN_AGENT,
                    agent_name=tool_or_agent,
                    arguments={"target": value}
                )
            
            # Check if it's a runbook
            if "_runbook" in tool_or_agent or tool_or_agent.endswith("_triage") or tool_or_agent.endswith("_investigation"):
                return Command(
                    raw=command_str,
                    command_type=CommandType.RUN_RUNBOOK,
                    runbook_name=tool_or_agent,
                    arguments={"target": value}
                )
            
            # Default to tool
            # Try to infer the argument name based on tool name
            arg_name = self._infer_argument_name(tool_or_agent)
            return Command(
                raw=command_str,
                command_type=CommandType.RUN_TOOL,
                tool_name=tool_or_agent,
                arguments={arg_name: value}
            )
        
        # Pattern: "run <tool_name> with <key>=<value>" (supports quoted tool names)
        match = re.match(r'^run\s+("?)([\w_]+)\1\s+with\s+(.+)$', command_str, re.IGNORECASE)
        if match:
            tool_name = match.group(2)  # Tool name (without quotes)
            params_str = match.group(3)  # Parameters after "with"
        else:
            match = re.match(r'^run\s+(\w+)\s+with\s+(.+)$', command_str, re.IGNORECASE)
            if match:
                tool_name = match.group(1)
                params_str = match.group(2)
        
        if match:
            arguments = self._parse_arguments(params_str)
            return Command(
                raw=command_str,
                command_type=CommandType.RUN_TOOL,
                tool_name=tool_name,
                arguments=arguments
            )
        
        # Pattern: "run <tool_name> <value>" (simple single argument, supports quoted)
        match = re.match(r'^run\s+("?)([\w_]+)\1\s+(.+)$', command_str, re.IGNORECASE)
        if match:
            tool_name = match.group(2)  # Tool name (without quotes)
            value = match.group(3).strip()  # Value
            value = strip_quotes(value)
        else:
            match = re.match(r'^run\s+(\w+)\s+(.+)$', command_str, re.IGNORECASE)
            if match:
                tool_name = match.group(1)
                value = match.group(2).strip()
                value = strip_quotes(value)
        
        if match:
            arg_name = self._infer_argument_name(tool_name)
            return Command(
                raw=command_str,
                command_type=CommandType.RUN_TOOL,
                tool_name=tool_name,
                arguments={arg_name: value}
            )
        
        # Unknown command - treat as freeform prompt for external agent
        # (e.g., Cursor IDE cursor-agent). We don't log a warning here to
        # avoid confusing users when they enter natural language prompts.
        logger.debug(f"Treating input as freeform prompt: {command_str}")
        return Command(
            raw=command_str,
            command_type=CommandType.UNKNOWN
        )
    
    def _infer_argument_name(self, tool_name: str) -> str:
        """Infer the argument name based on tool name."""
        # Common patterns
        if "hash" in tool_name.lower():
            return "hash_value"
        elif "ip" in tool_name.lower():
            return "ip"
        elif "domain" in tool_name.lower():
            return "domain"
        elif "alert" in tool_name.lower():
            return "alert_id"
        elif "case" in tool_name.lower():
            return "case_id"
        elif "user" in tool_name.lower():
            return "username"
        else:
            return "value"
    
    def _parse_arguments(self, params_str: str) -> Dict[str, Any]:
        """Parse argument string like 'key1=value1 key2=value2'."""
        arguments = {}
        # Simple parsing - can be enhanced
        for param in params_str.split():
            if "=" in param:
                key, value = param.split("=", 1)
                arguments[key.strip()] = value.strip()
        return arguments
    
    async def execute_command(self, command: Command) -> ExecutionResult:
        """
        Execute a parsed command and return the result.
        
        This method handles tool execution and can be extended to support
        agents and runbooks.
        """
        try:
            if command.command_type == CommandType.RUN_TOOL:
                return await self._execute_tool(command)
            elif command.command_type == CommandType.RUN_AGENT:
                return await self._execute_agent(command)
            elif command.command_type == CommandType.RUN_RUNBOOK:
                return await self._execute_runbook(command)
            elif command.command_type == CommandType.UNKNOWN:
                # Fallback: treat as freeform prompt and forward to external agent
                return await self._execute_freeform_prompt(command.raw)
            else:
                return ExecutionResult(
                    success=False,
                    output=None,
                    error=f"Unknown command type: {command.command_type}",
                    timestamp=datetime.now()
                )
        except Exception as e:
            logger.exception(f"Error executing command: {command.raw}")
            return ExecutionResult(
                success=False,
                output=None,
                error=str(e),
                timestamp=datetime.now()
            )
    
    async def _execute_tool(self, command: Command) -> ExecutionResult:
        """Execute a tool command."""
        if not command.tool_name:
            return ExecutionResult(
                success=False,
                output=None,
                error="No tool name specified",
                timestamp=datetime.now()
            )
        
        # Check if tool is registered
        if command.tool_name not in self._tool_registry:
            # Try to dynamically import the tool
            tool_func = await self._load_tool(command.tool_name)
            if not tool_func:
                return ExecutionResult(
                    success=False,
                    output=None,
                    error=f"Tool '{command.tool_name}' not found",
                    timestamp=datetime.now()
                )
            self._tool_registry[command.tool_name] = tool_func
        
        tool_func = self._tool_registry[command.tool_name]
        
        # Prepare clients based on tool requirements
        # Prepare clients before the lambda to avoid import issues
        clients = self._prepare_clients(command.tool_name)
        
        if not clients:
            return ExecutionResult(
                success=False,
                output=None,
                error=f"No clients available for tool '{command.tool_name}'. Check configuration.",
                timestamp=datetime.now()
            )
        
        # Execute tool in executor to avoid blocking
        loop = asyncio.get_event_loop()
        try:
            # Capture clients in closure before lambda
            tool_args = command.arguments.copy()
            if isinstance(clients, list):
                tool_args["clients"] = clients
            else:
                tool_args["client"] = clients
            
            result = await loop.run_in_executor(
                None,
                lambda: tool_func(**tool_args)
            )
            
            return ExecutionResult(
                success=True,
                output=result,
                timestamp=datetime.now()
            )
        except Exception as e:
            logger.exception(f"Error executing tool {command.tool_name}")
            return ExecutionResult(
                success=False,
                output=None,
                error=str(e),
                timestamp=datetime.now()
            )
    
    async def _execute_agent(self, command: Command) -> ExecutionResult:
        """Execute an agent command (for future implementation)."""
        # TODO: Implement agent execution
        return ExecutionResult(
            success=False,
            output=None,
            error="Agent execution not yet implemented",
            timestamp=datetime.now()
        )
    
    async def _execute_runbook(self, command: Command) -> ExecutionResult:
        """Execute a runbook command (for future implementation)."""
        # TODO: Implement runbook execution
        return ExecutionResult(
            success=False,
            output=None,
            error="Runbook execution not yet implemented",
            timestamp=datetime.now()
        )

    async def _execute_freeform_prompt(self, prompt: str) -> ExecutionResult:
        """
        Execute a freeform prompt by forwarding it to an external agent
        (Cursor IDE's cursor-agent binary).

        This allows the AI Controller UI to behave like a normal terminal
        where arbitrary prompts are handled by the agent, without requiring
        strict 'run <tool>' syntax.
        """

        loop = asyncio.get_event_loop()

        def _run_cursor_agent(prompt_text: str) -> Dict[str, Any]:
            """
            Run the external cursor-agent process and capture its output.

            Uses:
                cursor-agent --print --output-format text "<prompt>"
            """

            # Try to locate cursor-agent binary
            possible_paths = [
                "/usr/local/bin/cursor-agent",
                "/usr/bin/cursor-agent",
                os.path.expanduser("~/.local/bin/cursor-agent"),
                "/opt/homebrew/bin/cursor-agent",
            ]

            cursor_agent_bin: Optional[str] = None

            for path in possible_paths:
                if os.path.exists(path) and os.access(path, os.X_OK):
                    cursor_agent_bin = path
                    break

            if cursor_agent_bin is None:
                # Fall back to PATH lookup
                cursor_agent_bin = shutil.which("cursor-agent")

            if cursor_agent_bin is None:
                raise RuntimeError(
                    "Cursor IDE 'cursor-agent' binary not found in common locations or PATH. "
                    "Install Cursor and ensure 'cursor-agent' is available."
                )

            # Build command
            # --approve-mcps: auto-approve MCP server/tool usage so Cursor
            # doesn't prompt interactively for each tool call.
            cmd = [
                cursor_agent_bin,
                "--force",
                "--approve-mcps",
                "--print",
                "--output-format",
                "text",
                prompt_text,
            ]

            logger.debug(f"Executing external cursor-agent: {' '.join(cmd)}")

            # Use Popen so we can terminate the process on cancellation
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Register process so it can be cancelled from outside
            self._current_process = proc
            try:
                stdout, stderr = proc.communicate()
            finally:
                # Clear reference once process is finished
                self._current_process = None

            return {
                "returncode": proc.returncode,
                "stdout": (stdout or "").strip(),
                "stderr": (stderr or "").strip(),
                "command": cmd,
            }

        try:
            result = await loop.run_in_executor(None, _run_cursor_agent, prompt)

            success = result.get("returncode", 1) == 0
            output: Dict[str, Any] = {
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "command": " ".join(result.get("command", [])),
            }

            # Prefer stdout as primary output for UI
            primary_output = result.get("stdout", "") or result.get("stderr", "")

            return ExecutionResult(
                success=success,
                output={
                    "raw": output,
                    "text": primary_output,
                },
                error=None if success else result.get("stderr", "cursor-agent failed"),
                timestamp=datetime.now(),
            )
        except Exception as e:
            logger.exception("Error forwarding prompt to external cursor-agent")
            return ExecutionResult(
                success=False,
                output=None,
                error=str(e),
                timestamp=datetime.now(),
            )

    def cancel_current_execution(self):
        """
        Best-effort cancellation of any currently running external process.

        This is primarily used to stop a long-running cursor-agent process when
        the user clicks Stop or closes the session in the web UI.
        """
        proc = self._current_process
        if not proc:
            return

        if proc.poll() is not None:
            # Already finished
            self._current_process = None
            return

        try:
            logger.info("Attempting to terminate external process (pid=%s)", proc.pid)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("Process did not exit after terminate, killing (pid=%s)", proc.pid)
                proc.kill()
        except Exception as e:
            logger.warning("Failed to cancel external process: %s", e)
        finally:
            self._current_process = None
    
    async def _load_tool(self, tool_name: str) -> Optional[Callable]:
        """Dynamically load a tool function."""
        try:
            # Map tool names to their modules and functions
            tool_mapping = {
                "lookup_hash_ti": ("..orchestrator.tools_cti", "lookup_hash_ti"),
                "get_security_alerts": ("..orchestrator.tools_siem", "get_security_alerts"),
                "get_security_alert_by_id": ("..orchestrator.tools_siem", "get_security_alert_by_id"),
                "lookup_ip_ti": ("..orchestrator.tools_cti", "lookup_ip_ti"),
                "get_ip_address_report": ("..orchestrator.tools_siem", "get_ip_address_report"),
                # Add more mappings as needed
            }
            
            if tool_name in tool_mapping:
                module_path, func_name = tool_mapping[tool_name]
                module = __import__(module_path, fromlist=[func_name])
                return getattr(module, func_name)
            
            return None
        except Exception as e:
            logger.error(f"Failed to load tool {tool_name}: {e}")
            return None
    
    def _prepare_clients(self, tool_name: str):
        """Prepare client objects needed for tool execution."""
        try:
            # Determine which clients are needed based on tool name
            clients = []
            
            if "cti" in tool_name.lower() or "ti" in tool_name.lower():
                # Need CTI clients - load from config dict to support cti_opencti
                from src.core.config_storage import get_config_dict
                from src.core.config import CTIConfig, SamiConfig
                
                config_dict = get_config_dict()
                
                if self.config.cti:
                    from src.integrations.cti.local_tip.local_tip_client import LocalTipCTIClient
                    clients.append(LocalTipCTIClient.from_config(self.config))
                
                # Check for cti_opencti in config dict (not in SamiConfig dataclass)
                if config_dict.get("cti_opencti"):
                    from src.integrations.cti.opencti.opencti_client import OpenCTIClient
                    cti_opencti_config = config_dict["cti_opencti"]
                    opencti_cfg = CTIConfig(
                        cti_type=cti_opencti_config.get("cti_type", "opencti"),
                        base_url=cti_opencti_config.get("base_url"),
                        api_key=cti_opencti_config.get("api_key"),
                        timeout_seconds=cti_opencti_config.get("timeout_seconds", 30),
                        verify_ssl=cti_opencti_config.get("verify_ssl", False),
                    )
                    temp_config = SamiConfig(cti=opencti_cfg)
                    clients.append(OpenCTIClient.from_config(temp_config))
            
            if "siem" in tool_name.lower() or "alert" in tool_name.lower():
                # Need SIEM client
                if self.config.elastic:
                    from src.integrations.siem.elastic.elastic_client import ElasticSIEMClient
                    clients.append(ElasticSIEMClient.from_config(self.config))
            
            if "edr" in tool_name.lower():
                # Need EDR client
                if self.config.edr:
                    from src.integrations.edr.elastic_defend.elastic_defend_client import ElasticDefendEDRClient
                    clients.append(ElasticDefendEDRClient.from_config(self.config))
            
            if "case" in tool_name.lower():
                # Need case management client
                if self.config.iris:
                    from src.integrations.case_management.iris.iris_client import IRISCaseManagementClient
                    clients.append(IRISCaseManagementClient.from_config(self.config))
                elif self.config.thehive:
                    from src.integrations.case_management.thehive.thehive_client import TheHiveCaseManagementClient
                    clients.append(TheHiveCaseManagementClient.from_config(self.config))
            
            if not clients:
                logger.warning(f"No clients found for tool {tool_name}. Check configuration.")
                return None
            
            return clients[0] if len(clients) == 1 else clients
        except Exception as e:
            logger.exception(f"Failed to prepare clients for {tool_name}: {e}")
            return None

