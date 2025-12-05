"""
CLI entry point for cursor-agent command.

This acts as a wrapper that:
- Passes commands directly to Cursor IDE's cursor-agent binary
- Handles --web flag to start the SamiGPT AI Controller web interface

Usage:
    cursor-agent "your prompt"  # Passes to Cursor IDE cursor-agent
    cursor-agent --web  # Start SamiGPT AI Controller web server
    cursor-agent --help  # Shows Cursor IDE help
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
from typing import Optional

from ..agent_executor import AgentExecutor
from ..session_manager import SessionManager, SessionType
from ...core.config_storage import load_config_from_file
from ...core.logging import configure_logging, get_logger

logger = get_logger("sami.ai_controller.cli")


async def execute_command(command_str: str, session_name: Optional[str] = None) -> dict:
    """Execute a command and return the result."""
    executor = AgentExecutor(load_config_from_file())
    
    # Optionally create a session if session_name is provided
    session = None
    session_manager = None
    if session_name:
        session_manager = SessionManager()
        session = session_manager.create_session(session_name, SessionType.MANUAL)
        
        # Add entry
        entry = session_manager.add_entry(session.id, command_str)
    
    # Parse and execute command
    command = executor.parse_command(command_str)
    result = await executor.execute_command(command)
    
    # Update session if exists
    if session and session_manager:
        session_manager.update_entry(
            session.id,
            entry.id,
            result=result.to_dict() if result else None,
            status=result.status if hasattr(result, 'status') else None
        )
    
    return {
        "success": result.success if result else False,
        "output": result.output if result else None,
        "error": result.error if result else None,
        "session_id": session.id if session else None
    }


def print_result(result: dict):
    """Print the result in a formatted way."""
    if result["success"]:
        print("✓ Command executed successfully")
        if result["output"]:
            print("\nOutput:")
            print(json.dumps(result["output"], indent=2))
    else:
        print("✗ Command failed")
        if result["error"]:
            print(f"\nError: {result['error']}")
    
    if result.get("session_id"):
        print(f"\nSession ID: {result['session_id']}")


def find_cursor_agent_binary():
    """Find the actual Cursor IDE cursor-agent binary."""
    # Possible locations
    possible_paths = [
        "/usr/local/bin/cursor-agent",
        "/usr/bin/cursor-agent",
        os.path.expanduser("~/.local/bin/cursor-agent"),
        "/opt/homebrew/bin/cursor-agent",
    ]
    
    # Also check in PATH (but avoid this script's location)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    venv_bin = os.path.join(script_dir, "../../../venv/bin")
    
    # Try to find it using shutil.which, but exclude venv/bin
    env_path = os.environ.get("PATH", "")
    # Remove venv/bin from PATH temporarily
    paths = [p for p in env_path.split(os.pathsep) if venv_bin not in p]
    env_path_clean = os.pathsep.join(paths)
    
    # Try possible paths first
    for path in possible_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    
    # Try which command with cleaned PATH
    old_path = os.environ.get("PATH", "")
    try:
        os.environ["PATH"] = env_path_clean
        which_result = shutil.which("cursor-agent")
        if which_result:
            return which_result
    finally:
        os.environ["PATH"] = old_path
    
    # Last resort: try which with original PATH but check it's not our script
    result = shutil.which("cursor-agent")
    if result and "venv/bin/cursor-agent" not in result:
        return result
    
    return None


def pass_to_cursor_agent(args):
    """Pass all arguments to the actual Cursor IDE cursor-agent binary."""
    cursor_agent_bin = find_cursor_agent_binary()
    
    if not cursor_agent_bin:
        print("Error: Cursor IDE cursor-agent binary not found.", file=sys.stderr)
        print("Please ensure Cursor IDE is installed and cursor-agent is in your PATH.", file=sys.stderr)
        sys.exit(1)
    
    # Build command arguments - pass everything except --web
    cmd_args = [cursor_agent_bin]
    
    # Add all sys.argv except script name, but exclude --web and related args
    exclude_args = {"--web", "--port", "--host", "--storage-dir", "--session"}
    skip_next = False
    
    for arg in sys.argv[1:]:
        if skip_next:
            skip_next = False
            continue
        
        if arg in exclude_args:
            skip_next = True  # Skip the next arg (value)
            continue
        
        # Don't skip args that start with -- if they're not in exclude list
        if not arg.startswith("--"):
            skip_next = False
        
        cmd_args.append(arg)
    
    # Execute the actual cursor-agent binary
    try:
        os.execv(cursor_agent_bin, cmd_args)
    except Exception as e:
        print(f"Error executing cursor-agent: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main CLI entry point."""
    # Check for --web flag first (before any other parsing)
    if "--web" in sys.argv:
        # Handle web server mode
        parser = argparse.ArgumentParser(
            description="SamiGPT AI Controller Web Server",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        
        parser.add_argument(
            "--web",
            action="store_true",
            help="Start the web server interface"
        )
        
        parser.add_argument(
            "--port",
            type=int,
            default=None,
            help="Port for web server (default: from config or 8081)"
        )
        
        parser.add_argument(
            "--host",
            type=str,
            default=None,
            help="Host for web server (default: from config or 0.0.0.0)"
        )
        
        parser.add_argument(
            "--storage-dir",
            type=str,
            help="Storage directory for sessions (default: data/ai_controller)"
        )
        
        parser.add_argument(
            "--debug",
            action="store_true",
            help="Enable UI debug mode (show full JSON results in web UI)"
        )
        
        args = parser.parse_args()
        
        # Configure logging
        config = load_config_from_file()
        configure_logging(config.logging if config.logging else None)
        
        # Start web server
        import uvicorn
        from ..web.server import app, initialize
        
        # Get config settings for web server from config.json
        from ...core.config_storage import get_config_dict
        
        config_dict = get_config_dict()
        ai_controller_config = config_dict.get("ai_controller", {})
        
        web_port = args.port or ai_controller_config.get("web_port", 8081)
        web_host = args.host or ai_controller_config.get("web_host", "0.0.0.0")
        storage_dir = args.storage_dir or ai_controller_config.get("storage_dir", "data/ai_controller")
        
        # Initialize server
        initialize(config_storage_dir=storage_dir, debug_ui=args.debug)
        
        print(f"Starting SamiGPT AI Controller on http://{web_host}:{web_port}")
        print("Press Ctrl+C to stop")
        
        uvicorn.run(app, host=web_host, port=web_port, log_level="info")
        return
    
    # Not --web mode: pass through to Cursor IDE cursor-agent
    pass_to_cursor_agent(None)


if __name__ == "__main__":
    main()

