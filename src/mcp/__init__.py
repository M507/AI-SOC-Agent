"""
MCP (Model Context Protocol) server and rules engine for SamiGPT.

This package contains:
- mcp_server.py: MCP server implementation that exposes SamiGPT skills as tools
- rules_engine.py: Rules/workflow engine for automated investigations
"""

from .mcp_server import SamiGPTMCPServer, configure_mcp_logging
from .rules_engine import RulesEngine

__all__ = ["SamiGPTMCPServer", "configure_mcp_logging", "RulesEngine"]

