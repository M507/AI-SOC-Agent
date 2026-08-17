"""
MCP (Model Context Protocol) server and rules engine for SamiGPT.

This package contains:
- mcp_server.py: MCP server implementation that exposes SamiGPT skills as tools
- http_server.py: HTTP JSON-RPC transport + health endpoints
- supervisor.py: start/stop/health of the HTTP MCP listener
- factory.py: shared construction of a configured MCP server
- rules_engine.py: Rules/workflow engine for automated investigations
"""

from .mcp_server import SamiGPTMCPServer, configure_mcp_logging
from .rules_engine import RulesEngine

__all__ = ["SamiGPTMCPServer", "configure_mcp_logging", "RulesEngine"]
