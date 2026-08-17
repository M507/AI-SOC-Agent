"""MCP server hides tools disabled by the cluster skill vector."""

from src.mcp.mcp_server import SamiGPTMCPServer


def test_tools_list_honors_cluster_skill_vector(monkeypatch):
    server = SamiGPTMCPServer()
    assert "list_rules" in server.tools
    monkeypatch.setattr(
        "src.core.elastic_clusters.skill_vector_for_cluster",
        lambda cluster_id=None: "MSV:1/IRIS:N/TH:N/SIEM:N/EDR:N/CTI:N/KB:N/ENG:N/RB:N/AG:N/RU:N",
    )
    visible = server._tools_for_current_cluster()
    assert "list_rules" not in visible
    assert "execute_rule" not in visible
