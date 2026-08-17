#!/usr/bin/env python3
"""
SamiGPT application entry point.

Starts the HTTPS web interface on 0.0.0.0. A password from config.json is
required; unauthenticated requests never reach the UI, APIs, or static files.

Usage:
    python app.py
    python app.py --port 8081
    python app.py --no-mcp
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional


def _ensure_project_root() -> Path:
    root = Path(__file__).resolve().parent
    os.chdir(root)
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return root


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SamiGPT – SOC AI Agents Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python app.py\n"
            "  python app.py --port 8081\n"
            "  python app.py --no-mcp\n"
        ),
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Web UI bind address (default: 0.0.0.0)",
    )
    parser.add_argument("--port", type=int, default=None, help="Web UI port (default: from config or 8081)")
    parser.add_argument("--storage-dir", default=None, help="Session storage directory")
    parser.add_argument("--debug", action="store_true", help="Show full JSON results in the web UI")
    parser.add_argument(
        "--no-mcp",
        action="store_true",
        help="Do not auto-start the HTTPS MCP server (it can still be started from the UI)",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    _ensure_project_root()
    args = parse_args(argv)

    from src.core.config_storage import get_section, load_config_from_file
    from src.core.logging import configure_logging
    from src.core.tls import uvicorn_ssl_kwargs
    from src.ai_controller.web.auth import load_web_auth_config

    config = load_config_from_file()
    configure_logging(config.logging if config.logging else None)

    try:
        load_web_auth_config(cookie_secure=True)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    ai_cfg = get_section(
        "ai_controller",
        {"storage_dir": "data/ai_controller", "web_port": 8081, "web_host": "0.0.0.0"},
    )
    web_host = args.host or ai_cfg.get("web_host") or "0.0.0.0"
    web_port = args.port or int(ai_cfg.get("web_port", 8081))
    storage_dir = args.storage_dir or ai_cfg.get("storage_dir", "data/ai_controller")

    import uvicorn
    from src.ai_controller.web.server import app, initialize

    initialize(
        config_storage_dir=storage_dir,
        debug_ui=args.debug,
        mcp_auto_start=not args.no_mcp,
        cookie_secure=True,
    )

    mcp_cfg = get_section("mcp", {"host": "127.0.0.1", "port": 8082, "auto_start": True})
    print(f"Starting SamiGPT web interface on https://{web_host}:{web_port}")
    print("Sign-in uses web.username / web.password from config.json")
    if not args.no_mcp and mcp_cfg.get("auto_start", True):
        print(
            f"MCP HTTPS server will listen on https://{mcp_cfg.get('host', '127.0.0.1')}:"
            f"{mcp_cfg.get('port', 8082)}  (Bearer token required)"
        )
    print("Press Ctrl+C to stop")

    uvicorn.run(
        app,
        host=web_host,
        port=int(web_port),
        log_level="info",
        **uvicorn_ssl_kwargs(),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
