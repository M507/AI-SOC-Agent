#!/usr/bin/env python3
"""
CLI entry point for cursor-agent command.

This script provides a command-line interface for executing agent commands
and starting the web controller.
"""

import sys
from src.ai_controller.cli.main import main

if __name__ == "__main__":
    sys.exit(main())

