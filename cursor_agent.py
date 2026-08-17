#!/usr/bin/env python3
"""
Deprecated launcher.

Use `python app.py` to start the SamiGPT web interface.
This file remains so existing scripts keep working.
"""

import sys

print(
    "cursor_agent.py is deprecated. Starting the web interface via app.py instead.\n"
    "Use: python app.py",
    file=sys.stderr,
)

from app import main

if __name__ == "__main__":
    sys.exit(main())
