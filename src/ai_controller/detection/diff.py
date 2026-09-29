"""Unified diffs for a review. No model call.

The Review Change pane colors lines that start with + or -. An empty
diff (every condition unchecked) is returned as an explicit "no changes"
line so the pane never looks blank by accident. See
documentation/detection-as-code.md.
"""

from __future__ import annotations

import difflib
from typing import List


def unified_diff(before: str, after: str, filename: str) -> str:
    lines = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
    )
    text = "".join(lines)
    return text or f"(no changes to {filename})\n"
