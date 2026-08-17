"""Cursor IDE `cursor-agent` binary provider."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from ..core.logging import get_logger
from .base import HealthStatus, LLMProvider, LLMResult

logger = get_logger("sami.llm.cursor_agent")

_DEFAULT_PATHS = [
    "/usr/local/bin/cursor-agent",
    "/usr/bin/cursor-agent",
    os.path.expanduser("~/.local/bin/cursor-agent"),
    "/opt/homebrew/bin/cursor-agent",
]


def find_cursor_agent_binary(explicit: Optional[str] = None) -> Optional[str]:
    """Locate the Cursor IDE cursor-agent executable."""
    if explicit and os.path.exists(explicit) and os.access(explicit, os.X_OK):
        return explicit
    for path in _DEFAULT_PATHS:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return shutil.which("cursor-agent")


class CursorAgentProvider(LLMProvider):
    """Forwards freeform prompts to the local Cursor `cursor-agent` CLI."""

    provider_id = "cursor_agent"
    display_name = "Cursor Agent"

    def __init__(self, settings: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(settings)
        self._process: Optional[subprocess.Popen] = None

    def _binary(self) -> Optional[str]:
        return find_cursor_agent_binary(self.settings.get("binary_path"))

    def _extra_args(self) -> List[str]:
        extra = self.settings.get("extra_args")
        if isinstance(extra, list) and extra:
            return [str(a) for a in extra]
        return ["--force", "--approve-mcps"]

    async def complete(self, prompt: str, **kwargs: Any) -> LLMResult:
        binary = self._binary()
        if not binary:
            return LLMResult(
                success=False,
                text="",
                error=(
                    "Cursor IDE 'cursor-agent' binary not found. "
                    "Install Cursor or pick a different LLM provider in Settings."
                ),
                provider=self.provider_id,
            )

        cmd = [binary, *self._extra_args(), "--print", "--output-format", "text", prompt]
        logger.debug("Executing cursor-agent: %s", " ".join(cmd[:-1] + ["<prompt>"]))

        import asyncio

        def _run() -> LLMResult:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self._process = proc
            try:
                stdout, stderr = proc.communicate()
            finally:
                self._process = None
            stdout = (stdout or "").strip()
            stderr = (stderr or "").strip()
            success = proc.returncode == 0
            return LLMResult(
                success=success,
                text=stdout or stderr,
                raw={
                    "stdout": stdout,
                    "stderr": stderr,
                    "returncode": proc.returncode,
                    "command": cmd[:-1],
                },
                error=None if success else (stderr or "cursor-agent failed"),
                provider=self.provider_id,
                model="cursor-agent",
            )

        return await asyncio.get_event_loop().run_in_executor(None, _run)

    async def health_check(self) -> HealthStatus:
        binary = self._binary()
        if not binary:
            return HealthStatus(
                ok=False,
                message="cursor-agent binary not found on this host",
                details={"searched": _DEFAULT_PATHS},
            )
        return HealthStatus(
            ok=True,
            message=f"Found cursor-agent at {binary}",
            details={"binary_path": binary},
        )

    async def list_models(self) -> List[Dict[str, str]]:
        binary = self._binary()
        if not binary:
            return []
        return [{"id": "cursor-agent", "name": "cursor-agent (local CLI)"}]

    async def test_model(self, model: Optional[str] = None) -> HealthStatus:
        status = await self.health_check()
        if status.ok:
            status.message = f"{status.message}. Cursor Agent runs the local CLI; there is no remote model catalog."
        return status

    def cancel(self) -> None:
        proc = self._process
        if not proc or proc.poll() is not None:
            self._process = None
            return
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception as e:
            logger.warning("Failed to cancel cursor-agent: %s", e)
        finally:
            self._process = None

    @classmethod
    def settings_schema(cls) -> Dict[str, Any]:
        return {
            "fields": [
                {
                    "key": "binary_path",
                    "label": "Binary path (optional)",
                    "type": "text",
                    "placeholder": "Leave blank to auto-detect cursor-agent",
                },
            ]
        }
