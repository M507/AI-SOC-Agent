"""Shared types for LLM providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class HealthStatus:
    """Result of a provider connectivity check."""

    ok: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "message": self.message, "details": self.details}


@dataclass
class LLMResult:
    """Normalized completion result returned to AgentExecutor."""

    success: bool
    text: str
    raw: Any = None
    error: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    tool_calls: int = 0

    def to_output_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "raw": self.raw if self.raw is not None else self.text,
            "provider": self.provider,
            "model": self.model,
            "tool_calls": self.tool_calls,
        }


class LLMProvider(ABC):
    """Contract every LLM backend must implement."""

    provider_id: str
    display_name: str

    def __init__(self, settings: Optional[Dict[str, Any]] = None) -> None:
        self.settings = settings or {}

    @abstractmethod
    async def complete(self, prompt: str, **kwargs: Any) -> LLMResult:
        """Run a freeform prompt and return the assistant text."""

    @abstractmethod
    async def health_check(self) -> HealthStatus:
        """Verify credentials / reachability without running a full investigation."""

    async def list_models(self) -> List[Dict[str, str]]:
        """Return [{id, name}, ...] from the provider. Empty if unsupported."""
        return []

    async def test_model(self, model: Optional[str] = None) -> HealthStatus:
        """Send a tiny prompt to a specific model. Defaults to health_check."""
        return await self.health_check()

    def cancel(self) -> None:
        """Best-effort cancel of an in-flight completion. Optional."""
        return None

    @classmethod
    def settings_schema(cls) -> Dict[str, Any]:
        """JSON-ish field list used to render the settings form."""
        return {"fields": []}
