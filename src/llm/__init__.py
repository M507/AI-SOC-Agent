"""
Pluggable LLM backends used by the web controller.

The web UI never talks to a vendor SDK directly. AgentExecutor asks the
registry for the configured provider and every provider implements the same
complete() / health_check() / cancel() surface.
"""

from .base import HealthStatus, LLMProvider, LLMResult
from .registry import (
    PROVIDER_CATALOG,
    create_provider,
    get_active_provider,
    provider_catalog,
)

__all__ = [
    "HealthStatus",
    "LLMProvider",
    "LLMResult",
    "PROVIDER_CATALOG",
    "create_provider",
    "get_active_provider",
    "provider_catalog",
]
