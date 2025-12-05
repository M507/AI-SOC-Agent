"""
Core error types for SamiGPT.

These exceptions provide a common base for all raised errors across the
project so that callers (including the orchestrator and web API) can handle
them in a consistent way.
"""

from __future__ import annotations


class SamiError(Exception):
    """
    Base exception for all SamiGPT-specific errors.
    """


class ConfigError(SamiError):
    """
    Raised when configuration is missing, invalid, or inconsistent.
    """


class IntegrationError(SamiError):
    """
    Raised when an external integration (TheHive, SIEM, EDR, etc.) fails
    or returns an unexpected response.
    """


class ValidationError(SamiError):
    """
    Raised when input data, DTOs, or configuration values fail validation.
    """


