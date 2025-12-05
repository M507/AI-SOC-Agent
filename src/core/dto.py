"""
Common DTO utilities for SamiGPT.

We use Python dataclasses for DTOs across the generic API layer. This module
provides a small mixin with helper methods so all DTOs have a consistent
API (e.g., ``to_dict``).

Design choices:
- Style: synchronous (no async in DTOs or interfaces).
- Response pattern: API clients return DTOs (or lists of DTOs) directly,
  without wrapping everything in a ``result`` + ``metadata`` envelope.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Type, TypeVar


T_BaseDTO = TypeVar("T_BaseDTO", bound="BaseDTO")


@dataclass
class BaseDTO:
    """
    Base mixin for DTO dataclasses.

    Inherit from this in DTOs to get a consistent ``to_dict`` method and
    a simple ``from_dict`` constructor.
    """

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert this DTO into a plain dict (recursively).
        """

        return asdict(self)

    @classmethod
    def from_dict(cls: Type[T_BaseDTO], data: Dict[str, Any]) -> T_BaseDTO:
        """
        Construct this DTO from a dict of attributes.

        This is a thin wrapper around normal dataclass construction; any
        extra validation should be implemented by callers as needed.
        """

        return cls(**data)


