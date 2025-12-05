"""
IRIS case management integration.

IRIS (https://github.com/dfir-iris/iris) is an open-source incident response platform.
This module provides integration with IRIS for case management.
"""

from .iris_client import IRISCaseManagementClient

__all__ = ["IRISCaseManagementClient"]

