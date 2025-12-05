"""
Knowledge base integrations for SamiGPT.

Currently this provides a filesystem-backed KB client that reads client
infrastructure descriptions from ``client_env/*`` in the project root.
"""

from .fs_kb_client import FileSystemKBClient

__all__ = ["FileSystemKBClient"]


