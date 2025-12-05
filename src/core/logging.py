"""
Shared logging configuration for SamiGPT.

This module centralizes logging setup so that all components
(core, API layer, integrations, orchestrator, web API) can
log in a consistent way.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
from typing import Optional

from .config import LoggingConfig


def configure_logging(config: Optional[LoggingConfig] = None) -> None:
    """
    Configure application-wide logging.

    This function is idempotent: calling it multiple times will not
    re-add handlers if they already exist.
    """

    if config is None:
        # Fall back to sensible defaults if no config is provided.
        config = LoggingConfig()

    log_dir = config.log_dir
    os.makedirs(log_dir, exist_ok=True)

    root_logger = logging.getLogger()

    # Avoid configuring logging twice.
    if getattr(root_logger, "_sami_logging_configured", False):
        return

    root_logger.setLevel(config.log_level.upper())

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s [%(message)s]",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Error log
    error_handler = logging.FileHandler(os.path.join(log_dir, "error.log"))
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)

    # Warning log
    warning_handler = logging.FileHandler(os.path.join(log_dir, "warning.log"))
    warning_handler.setLevel(logging.WARNING)
    warning_handler.setFormatter(formatter)

    # Debug log
    debug_handler = logging.FileHandler(os.path.join(log_dir, "debug.log"))
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(formatter)

    # Optional console handler for development.
    console_handler = logging.StreamHandler()
    console_handler.setLevel(config.log_level.upper())
    console_handler.setFormatter(formatter)

    root_logger.addHandler(error_handler)
    root_logger.addHandler(warning_handler)
    root_logger.addHandler(debug_handler)
    root_logger.addHandler(console_handler)

    # Mark as configured
    root_logger._sami_logging_configured = True  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Dedicated logging for ai_controller components
    # ------------------------------------------------------------------
    try:
        from pathlib import Path

        core_dir = Path(__file__).resolve().parent
        ai_controller_logs_dir = core_dir.parent / "ai_controller" / "logs"
        os.makedirs(ai_controller_logs_dir, exist_ok=True)

        ai_logger = logging.getLogger("sami.ai_controller")

        if not getattr(ai_logger, "_sami_ai_controller_logging_configured", False):
            ai_formatter = logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s [%(message)s]",
                datefmt="%Y-%m-%d %H:%M:%S",
            )

            # Error log for ai_controller
            ai_error_handler = logging.FileHandler(os.path.join(ai_controller_logs_dir, "error.log"))
            ai_error_handler.setLevel(logging.ERROR)
            ai_error_handler.setFormatter(ai_formatter)

            # Warning log for ai_controller
            ai_warning_handler = logging.FileHandler(os.path.join(ai_controller_logs_dir, "warning.log"))
            ai_warning_handler.setLevel(logging.WARNING)
            ai_warning_handler.setFormatter(ai_formatter)

            # Debug log for ai_controller (includes info/debug)
            ai_debug_handler = logging.FileHandler(os.path.join(ai_controller_logs_dir, "debug.log"))
            ai_debug_handler.setLevel(logging.DEBUG)
            ai_debug_handler.setFormatter(ai_formatter)

            ai_logger.addHandler(ai_error_handler)
            ai_logger.addHandler(ai_warning_handler)
            ai_logger.addHandler(ai_debug_handler)

            # Ensure we still propagate to root so central logs receive entries too
            ai_logger.propagate = True

            ai_logger._sami_ai_controller_logging_configured = True  # type: ignore[attr-defined]
    except Exception:
        # Never let logging configuration crash the app
        root_logger.exception("Failed to configure dedicated ai_controller logging handlers")


def get_logger(name: str) -> logging.Logger:
    """
    Convenience helper to get a logger for a given module or subsystem.
    """

    return logging.getLogger(name)


