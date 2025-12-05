"""
Configuration storage and loading for SamiGPT.

This module provides functions to save and load configuration from both JSON and .env files,
allowing the web UI to manage configurations and supporting manual file editing.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from .config import (
    CTIConfig,
    ClickUpConfig,
    EDRConfig,
    ElasticConfig,
    EngConfig,
    GitHubConfig,
    IrisConfig,
    LoggingConfig,
    SamiConfig,
    TheHiveConfig,
    TrelloConfig,
)
from .errors import ConfigError


CONFIG_FILE = os.getenv("SAMIGPT_CONFIG_FILE", "config.json")
ENV_FILE = os.getenv("SAMIGPT_ENV_FILE", ".env")
STARTING_CONFIG_FILE = os.getenv("SAMIGPT_STARTING_CONFIG_FILE", "config.json.example")


def _config_to_dict(config: SamiConfig) -> Dict[str, Any]:
    """Convert SamiConfig to a dictionary."""
    result: Dict[str, Any] = {
        "logging": {
            "log_dir": config.logging.log_dir if config.logging else "logs",
            "log_level": config.logging.log_level if config.logging else "INFO",
        },
    }

    if config.thehive:
        result["thehive"] = {
            "base_url": config.thehive.base_url,
            "api_key": config.thehive.api_key,
            "timeout_seconds": config.thehive.timeout_seconds,
        }

    if config.iris:
        result["iris"] = {
            "base_url": config.iris.base_url,
            "api_key": config.iris.api_key,
            "timeout_seconds": config.iris.timeout_seconds,
            "verify_ssl": config.iris.verify_ssl,
        }

    if config.elastic:
        result["elastic"] = {
            "base_url": config.elastic.base_url,
            "api_key": config.elastic.api_key,
            "username": config.elastic.username,
            "password": config.elastic.password,
            "timeout_seconds": config.elastic.timeout_seconds,
            "verify_ssl": config.elastic.verify_ssl,
        }

    if config.edr:
        result["edr"] = {
            "edr_type": config.edr.edr_type,
            "base_url": config.edr.base_url,
            "api_key": config.edr.api_key,
            "timeout_seconds": config.edr.timeout_seconds,
            "verify_ssl": config.edr.verify_ssl,
            "additional_params": config.edr.additional_params,
        }

    if config.cti:
        result["cti"] = {
            "cti_type": config.cti.cti_type,
            "base_url": config.cti.base_url,
            "api_key": config.cti.api_key,
            "timeout_seconds": config.cti.timeout_seconds,
            "verify_ssl": config.cti.verify_ssl,
        }

    if config.eng:
        eng_dict: Dict[str, Any] = {
            "provider": config.eng.provider,
        }
        if config.eng.trello:
            eng_dict["trello"] = {
                "api_key": config.eng.trello.api_key,
                "api_token": config.eng.trello.api_token,
                "fine_tuning_board_id": config.eng.trello.fine_tuning_board_id,
                "engineering_board_id": config.eng.trello.engineering_board_id,
                "timeout_seconds": config.eng.trello.timeout_seconds,
                "verify_ssl": config.eng.trello.verify_ssl,
            }
        if config.eng.clickup:
            eng_dict["clickup"] = {
                "api_token": config.eng.clickup.api_token,
                "fine_tuning_list_id": config.eng.clickup.fine_tuning_list_id,
                "engineering_list_id": config.eng.clickup.engineering_list_id,
                "timeout_seconds": config.eng.clickup.timeout_seconds,
                "verify_ssl": config.eng.clickup.verify_ssl,
            }
            if config.eng.clickup.space_id:
                eng_dict["clickup"]["space_id"] = config.eng.clickup.space_id
        if config.eng.github:
            eng_dict["github"] = {
                "api_token": config.eng.github.api_token,
                "fine_tuning_project_id": config.eng.github.fine_tuning_project_id,
                "engineering_project_id": config.eng.github.engineering_project_id,
                "timeout_seconds": config.eng.github.timeout_seconds,
                "verify_ssl": config.eng.github.verify_ssl,
            }
        if eng_dict:
            result["eng"] = eng_dict

    return result


def _dict_to_config(data: Dict[str, Any]) -> SamiConfig:
    """Convert a dictionary to SamiConfig."""
    logging_data = data.get("logging", {})
    logging_cfg = LoggingConfig(
        log_dir=logging_data.get("log_dir", "logs"),
        log_level=logging_data.get("log_level", "INFO"),
    ) if logging_data else LoggingConfig()

    thehive_cfg: Optional[TheHiveConfig] = None
    if "thehive" in data and data["thehive"]:
        th_data = data["thehive"]
        if th_data.get("base_url") and th_data.get("api_key"):
            thehive_cfg = TheHiveConfig(
                base_url=th_data["base_url"],
                api_key=th_data["api_key"],
                timeout_seconds=th_data.get("timeout_seconds", 30),
            )

    iris_cfg: Optional[IrisConfig] = None
    if "iris" in data and data["iris"]:
        iris_data = data["iris"]
        if iris_data.get("base_url") and iris_data.get("api_key"):
            iris_cfg = IrisConfig(
                base_url=iris_data["base_url"],
                api_key=iris_data["api_key"],
                timeout_seconds=iris_data.get("timeout_seconds", 30),
                verify_ssl=iris_data.get("verify_ssl", True),
            )

    elastic_cfg: Optional[ElasticConfig] = None
    if "elastic" in data and data["elastic"]:
        el_data = data["elastic"]
        if el_data.get("base_url"):
            elastic_cfg = ElasticConfig(
                base_url=el_data["base_url"],
                api_key=el_data.get("api_key"),
                username=el_data.get("username"),
                password=el_data.get("password"),
                timeout_seconds=el_data.get("timeout_seconds", 30),
                verify_ssl=el_data.get("verify_ssl", True),
            )

    edr_cfg: Optional[EDRConfig] = None
    if "edr" in data and data["edr"]:
        edr_data = data["edr"]
        if edr_data.get("base_url") and edr_data.get("api_key"):
            edr_cfg = EDRConfig(
                edr_type=edr_data.get("edr_type", "velociraptor"),
                base_url=edr_data["base_url"],
                api_key=edr_data["api_key"],
                timeout_seconds=edr_data.get("timeout_seconds", 30),
                verify_ssl=edr_data.get("verify_ssl", True),
                additional_params=edr_data.get("additional_params"),
            )

    cti_cfg: Optional[CTIConfig] = None
    if "cti" in data and data["cti"]:
        cti_data = data["cti"]
        if cti_data.get("base_url"):
            # Handle api_key - it's optional for local_tip but required for opencti
            api_key = cti_data.get("api_key")
            cti_cfg = CTIConfig(
                cti_type=cti_data.get("cti_type", "local_tip"),
                base_url=cti_data["base_url"],
                api_key=api_key,
                timeout_seconds=cti_data.get("timeout_seconds", 30),
                verify_ssl=cti_data.get("verify_ssl", True),
            )

    eng_cfg: Optional[EngConfig] = None
    if "eng" in data and data["eng"]:
        eng_data = data["eng"]
        provider = eng_data.get("provider", "trello")
        
        trello_cfg: Optional[TrelloConfig] = None
        if eng_data.get("trello"):
            trello_data = eng_data["trello"]
            if trello_data.get("api_key") and trello_data.get("api_token"):
                trello_cfg = TrelloConfig(
                    api_key=trello_data["api_key"],
                    api_token=trello_data["api_token"],
                    fine_tuning_board_id=trello_data["fine_tuning_board_id"],
                    engineering_board_id=trello_data["engineering_board_id"],
                    timeout_seconds=trello_data.get("timeout_seconds", 30),
                    verify_ssl=trello_data.get("verify_ssl", True),
                )
        
        clickup_cfg: Optional[ClickUpConfig] = None
        if eng_data.get("clickup"):
            clickup_data = eng_data["clickup"]
            if clickup_data.get("api_token"):
                clickup_cfg = ClickUpConfig(
                    api_token=clickup_data["api_token"],
                    fine_tuning_list_id=clickup_data["fine_tuning_list_id"],
                    engineering_list_id=clickup_data["engineering_list_id"],
                    space_id=clickup_data.get("space_id"),
                    timeout_seconds=clickup_data.get("timeout_seconds", 30),
                    verify_ssl=clickup_data.get("verify_ssl", True),
                )
        
        github_cfg: Optional[GitHubConfig] = None
        if eng_data.get("github"):
            github_data = eng_data["github"]
            if github_data.get("api_token"):
                github_cfg = GitHubConfig(
                    api_token=github_data["api_token"],
                    fine_tuning_project_id=github_data["fine_tuning_project_id"],
                    engineering_project_id=github_data["engineering_project_id"],
                    timeout_seconds=github_data.get("timeout_seconds", 30),
                    verify_ssl=github_data.get("verify_ssl", True),
                )
        
        if trello_cfg or clickup_cfg or github_cfg:
            eng_cfg = EngConfig(
                trello=trello_cfg,
                clickup=clickup_cfg,
                github=github_cfg,
                provider=provider,
            )

    return SamiConfig(
        thehive=thehive_cfg,
        iris=iris_cfg,
        elastic=elastic_cfg,
        edr=edr_cfg,
        cti=cti_cfg,
        eng=eng_cfg,
        logging=logging_cfg,
    )


def load_config_from_env_file(env_path: str = ENV_FILE) -> Dict[str, Any]:
    """
    Load configuration from a .env file.

    Args:
        env_path: Path to the .env file.

    Returns:
        Dictionary with configuration values.

    Raises:
        ConfigError: If the file cannot be read or parsed.
    """
    env_file = Path(env_path)
    config_dict: Dict[str, Any] = {}

    if not env_file.exists():
        return config_dict

    try:
        with open(env_file, "r") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                # Parse KEY=VALUE
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    # Remove quotes if present
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    config_dict[key] = value
        return config_dict
    except Exception as e:
        raise ConfigError(f"Failed to load .env file: {e}") from e


def _env_dict_to_config(env_dict: Dict[str, Any]) -> SamiConfig:
    """Convert .env dictionary to SamiConfig."""
    logging_cfg = LoggingConfig(
        log_dir=env_dict.get("SAMIGPT_LOG_DIR", "logs"),
        log_level=env_dict.get("SAMIGPT_LOG_LEVEL", "INFO"),
    )

    thehive_cfg: Optional[TheHiveConfig] = None
    thehive_url = env_dict.get("SAMIGPT_THEHIVE_URL")
    thehive_api_key = env_dict.get("SAMIGPT_THEHIVE_API_KEY")
    if thehive_url and thehive_api_key:
        timeout = int(env_dict.get("SAMIGPT_THEHIVE_TIMEOUT_SECONDS", "30"))
        thehive_cfg = TheHiveConfig(
            base_url=thehive_url,
            api_key=thehive_api_key,
            timeout_seconds=timeout,
        )

    iris_cfg: Optional[IrisConfig] = None
    iris_url = env_dict.get("SAMIGPT_IRIS_URL")
    iris_api_key = env_dict.get("SAMIGPT_IRIS_API_KEY")
    if iris_url and iris_api_key:
        timeout = int(env_dict.get("SAMIGPT_IRIS_TIMEOUT_SECONDS", "30"))
        verify_ssl = env_dict.get("SAMIGPT_IRIS_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
        iris_cfg = IrisConfig(
            base_url=iris_url,
            api_key=iris_api_key,
            timeout_seconds=timeout,
            verify_ssl=verify_ssl,
        )

    elastic_cfg: Optional[ElasticConfig] = None
    elastic_url = env_dict.get("SAMIGPT_ELASTIC_URL")
    if elastic_url:
        timeout = int(env_dict.get("SAMIGPT_ELASTIC_TIMEOUT_SECONDS", "30"))
        verify_ssl = env_dict.get("SAMIGPT_ELASTIC_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
        elastic_cfg = ElasticConfig(
            base_url=elastic_url,
            api_key=env_dict.get("SAMIGPT_ELASTIC_API_KEY"),
            username=env_dict.get("SAMIGPT_ELASTIC_USERNAME"),
            password=env_dict.get("SAMIGPT_ELASTIC_PASSWORD"),
            timeout_seconds=timeout,
            verify_ssl=verify_ssl,
        )

    edr_cfg: Optional[EDRConfig] = None
    edr_url = env_dict.get("SAMIGPT_EDR_URL")
    edr_api_key = env_dict.get("SAMIGPT_EDR_API_KEY")
    if edr_url and edr_api_key:
        timeout = int(env_dict.get("SAMIGPT_EDR_TIMEOUT_SECONDS", "30"))
        verify_ssl = env_dict.get("SAMIGPT_EDR_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
        edr_cfg = EDRConfig(
            edr_type=env_dict.get("SAMIGPT_EDR_TYPE", "velociraptor"),
            base_url=edr_url,
            api_key=edr_api_key,
            timeout_seconds=timeout,
            verify_ssl=verify_ssl,
        )

    return SamiConfig(
        thehive=thehive_cfg,
        iris=iris_cfg,
        elastic=elastic_cfg,
        edr=edr_cfg,
        logging=logging_cfg,
    )


def _ensure_starting_config(config_path: str = CONFIG_FILE, starting_config_path: str = STARTING_CONFIG_FILE) -> None:
    """
    Ensure config.json exists by copying from starting config if needed.

    Args:
        config_path: Path to the JSON configuration file.
        starting_config_path: Path to the starting/template configuration file.
    """
    config_file = Path(config_path)
    starting_config_file = Path(starting_config_path)

    # If config.json doesn't exist, but starting config does, copy it
    if not config_file.exists() and starting_config_file.exists():
        try:
            shutil.copy2(starting_config_file, config_file)
        except Exception as e:
            # If copy fails, continue - we'll use defaults
            pass


def load_config_from_file(config_path: str = CONFIG_FILE, env_path: str = ENV_FILE, starting_config_path: str = STARTING_CONFIG_FILE) -> SamiConfig:
    """
    Load configuration from files. Tries .env file first, then JSON file.

    Priority: .env file > JSON file > starting config > defaults

    Args:
        config_path: Path to the JSON configuration file.
        env_path: Path to the .env file.
        starting_config_path: Path to the starting/template configuration file.

    Returns:
        SamiConfig instance.

    Raises:
        ConfigError: If the files cannot be read or parsed.
    """
    env_file = Path(env_path)
    config_file = Path(config_path)
    starting_config_file = Path(starting_config_path)

    # Ensure config.json exists by copying from starting config if needed
    _ensure_starting_config(config_path, starting_config_path)

    # Try .env file first
    if env_file.exists():
        try:
            env_dict = load_config_from_env_file(env_path)
            if env_dict:
                return _env_dict_to_config(env_dict)
        except Exception as e:
            # If .env parsing fails, try JSON
            pass

    # Fall back to JSON file
    if config_file.exists():
        try:
            with open(config_file, "r") as f:
                data = json.load(f)
            return _dict_to_config(data)
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in config file: {e}") from e
        except Exception as e:
            raise ConfigError(f"Failed to load config file: {e}") from e

    # Fall back to starting config file
    if starting_config_file.exists():
        try:
            with open(starting_config_file, "r") as f:
                data = json.load(f)
            return _dict_to_config(data)
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in starting config file: {e}") from e
        except Exception as e:
            # If starting config fails, continue to defaults
            pass

    # Return default config if no files exist
    return SamiConfig(
        thehive=None,
        elastic=None,
        edr=None,
        logging=LoggingConfig(),
    )


def save_config_to_env_file(config: SamiConfig, env_path: str = ENV_FILE) -> None:
    """
    Save configuration to a .env file.

    Args:
        config: SamiConfig instance to save.
        env_path: Path to the .env file.

    Raises:
        ConfigError: If the file cannot be written.
    """
    env_file = Path(env_path)

    try:
        # Create parent directories if needed
        env_file.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            "# SamiGPT Configuration File",
            "# This file can be edited manually or via the web interface",
            "# Changes are synchronized between this file and config.json",
            "",
        ]

        # Logging
        lines.append("# Logging Configuration")
        lines.append(f"SAMIGPT_LOG_DIR={config.logging.log_dir}")
        lines.append(f"SAMIGPT_LOG_LEVEL={config.logging.log_level}")
        lines.append("")

        # TheHive
        if config.thehive:
            lines.append("# TheHive Case Management")
            lines.append(f"SAMIGPT_THEHIVE_URL={config.thehive.base_url}")
            lines.append(f'SAMIGPT_THEHIVE_API_KEY="{config.thehive.api_key}"')
            lines.append(f"SAMIGPT_THEHIVE_TIMEOUT_SECONDS={config.thehive.timeout_seconds}")
            lines.append("")
        else:
            lines.append("# TheHive Case Management (disabled)")
            lines.append("# SAMIGPT_THEHIVE_URL=")
            lines.append("# SAMIGPT_THEHIVE_API_KEY=")
            lines.append("")

        # IRIS
        if config.iris:
            lines.append("# IRIS Case Management")
            lines.append(f"SAMIGPT_IRIS_URL={config.iris.base_url}")
            lines.append(f'SAMIGPT_IRIS_API_KEY="{config.iris.api_key}"')
            lines.append(f"SAMIGPT_IRIS_TIMEOUT_SECONDS={config.iris.timeout_seconds}")
            lines.append(f"SAMIGPT_IRIS_VERIFY_SSL={'true' if config.iris.verify_ssl else 'false'}")
            lines.append("")
        else:
            lines.append("# IRIS Case Management (disabled)")
            lines.append("# SAMIGPT_IRIS_URL=")
            lines.append("# SAMIGPT_IRIS_API_KEY=")
            lines.append("")

        # Elastic
        if config.elastic:
            lines.append("# Elastic (SIEM)")
            lines.append(f"SAMIGPT_ELASTIC_URL={config.elastic.base_url}")
            if config.elastic.api_key:
                lines.append(f'SAMIGPT_ELASTIC_API_KEY="{config.elastic.api_key}"')
            if config.elastic.username:
                lines.append(f'SAMIGPT_ELASTIC_USERNAME="{config.elastic.username}"')
            if config.elastic.password:
                lines.append(f'SAMIGPT_ELASTIC_PASSWORD="{config.elastic.password}"')
            lines.append(f"SAMIGPT_ELASTIC_TIMEOUT_SECONDS={config.elastic.timeout_seconds}")
            lines.append(f"SAMIGPT_ELASTIC_VERIFY_SSL={'true' if config.elastic.verify_ssl else 'false'}")
            lines.append("")
        else:
            lines.append("# Elastic (SIEM) (disabled)")
            lines.append("# SAMIGPT_ELASTIC_URL=")
            lines.append("")

        # EDR
        if config.edr:
            lines.append("# EDR Configuration")
            lines.append(f"SAMIGPT_EDR_TYPE={config.edr.edr_type}")
            lines.append(f"SAMIGPT_EDR_URL={config.edr.base_url}")
            lines.append(f'SAMIGPT_EDR_API_KEY="{config.edr.api_key}"')
            lines.append(f"SAMIGPT_EDR_TIMEOUT_SECONDS={config.edr.timeout_seconds}")
            lines.append(f"SAMIGPT_EDR_VERIFY_SSL={'true' if config.edr.verify_ssl else 'false'}")
            lines.append("")
        else:
            lines.append("# EDR Configuration (disabled)")
            lines.append("# SAMIGPT_EDR_URL=")
            lines.append("# SAMIGPT_EDR_API_KEY=")
            lines.append("")

        with open(env_file, "w") as f:
            f.write("\n".join(lines))
    except Exception as e:
        raise ConfigError(f"Failed to save .env file: {e}") from e


def save_config_to_file(
    config: SamiConfig, config_path: str = CONFIG_FILE, env_path: str = ENV_FILE, save_both: bool = True
) -> None:
    """
    Save configuration to both JSON and .env files for synchronization.

    Args:
        config: SamiConfig instance to save.
        config_path: Path to the JSON configuration file.
        env_path: Path to the .env file.
        save_both: If True, save to both JSON and .env. If False, only save to JSON.

    Raises:
        ConfigError: If the files cannot be written.
    """
    config_file = Path(config_path)

    try:
        # Create parent directories if needed
        config_file.parent.mkdir(parents=True, exist_ok=True)

        data = _config_to_dict(config)
        with open(config_file, "w") as f:
            json.dump(data, f, indent=2)

        # Also save to .env file for manual editing
        if save_both:
            save_config_to_env_file(config, env_path)
    except Exception as e:
        raise ConfigError(f"Failed to save config file: {e}") from e


def get_config_dict(config_path: str = CONFIG_FILE, env_path: str = ENV_FILE) -> Dict[str, Any]:
    """
    Get configuration as a dictionary (for API responses).

    Args:
        config_path: Path to the JSON configuration file.
        env_path: Path to the .env file.

    Returns:
        Dictionary representation of the configuration.
    """
    config = load_config_from_file(config_path, env_path)
    return _config_to_dict(config)


def update_config_dict(
    updates: Dict[str, Any], config_path: str = CONFIG_FILE, env_path: str = ENV_FILE, save_both: bool = True
) -> SamiConfig:
    """
    Update configuration with new values and save to both JSON and .env files.

    Args:
        updates: Dictionary with configuration updates.
        config_path: Path to the JSON configuration file.
        env_path: Path to the .env file.
        save_both: If True, save to both JSON and .env. If False, only save to JSON.

    Returns:
        Updated SamiConfig instance.

    Raises:
        ConfigError: If the update fails.
    """
    # Load existing config (checks both .env and JSON)
    config = load_config_from_file(config_path, env_path)

    # Update logging
    if "logging" in updates:
        logging_updates = updates["logging"]
        if "log_dir" in logging_updates:
            config.logging.log_dir = logging_updates["log_dir"]
        if "log_level" in logging_updates:
            config.logging.log_level = logging_updates["log_level"]

    # Update TheHive
    if "thehive" in updates:
        th_updates = updates["thehive"]
        if th_updates is None:
            config.thehive = None
        elif th_updates.get("base_url") and th_updates.get("api_key"):
            config.thehive = TheHiveConfig(
                base_url=th_updates["base_url"],
                api_key=th_updates["api_key"],
                timeout_seconds=th_updates.get("timeout_seconds", 30),
            )

    # Update IRIS
    if "iris" in updates:
        iris_updates = updates["iris"]
        if iris_updates is None:
            config.iris = None
        elif iris_updates.get("base_url") and iris_updates.get("api_key"):
            config.iris = IrisConfig(
                base_url=iris_updates["base_url"],
                api_key=iris_updates["api_key"],
                timeout_seconds=iris_updates.get("timeout_seconds", 30),
                verify_ssl=iris_updates.get("verify_ssl", True),
            )

    # Update Elastic
    if "elastic" in updates:
        el_updates = updates["elastic"]
        if el_updates is None:
            config.elastic = None
        elif el_updates.get("base_url"):
            config.elastic = ElasticConfig(
                base_url=el_updates["base_url"],
                api_key=el_updates.get("api_key"),
                username=el_updates.get("username"),
                password=el_updates.get("password"),
                timeout_seconds=el_updates.get("timeout_seconds", 30),
                verify_ssl=el_updates.get("verify_ssl", True),
            )

    # Update EDR
    if "edr" in updates:
        edr_updates = updates["edr"]
        if edr_updates is None:
            config.edr = None
        elif edr_updates.get("base_url") and edr_updates.get("api_key"):
            config.edr = EDRConfig(
                edr_type=edr_updates.get("edr_type", "velociraptor"),
                base_url=edr_updates["base_url"],
                api_key=edr_updates["api_key"],
                timeout_seconds=edr_updates.get("timeout_seconds", 30),
                verify_ssl=edr_updates.get("verify_ssl", True),
                additional_params=edr_updates.get("additional_params"),
            )

    # Save updated config to both files
    save_config_to_file(config, config_path, env_path, save_both=save_both)
    return config

