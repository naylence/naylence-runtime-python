from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import ConfigDict, Field, ValidationError

from naylence.fame.core import FameConfig
from naylence.fame.util import logging

# configure logger
logger = logging.getLogger(__name__)

ENV_VAR_FAME_CONFIG = "FAME_CONFIG"

# search order: current dir then /etc/fame
_CONFIG_SEARCH_PATHS = [
    Path("fame-config.json"),
    Path("fame-config.yaml"),
    Path("fame-config.yml"),
    Path("/etc/fame/fame-config.json"),
    Path("/etc/fame/fame-config.yaml"),
    Path("/etc/fame/fame-config.yml"),
]


class ExtendedFameConfig(FameConfig):
    node: Optional[Any] = Field(None, description="Node config")
    welcome: Optional[Any] = Field(None, description="Welcome service config")

    model_config = ConfigDict(extra="allow")


def load_fame_config() -> FameConfig:
    """
    Load FameConfig from:
      1) FAME_CONFIG env var (JSON string)
      2) fame-config.{json,yaml,yml} in cwd or /etc/fame/
      3) Defaults from FameConfig model
    """
    # 1) env var
    raw = os.getenv(ENV_VAR_FAME_CONFIG)
    if raw:
        # Check if it's a file path first
        config_path = Path(raw.strip())
        if config_path.is_file():
            # It's a file path - read and parse the file
            try:
                text = config_path.read_text()
                if config_path.suffix.lower() in (".yaml", ".yml"):
                    cfg_dict = yaml.safe_load(text)
                    logger.debug("loaded_fame_config_from_env_var_file_yaml", file=config_path)
                else:
                    cfg_dict = json.loads(text)
                    logger.debug("loaded_fame_config_from_env_var_file_json", file=config_path)
            except Exception as e:
                logger.error("Failed to parse config file %s from FAME_CONFIG: %s", config_path, e)
                raise
        else:
            # It's raw content - try parsing directly
            json_error = None
            yaml_error = None

            # Try JSON first
            try:
                cfg_dict = json.loads(raw)
                logger.debug("loaded_fame_config_from_env_var_json")
            except json.JSONDecodeError as e:
                json_error = e
                # If JSON fails, try YAML
                try:
                    cfg_dict = yaml.safe_load(raw)
                    logger.debug("loaded_fame_config_from_env_var_yaml")
                except yaml.YAMLError as e:
                    yaml_error = e
                    # Both parsing attempts failed
                    logger.error(
                        "Invalid JSON/YAML in FAME_CONFIG. JSON error: %s, YAML error: %s",
                        json_error,
                        yaml_error,
                    )
                    raise ValueError(
                        f"FAME_CONFIG contains invalid JSON/YAML. JSON error: {json_error}, YAML error: {
                            yaml_error
                        }"
                    )
    else:
        # 2) config files
        cfg_dict: Dict[str, Any] = {}
        for path in _CONFIG_SEARCH_PATHS:
            if path.is_file():
                text = path.read_text()
                try:
                    if path.suffix in (".yaml", ".yml"):
                        cfg_dict = yaml.safe_load(text)  # type: ignore
                    else:
                        cfg_dict = json.loads(text)
                except Exception as e:
                    logger.error("Failed to parse config %s: %s", path, e)
                    raise
                logger.debug("loaded_fame_config_from_file", file=path)
                break

    # 3) instantiate

    try:
        return ExtendedFameConfig(**cfg_dict)
    except ValidationError as ve:
        logger.error("FameConfig validation error: %s", ve)
        raise


_instance: Optional[FameConfig] = None


def get_fame_config() -> FameConfig:
    global _instance
    if _instance is None:
        _instance = load_fame_config()
    return _instance
