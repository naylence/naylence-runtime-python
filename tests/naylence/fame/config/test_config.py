import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from naylence.fame.config.config import (
    ENV_VAR_FAME_CONFIG,
    ExtendedFameConfig,
    get_fame_config,
    load_fame_config,
)


@pytest.fixture(autouse=True)
def reset_config_singleton():
    """Reset the global config instance between tests."""
    from naylence.fame.config import config

    config._instance = None
    yield
    config._instance = None


@pytest.fixture
def temp_config_file():
    """Create a temporary config file and return its path."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        yield Path(f.name)
    # Cleanup
    Path(f.name).unlink(missing_ok=True)


@pytest.fixture
def temp_yaml_config_file():
    """Create a temporary YAML config file and return its path."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml") as f:
        yield Path(f.name)
    # Cleanup
    Path(f.name).unlink(missing_ok=True)


class TestLoadFameConfigFromEnvVar:
    """Test loading config from FAME_CONFIG environment variable."""

    def test_load_from_env_var_raw_json(self, monkeypatch):
        """Test loading config from raw JSON in environment variable."""
        config_data = {"node": {"port": 8080}, "welcome": {"enabled": True}}
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, json.dumps(config_data))

        config = load_fame_config()

        assert isinstance(config, ExtendedFameConfig)
        assert config.node == {"port": 8080}
        assert config.welcome == {"enabled": True}

    def test_load_from_env_var_raw_yaml(self, monkeypatch):
        """Test loading config from raw YAML in environment variable."""
        yaml_content = """
        node:
          port: 8080
        welcome:
          enabled: true
        """
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, yaml_content)

        config = load_fame_config()

        assert isinstance(config, ExtendedFameConfig)
        assert config.node == {"port": 8080}
        assert config.welcome == {"enabled": True}

    def test_load_from_env_var_file_path_json(self, monkeypatch, temp_config_file):
        """Test loading config from JSON file path in environment variable."""
        config_data = {"node": {"port": 9090}, "welcome": {"timeout": 30}}
        temp_config_file.write_text(json.dumps(config_data))

        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, str(temp_config_file))

        config = load_fame_config()

        assert isinstance(config, ExtendedFameConfig)
        assert config.node == {"port": 9090}
        assert config.welcome == {"timeout": 30}

    def test_load_from_env_var_file_path_yaml(self, monkeypatch, temp_yaml_config_file):
        """Test loading config from YAML file path in environment variable."""
        yaml_content = """
        node:
          port: 7070
        welcome:
          debug: true
        """
        temp_yaml_config_file.write_text(yaml_content)

        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, str(temp_yaml_config_file))

        config = load_fame_config()

        assert isinstance(config, ExtendedFameConfig)
        assert config.node == {"port": 7070}
        assert config.welcome == {"debug": True}

    def test_load_from_env_var_file_path_with_spaces(self, monkeypatch, temp_config_file):
        """Test loading config from file path with leading/trailing spaces."""
        config_data = {"node": {"port": 6060}}
        temp_config_file.write_text(json.dumps(config_data))

        # Add spaces around the file path
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, f"  {temp_config_file}  ")

        config = load_fame_config()

        assert isinstance(config, ExtendedFameConfig)
        assert config.node == {"port": 6060}

    def test_load_from_env_var_invalid_json(self, monkeypatch):
        """Test error handling for invalid JSON in environment variable."""
        # Use content that fails both JSON and YAML parsing
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, "{{nested: invalid}}")

        with pytest.raises(ValueError) as exc_info:
            load_fame_config()

        assert "FAME_CONFIG contains invalid JSON/YAML" in str(exc_info.value)
        assert "JSON error:" in str(exc_info.value)
        assert "YAML error:" in str(exc_info.value)

    def test_load_from_env_var_invalid_yaml(self, monkeypatch):
        """Test error handling for invalid YAML in environment variable."""
        # Use content that fails both JSON and YAML parsing
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, "invalid: yaml: content: [unclosed")

        with pytest.raises(ValueError) as exc_info:
            load_fame_config()

        assert "FAME_CONFIG contains invalid JSON/YAML" in str(exc_info.value)

    def test_load_from_env_var_content_that_parses_as_string(self, monkeypatch):
        """Test handling of content that YAML parses as a string instead of dict."""
        # This will parse as a string in YAML, causing TypeError when creating config
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, "just a simple string")

        with pytest.raises(TypeError) as exc_info:
            load_fame_config()

        assert "argument after ** must be a mapping" in str(exc_info.value)

    def test_load_from_env_var_nonexistent_file(self, monkeypatch):
        """Test that nonexistent file path falls back to content parsing."""
        # This should be treated as raw content, not a file path
        # Use content that will fail as both JSON and YAML when instantiating ExtendedFameConfig
        nonexistent_path = "/path/that/does/not/exist.json"
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, nonexistent_path)

        with pytest.raises(TypeError) as exc_info:
            load_fame_config()

        # Should fail when trying to create ExtendedFameConfig with a string instead of dict
        assert "argument after ** must be a mapping" in str(exc_info.value)

    def test_load_from_env_var_file_parse_error(self, monkeypatch, temp_config_file):
        """Test error handling for file with invalid content."""
        temp_config_file.write_text('{"invalid": json}')

        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, str(temp_config_file))

        with pytest.raises(Exception) as exc_info:
            load_fame_config()

        # Should re-raise the JSON parsing error directly
        assert "Expecting value" in str(exc_info.value)

    def test_load_from_env_var_file_extension_detection(self, monkeypatch):
        """Test that file extension properly determines parsing method."""
        # Test .yml extension
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yml") as f:
            yml_file = Path(f.name)
            yml_content = "node:\n  port: 5050"
            yml_file.write_text(yml_content)

            monkeypatch.setenv(ENV_VAR_FAME_CONFIG, str(yml_file))

            config = load_fame_config()
            assert config.node == {"port": 5050}

            yml_file.unlink()


class TestLoadFameConfigFromFiles:
    """Test loading config from search path files."""

    def test_load_from_search_path_json(self, monkeypatch):
        """Test loading config from JSON file in search path."""
        config_data = {"node": {"port": 4040}}

        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "fame-config.json"
            config_file.write_text(json.dumps(config_data))

            # Mock the search paths to include our temp directory
            with patch("naylence.fame.config.config._CONFIG_SEARCH_PATHS", [config_file]):
                monkeypatch.delenv(ENV_VAR_FAME_CONFIG, raising=False)

                config = load_fame_config()

                assert isinstance(config, ExtendedFameConfig)
                assert config.node == {"port": 4040}

    def test_load_from_search_path_yaml(self, monkeypatch):
        """Test loading config from YAML file in search path."""
        yaml_content = "node:\n  port: 3030"

        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "fame-config.yaml"
            config_file.write_text(yaml_content)

            # Mock the search paths to include our temp directory
            with patch("naylence.fame.config.config._CONFIG_SEARCH_PATHS", [config_file]):
                monkeypatch.delenv(ENV_VAR_FAME_CONFIG, raising=False)

                config = load_fame_config()

                assert isinstance(config, ExtendedFameConfig)
                assert config.node == {"port": 3030}

    def test_load_search_path_priority(self, monkeypatch):
        """Test that first found file in search path takes priority."""
        config_data_1 = {"node": {"port": 1111}}
        config_data_2 = {"node": {"port": 2222}}

        with tempfile.TemporaryDirectory() as temp_dir:
            config_file_1 = Path(temp_dir) / "config1.json"
            config_file_2 = Path(temp_dir) / "config2.json"

            config_file_1.write_text(json.dumps(config_data_1))
            config_file_2.write_text(json.dumps(config_data_2))

            # First file should take priority
            with patch("naylence.fame.config.config._CONFIG_SEARCH_PATHS", [config_file_1, config_file_2]):
                monkeypatch.delenv(ENV_VAR_FAME_CONFIG, raising=False)

                config = load_fame_config()

                assert config.node == {"port": 1111}

    def test_load_no_config_files_defaults(self, monkeypatch):
        """Test that default config is returned when no files are found."""
        # Mock empty search paths
        with patch("naylence.fame.config.config._CONFIG_SEARCH_PATHS", []):
            monkeypatch.delenv(ENV_VAR_FAME_CONFIG, raising=False)

            config = load_fame_config()

            assert isinstance(config, ExtendedFameConfig)
            # Should have default values
            assert config.node is None
            assert config.welcome is None


class TestGetFameConfig:
    """Test singleton behavior of get_fame_config."""

    def test_singleton_behavior(self, monkeypatch):
        """Test that get_fame_config returns the same instance."""
        config_data = {"node": {"port": 8888}}
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, json.dumps(config_data))

        config1 = get_fame_config()
        config2 = get_fame_config()

        assert config1 is config2
        assert config1.node == {"port": 8888}

    def test_singleton_reset_after_env_change(self, monkeypatch):
        """Test that changing environment doesn't affect already loaded config."""
        config_data_1 = {"node": {"port": 7777}}
        config_data_2 = {"node": {"port": 9999}}

        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, json.dumps(config_data_1))
        config1 = get_fame_config()

        # Change environment variable
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, json.dumps(config_data_2))
        config2 = get_fame_config()

        # Should still be the same instance with original config
        assert config1 is config2
        assert config1.node == {"port": 7777}


class TestConfigValidation:
    """Test configuration validation."""

    def test_validation_error_handling(self, monkeypatch):
        """Test that validation errors are properly handled."""
        # This might depend on the actual FameConfig validation rules
        # For now, test with an empty config that should be valid
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, "{}")

        config = load_fame_config()

        assert isinstance(config, ExtendedFameConfig)

    def test_extended_config_fields(self, monkeypatch):
        """Test that ExtendedFameConfig accepts node and welcome fields."""
        config_data = {"node": {"custom_field": "value"}, "welcome": {"another_field": 123}}
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, json.dumps(config_data))

        config = load_fame_config()

        assert isinstance(config, ExtendedFameConfig)
        assert config.node == {"custom_field": "value"}
        assert config.welcome == {"another_field": 123}


class TestErrorScenarios:
    """Test various error scenarios and edge cases."""

    def test_env_var_empty_string(self, monkeypatch):
        """Test behavior with empty environment variable."""
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, "")

        # Empty string should be treated as no env var
        with patch("naylence.fame.config.config._CONFIG_SEARCH_PATHS", []):
            config = load_fame_config()

            assert isinstance(config, ExtendedFameConfig)
            assert config.node is None

    def test_env_var_whitespace_only(self, monkeypatch):
        """Test behavior with whitespace-only environment variable."""
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, "   \n\t   ")

        with pytest.raises(ValueError) as exc_info:
            load_fame_config()

        assert "FAME_CONFIG contains invalid JSON/YAML" in str(exc_info.value)

    def test_file_permission_error(self, monkeypatch, temp_config_file):
        """Test handling of file permission errors."""
        config_data = {"node": {"port": 5555}}
        temp_config_file.write_text(json.dumps(config_data))

        # Make file unreadable (this might not work on all systems)
        try:
            temp_config_file.chmod(0o000)
            monkeypatch.setenv(ENV_VAR_FAME_CONFIG, str(temp_config_file))

            with pytest.raises(Exception):
                load_fame_config()
        finally:
            # Restore permissions for cleanup
            temp_config_file.chmod(0o644)

    def test_complex_yaml_structures(self, monkeypatch):
        """Test parsing of complex YAML structures."""
        yaml_content = """
        node:
          port: 8080
          hosts:
            - localhost
            - 0.0.0.0
          config:
            nested:
              value: true
        welcome:
          - item1
          - item2
        """
        monkeypatch.setenv(ENV_VAR_FAME_CONFIG, yaml_content)

        config = load_fame_config()

        assert config.node["port"] == 8080
        assert config.node["hosts"] == ["localhost", "0.0.0.0"]
        assert config.node["config"]["nested"]["value"] is True
        assert config.welcome == ["item1", "item2"]
