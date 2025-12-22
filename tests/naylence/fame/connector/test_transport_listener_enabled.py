"""Tests for TransportListenerConfig enabled flag functionality."""


from naylence.fame.connector.transport_listener_config import TransportListenerConfig


class TestTransportListenerConfigEnabled:
    """Tests for the enabled property on TransportListenerConfig."""

    def test_enabled_defaults_to_true(self):
        """Test that enabled defaults to True when not specified."""
        config = TransportListenerConfig(type="HttpListener")
        assert config.enabled is True

    def test_enabled_can_be_set_to_false(self):
        """Test that enabled can be explicitly set to False."""
        config = TransportListenerConfig(type="HttpListener", enabled=False)
        assert config.enabled is False

    def test_enabled_can_be_set_to_true(self):
        """Test that enabled can be explicitly set to True."""
        config = TransportListenerConfig(type="HttpListener", enabled=True)
        assert config.enabled is True

    def test_enabled_from_dict_with_camel_case(self):
        """Test that enabled works with camelCase alias."""
        config = TransportListenerConfig.model_validate(
            {"type": "HttpListener", "enabled": False}
        )
        assert config.enabled is False

    def test_enabled_not_in_dict_defaults_to_true(self):
        """Test that config from dict without enabled defaults to True."""
        config = TransportListenerConfig.model_validate({"type": "HttpListener"})
        assert config.enabled is True


class TestListenerFilteringLogic:
    """Tests for the enabled flag filtering logic used in factory_commons."""

    def _should_create_listener(self, listener_config) -> bool:
        """
        Test helper that replicates the filtering logic from factory_commons.
        This tests the same logic without needing to mock all of make_common_opts.
        """
        if isinstance(listener_config, dict):
            if listener_config.get("enabled") is False:
                return False
        elif hasattr(listener_config, "enabled") and listener_config.enabled is False:
            return False
        return True

    def test_dict_config_without_enabled_is_created(self):
        """Test that dict config without enabled property returns True."""
        config = {"type": "HttpListener", "port": 8080}
        assert self._should_create_listener(config) is True

    def test_dict_config_with_enabled_true_is_created(self):
        """Test that dict config with enabled=True returns True."""
        config = {"type": "HttpListener", "port": 8080, "enabled": True}
        assert self._should_create_listener(config) is True

    def test_dict_config_with_enabled_false_is_skipped(self):
        """Test that dict config with enabled=False returns False."""
        config = {"type": "HttpListener", "port": 8080, "enabled": False}
        assert self._should_create_listener(config) is False

    def test_pydantic_config_without_explicit_enabled_is_created(self):
        """Test that Pydantic config (defaults to enabled=True) returns True."""
        config = TransportListenerConfig(type="HttpListener", port=8080)
        assert self._should_create_listener(config) is True

    def test_pydantic_config_with_enabled_true_is_created(self):
        """Test that Pydantic config with enabled=True returns True."""
        config = TransportListenerConfig(type="HttpListener", port=8080, enabled=True)
        assert self._should_create_listener(config) is True

    def test_pydantic_config_with_enabled_false_is_skipped(self):
        """Test that Pydantic config with enabled=False returns False."""
        config = TransportListenerConfig(type="HttpListener", port=8080, enabled=False)
        assert self._should_create_listener(config) is False

    def test_mixed_configs_filtering(self):
        """Test filtering a list of mixed configs."""
        configs = [
            {"type": "HttpListener", "port": 8080},  # no enabled (should create)
            {"type": "WebSocketListener", "port": 8080, "enabled": True},  # should create
            {"type": "AgentHttpGatewayListener", "port": 8080, "enabled": False},  # should skip
            TransportListenerConfig(type="AnotherListener", port=9090),  # should create
            TransportListenerConfig(type="DisabledListener", port=9091, enabled=False),  # should skip
        ]

        created = [c for c in configs if self._should_create_listener(c)]
        assert len(created) == 3

        # Verify correct configs are included
        created_types = []
        for c in created:
            if isinstance(c, dict):
                created_types.append(c["type"])
            else:
                created_types.append(c.type)

        assert "HttpListener" in created_types
        assert "WebSocketListener" in created_types
        assert "AnotherListener" in created_types
        assert "AgentHttpGatewayListener" not in created_types
        assert "DisabledListener" not in created_types

    def test_all_disabled_configs(self):
        """Test that all disabled configs result in empty list."""
        configs = [
            {"type": "HttpListener", "port": 8080, "enabled": False},
            {"type": "WebSocketListener", "port": 8080, "enabled": False},
        ]

        created = [c for c in configs if self._should_create_listener(c)]
        assert len(created) == 0

    def test_all_enabled_configs(self):
        """Test that all enabled configs are created."""
        configs = [
            {"type": "HttpListener", "port": 8080, "enabled": True},
            {"type": "WebSocketListener", "port": 8080},  # defaults to enabled
        ]

        created = [c for c in configs if self._should_create_listener(c)]
        assert len(created) == 2
