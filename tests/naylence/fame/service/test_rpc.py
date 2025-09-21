"""Tests for naylence.fame.service.rpc module."""

import inspect
from types import MappingProxyType
from unittest.mock import AsyncMock, Mock, patch

import pytest

from naylence.fame.service.rpc import RpcMixin, RpcProxy, operation


class TestOperation:
    """Test the @operation decorator - lines 51-61."""

    def test_operation_bare_decorator(self):
        """Test @operation without parameters."""

        # Test the bare form @operation
        @operation
        async def test_func():
            return "test"

        assert test_func._rpc_name == "test_func"
        assert test_func._rpc_streaming is False

    def test_operation_with_parameters(self):
        """Test @operation with name and streaming parameters."""

        # Test the called form @operation(...)
        @operation(name="custom.name", streaming=True)
        async def test_func():
            return "test"

        assert test_func._rpc_name == "custom.name"
        assert test_func._rpc_streaming is True

    def test_operation_with_name_only(self):
        """Test @operation with only name parameter."""

        @operation(name="custom.name")
        async def test_func():
            return "test"

        assert test_func._rpc_name == "custom.name"
        assert test_func._rpc_streaming is False

    def test_operation_with_streaming_only(self):
        """Test @operation with only streaming parameter."""

        @operation(streaming=True)
        async def test_func():
            return "test"

        assert test_func._rpc_name == "test_func"
        assert test_func._rpc_streaming is True

    def test_operation_preserves_function_metadata(self):
        """Test that @operation preserves original function metadata."""

        @operation
        async def test_func():
            """Test docstring."""
            return "test"

        assert test_func.__name__ == "test_func"
        assert test_func.__doc__ == "Test docstring."


class TestRpcMixin:
    """Test the RpcMixin class - lines 84-95, 110-125."""

    def test_init_subclass_creates_registry(self):
        """Test that __init_subclass__ creates _rpc_registry."""

        class TestService(RpcMixin):
            @operation
            async def test_method(self):
                return "test"

            @operation(name="custom.method", streaming=True)
            async def streaming_method(self):
                return "stream"

        # Verify registry was created correctly
        assert isinstance(TestService._rpc_registry, MappingProxyType)
        assert "test_method" in TestService._rpc_registry
        assert "custom.method" in TestService._rpc_registry

        # Verify registry contents
        assert TestService._rpc_registry["test_method"] == ("test_method", False)
        assert TestService._rpc_registry["custom.method"] == ("streaming_method", True)

    def test_init_subclass_inheritance(self):
        """Test that __init_subclass__ handles inheritance correctly."""

        class BaseService(RpcMixin):
            @operation
            async def base_method(self):
                return "base"

        class DerivedService(BaseService):
            @operation
            async def derived_method(self):
                return "derived"

        # Verify both methods are in derived class registry
        assert "base_method" in DerivedService._rpc_registry
        assert "derived_method" in DerivedService._rpc_registry
        assert len(DerivedService._rpc_registry) == 2

    def test_init_subclass_empty_registry(self):
        """Test __init_subclass__ with no @operation methods."""

        class EmptyService(RpcMixin):
            async def regular_method(self):
                return "not_rpc"

        # Should have empty registry
        assert len(EmptyService._rpc_registry) == 0

    @pytest.mark.asyncio
    async def test_handle_rpc_request_known_method(self):
        """Test handle_rpc_request with known method."""

        class TestService(RpcMixin):
            @operation
            async def test_method(self, param1, param2="default"):
                return f"result: {param1}, {param2}"

        service = TestService()
        params = {"kwargs": {"param1": "value1", "param2": "value2"}}

        result = await service.handle_rpc_request("test_method", params)
        assert result == "result: value1, value2"

    @pytest.mark.asyncio
    async def test_handle_rpc_request_async_generator(self):
        """Test handle_rpc_request with async generator method."""

        class TestService(RpcMixin):
            @operation(streaming=True)
            async def streaming_method(self, count=3):
                for i in range(count):
                    yield f"item_{i}"

        service = TestService()
        params = {"kwargs": {"count": 2}}

        result = await service.handle_rpc_request("streaming_method", params)
        # Should return the async generator directly without awaiting
        assert inspect.isasyncgen(result)

    @pytest.mark.asyncio
    async def test_handle_rpc_request_no_params(self):
        """Test handle_rpc_request with no parameters."""

        class TestService(RpcMixin):
            @operation
            async def no_param_method(self):
                return "no_params"

        service = TestService()

        # Test with None params
        result = await service.handle_rpc_request("no_param_method", None)
        assert result == "no_params"

        # Test with empty params
        result = await service.handle_rpc_request("no_param_method", {})
        assert result == "no_params"

    @pytest.mark.asyncio
    async def test_handle_rpc_request_unknown_method(self):
        """Test handle_rpc_request with unknown method."""

        class TestService(RpcMixin):
            @operation
            async def known_method(self):
                return "known"

        service = TestService()

        with pytest.raises(ValueError, match="Unknown RPC method: unknown_method"):
            await service.handle_rpc_request("unknown_method", {})


class TestRpcProxy:
    """Test the RpcProxy class - lines 130-157."""

    def test_getattr_private_attributes(self):
        """Test __getattr__ for private attributes."""
        proxy = RpcProxy()

        # Should delegate to super for private attributes
        with pytest.raises(AttributeError):
            _ = proxy._nonexistent_private_attr

    @pytest.mark.asyncio
    async def test_getattr_public_method_with_address(self):
        """Test __getattr__ for public method calls with address."""
        proxy = RpcProxy()
        proxy._address = "test.address"
        proxy._timeout = 5000

        # Mock the _invoke method
        proxy._invoke = AsyncMock(return_value="invoke_result")

        method = proxy.test_method
        result = await method({"key": "value"})

        proxy._invoke.assert_called_once_with("test.address", "test_method", {"key": "value"})
        assert result == "invoke_result"

    @pytest.mark.asyncio
    async def test_getattr_public_method_with_capabilities(self):
        """Test __getattr__ for public method calls with capabilities."""
        proxy = RpcProxy()
        proxy._address = None
        proxy._capabilities = ["test.capability"]
        proxy._timeout = 5000

        # Mock the _invoke_by_capability method
        proxy._invoke_by_capability = AsyncMock(return_value="capability_result")

        method = proxy.test_method
        result = await method("arg1", kwarg1="value1")

        expected_params = {"args": ("arg1",), "kwargs": {"kwarg1": "value1"}}
        proxy._invoke_by_capability.assert_called_once_with(
            ["test.capability"], "test_method", expected_params
        )
        assert result == "capability_result"

    @pytest.mark.asyncio
    async def test_getattr_streaming_with_address(self):
        """Test __getattr__ for streaming calls with address."""
        proxy = RpcProxy()
        proxy._address = "test.address"
        proxy._timeout = 5000

        # Mock FameFabric
        mock_fabric = Mock()
        mock_fabric.invoke_stream = AsyncMock(return_value="stream_result")
        proxy._fabric = mock_fabric

        method = proxy.test_method
        result = await method({"data": "test"}, _stream=True)

        mock_fabric.invoke_stream.assert_called_once_with(
            "test.address", "test_method", {"data": "test"}, timeout_ms=5000
        )
        assert result == "stream_result"

    @pytest.mark.asyncio
    async def test_getattr_streaming_with_capabilities(self):
        """Test __getattr__ for streaming calls with capabilities."""
        proxy = RpcProxy()
        proxy._address = None
        proxy._capabilities = ["test.capability"]
        proxy._timeout = 5000

        # Mock FameFabric
        mock_fabric = Mock()
        mock_fabric.invoke_by_capability_stream = AsyncMock(return_value="capability_stream_result")
        proxy._fabric = mock_fabric

        method = proxy.test_method
        result = await method("arg1", kwarg1="value1", _stream=True)

        expected_params = {"args": ("arg1",), "kwargs": {"kwarg1": "value1"}}
        mock_fabric.invoke_by_capability_stream.assert_called_once_with(
            ["test.capability"], "test_method", expected_params, timeout_ms=5000
        )
        assert result == "capability_stream_result"

    @pytest.mark.asyncio
    @patch("naylence.fame.service.rpc.FameFabric.current")
    async def test_getattr_streaming_current_fabric(self, mock_current):
        """Test __getattr__ uses FameFabric.current() when _fabric is None."""
        proxy = RpcProxy()
        proxy._address = "test.address"
        proxy._timeout = 5000
        proxy._fabric = None

        # Mock current fabric
        mock_fabric = Mock()
        mock_fabric.invoke_stream = AsyncMock(return_value="current_fabric_result")
        mock_current.return_value = mock_fabric

        method = proxy.test_method
        result = await method({"data": "test"}, _stream=True)

        mock_current.assert_called_once()
        mock_fabric.invoke_stream.assert_called_once_with(
            "test.address", "test_method", {"data": "test"}, timeout_ms=5000
        )
        assert result == "current_fabric_result"

    @pytest.mark.asyncio
    async def test_getattr_single_dict_arg_packing(self):
        """Test __getattr__ parameter packing for single dict argument."""
        proxy = RpcProxy()
        proxy._address = "test.address"
        proxy._invoke = AsyncMock(return_value="packed_result")

        method = proxy.test_method
        # Call with single dict argument - should be passed as-is
        result = await method({"key": "value"})

        proxy._invoke.assert_called_once_with("test.address", "test_method", {"key": "value"})
        assert result == "packed_result"

    @pytest.mark.asyncio
    async def test_getattr_args_kwargs_packing(self):
        """Test __getattr__ parameter packing for args and kwargs."""
        proxy = RpcProxy()
        proxy._address = "test.address"
        proxy._invoke = AsyncMock(return_value="packed_result")

        method = proxy.test_method
        # Call with args and kwargs - should be packed into structure
        result = await method("arg1", "arg2", kwarg1="value1")

        expected_params = {"args": ("arg1", "arg2"), "kwargs": {"kwarg1": "value1"}}
        proxy._invoke.assert_called_once_with("test.address", "test_method", expected_params)
        assert result == "packed_result"

    @pytest.mark.asyncio
    async def test_getattr_stream_kwarg_removal(self):
        """Test that _stream kwarg is removed from parameters."""
        proxy = RpcProxy()
        proxy._address = "test.address"
        proxy._timeout = 5000

        # Mock fabric for streaming
        mock_fabric = Mock()
        mock_fabric.invoke_stream = AsyncMock(return_value="stream_result")
        proxy._fabric = mock_fabric

        method = proxy.test_method
        result = await method("arg1", kwarg1="value1", _stream=True)

        # _stream should be removed from kwargs before packing
        expected_params = {"args": ("arg1",), "kwargs": {"kwarg1": "value1"}}
        mock_fabric.invoke_stream.assert_called_once_with(
            "test.address", "test_method", expected_params, timeout_ms=5000
        )
        assert result == "stream_result"
