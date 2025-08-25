"""Utilities for handling optional dependencies."""

from typing import Any, Optional


def try_import(module_name: str, package: Optional[str] = None) -> Optional[Any]:
    """Try to import a module, return None if it's not available."""
    try:
        import importlib

        return importlib.import_module(module_name, package)
    except ImportError:
        return None


def require_crypto() -> None:
    """Raise helpful error if cryptography is not available."""
    if try_import("cryptography") is None:
        raise ImportError(
            "This feature requires the 'cryptography' package. "
            "Install it with: pip install 'naylence-fame-runtime[crypto]' "
            "or 'naylence-fame-runtime[x25519]'"
        )


def require_jwt() -> None:
    """Raise helpful error if PyJWT is not available."""
    if try_import("jwt") is None:
        raise ImportError(
            "This feature requires the 'pyjwt' package. "
            "Install it with: pip install 'naylence-fame-runtime[jwt]' or 'naylence-fame-runtime[crypto]'"
        )


def has_crypto() -> bool:
    """Check if cryptography is available."""
    return try_import("cryptography") is not None


def has_jwt() -> bool:
    """Check if PyJWT is available."""
    return try_import("jwt") is not None
