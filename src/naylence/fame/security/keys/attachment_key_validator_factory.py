"""
Factory and configuration for attachment key validators.

This module provides the factory interface and configuration classes for creating
attachment key validators that validate keys during node handshake.
"""

from __future__ import annotations

from abc import ABC
from typing import TypeVar

from naylence.fame.factory import ResourceConfig, ResourceFactory
from naylence.fame.security.keys.attachment_key_validator import AttachmentKeyValidator


class AttachmentKeyValidatorConfig(ResourceConfig):
    """Base configuration for attachment key validators"""

    type: str = "AttachmentKeyValidator"


C = TypeVar("C", bound=AttachmentKeyValidatorConfig)


class AttachmentKeyValidatorFactory(ABC, ResourceFactory[AttachmentKeyValidator, C]):
    """Abstract factory for creating attachment key validators."""

    pass
