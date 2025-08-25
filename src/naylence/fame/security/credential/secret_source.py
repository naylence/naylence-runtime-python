"""
SecretSource - A reusable field type for handling various secret input formats.

This module provides a Pydantic-compatible field type that can accept secrets
in multiple formats and normalize them to CredentialProviderConfig instances.
"""

from __future__ import annotations

from typing import Any, Union

from pydantic_core import core_schema

from naylence.fame.security.credential.credential_provider_factory import (
    CredentialProviderConfig,
)


class SecretSource:
    """
    A reusable field type that deserializes various secret input formats
    to a CredentialProviderConfig.

    Accepted input forms:
    --------------------
    • Plain string: "my-secret"
      → StaticCredentialProviderConfig(credential_value="my-secret")

    • Environment variable URI: "env://VAR_NAME"
      → EnvCredentialProviderConfig(var_name="VAR_NAME")

    • Secret store URI: "secret://secret-name"
      → SecretStoreCredentialProviderConfig(secret_name="secret-name")

    • Full provider config dict: {"type": "CustomProvider", ...}
      → Raw dict (validated later by factory)

    • Provider config instance: Already a CredentialProviderConfig
      → Pass through unchanged

    Usage:
    ------
    ```python
    from naylence.fame.security.credential.secret_source import SecretSource
    from pydantic import BaseModel, Field

    class MyConfig(BaseModel):
        api_key: SecretSource = Field(description="API key from various sources")
        db_password: SecretSource = Field(description="Database password")

    # All these work:
    config = MyConfig(
        api_key="env://API_KEY",           # Environment variable
        db_password="secret://db-pwd"      # Secret store
    )

    config = MyConfig(
        api_key="my-literal-key",          # Plain string
        db_password={                      # Full config
            "type": "VaultCredentialProvider",
            "vault_url": "https://vault.example.com"
        }
    )
    ```
    """

    @classmethod
    def __get_pydantic_core_schema__(cls, _source, _handler):
        def validate(value: Any, _info=None) -> CredentialProviderConfig:
            # Already a provider config object - pass through
            if isinstance(value, CredentialProviderConfig):
                return value

            # Dict form - validate through the proper config class
            if isinstance(value, dict) and "type" in value:
                from naylence.fame.security.credential.credential_provider_factory import (
                    EnvCredentialProviderConfig,
                    SecretStoreCredentialProviderConfig,
                    StaticCredentialProviderConfig,
                )

                type_name = value.get("type")
                if type_name == "EnvCredentialProvider":
                    return EnvCredentialProviderConfig.model_validate(value)
                elif type_name == "SecretStoreCredentialProvider":
                    return SecretStoreCredentialProviderConfig.model_validate(value)
                elif type_name == "StaticCredentialProvider":
                    return StaticCredentialProviderConfig.model_validate(value)
                else:
                    # Unknown type - return as-is for factory validation during resource creation
                    return value  # type: ignore[return-value]

            # String-based shortcuts
            if isinstance(value, str):
                # Import locally to avoid circular imports
                from naylence.fame.security.credential.credential_provider_factory import (
                    EnvCredentialProviderConfig,
                    SecretStoreCredentialProviderConfig,
                    StaticCredentialProviderConfig,
                )

                if value.startswith("env://"):
                    var_name = value[6:]
                    if not var_name:
                        raise ValueError("Environment variable name cannot be empty in 'env://' URI")
                    return EnvCredentialProviderConfig(var_name=var_name)

                if value.startswith("secret://"):
                    secret_name = value[9:]
                    if not secret_name:
                        raise ValueError("Secret name cannot be empty in 'secret://' URI")
                    return SecretStoreCredentialProviderConfig(secret_name=secret_name)

                # Plain string -> static provider with default credential name
                return StaticCredentialProviderConfig(credential_value=value)

            raise TypeError(
                f"Unsupported secret source type: {type(value)}. "
                f"Expected string, dict with 'type' field, or CredentialProviderConfig instance."
            )

        return core_schema.with_info_plain_validator_function(validate)


# Type alias for documentation and IDE support
SecretSourceType = Union[
    str,  # Plain secret or URI (env://, secret://)
    dict,  # Provider config dict
    CredentialProviderConfig,  # Provider config instance
]
