#!/usr/bin/env python3
"""
JWK validation utilities for the Fame system.

This module provides validation functions for JWK (JSON Web Key) structures
to ensure they have proper "use" fields and are structurally valid.
"""

from typing import Any, Dict, List

# Valid key uses
VALID_KEY_USES = {"sig", "enc"}

# Required fields for different key types
REQUIRED_FIELDS_BY_KTY = {
    "RSA": {"kty", "n", "e"},
    "EC": {"kty", "crv", "x", "y"},
    "OKP": {"kty", "crv", "x"},
}

# Valid curves for different key types
VALID_CURVES_BY_KTY = {
    "EC": {"P-256", "P-384", "P-521"},
    "OKP": {"Ed25519", "Ed448", "X25519", "X448"},
}


class JWKValidationError(ValueError):
    """Raised when JWK validation fails."""

    pass


def validate_jwk_use_field(jwk: Dict[str, Any]) -> str:
    """
    Validate that a JWK has a valid "use" field.

    Args:
        jwk: The JWK dictionary to validate

    Returns:
        The validated "use" value

    Raises:
        JWKValidationError: If the "use" field is missing or invalid
    """
    use = jwk.get("use")
    if not use:
        raise JWKValidationError(f"JWK missing required 'use' field: {jwk.get('kid', 'unknown')}")

    if not isinstance(use, str):
        raise JWKValidationError(f"JWK 'use' field must be a string: {jwk.get('kid', 'unknown')}")

    if use not in VALID_KEY_USES:
        raise JWKValidationError(
            f"JWK has invalid 'use' field '{use}'. Valid values: {', '.join(VALID_KEY_USES)}"
        )

    return use


def validate_jwk_structure(jwk: Dict[str, Any]) -> None:
    """
    Validate the overall structure of a JWK.

    Args:
        jwk: The JWK dictionary to validate

    Raises:
        JWKValidationError: If the JWK structure is invalid
    """
    # Check required basic fields
    if not isinstance(jwk, dict):
        raise JWKValidationError("JWK must be a dictionary")

    # Check for kid (key ID)
    kid = jwk.get("kid")
    if not kid or not isinstance(kid, str):
        raise JWKValidationError("JWK missing required 'kid' field or kid is not a string")

    # Check for kty (key type)
    kty = jwk.get("kty")
    if not kty or not isinstance(kty, str):
        raise JWKValidationError(f"JWK {kid} missing required 'kty' field or kty is not a string")

    # Check if we support this key type
    if kty not in REQUIRED_FIELDS_BY_KTY:
        raise JWKValidationError(f"JWK {kid} has unsupported key type '{kty}'")

    # Check required fields for this key type
    required_fields = REQUIRED_FIELDS_BY_KTY[kty]
    missing_fields = required_fields - set(jwk.keys())
    if missing_fields:
        raise JWKValidationError(
            f"JWK {kid} missing required fields for {kty}: {', '.join(missing_fields)}"
        )

    # Validate curve for EC and OKP keys
    if kty in {"EC", "OKP"}:
        crv = jwk.get("crv")
        if not crv or not isinstance(crv, str):
            raise JWKValidationError(f"JWK {kid} missing required 'crv' field or crv is not a string")

        valid_curves = VALID_CURVES_BY_KTY[kty]
        if crv not in valid_curves:
            raise JWKValidationError(
                f"JWK {kid} has invalid curve '{crv}' for {kty}. Valid curves: {', '.join(valid_curves)}"
            )


def validate_jwk_complete(jwk: Dict[str, Any]) -> str:
    """
    Perform complete validation of a JWK including structure and use field.

    This validates that:
    1. The JWK has proper structure for its key type
    2. The JWK has a valid "use" field
    3. The "use" field matches the key type (e.g., X25519 should be "enc", Ed25519 should be "sig")

    Args:
        jwk: The JWK dictionary to validate

    Returns:
        The validated "use" value

    Raises:
        JWKValidationError: If validation fails
    """
    # First validate structure
    validate_jwk_structure(jwk)

    # Then validate use field
    use = validate_jwk_use_field(jwk)

    # Finally validate that the use field matches the key type
    kty = jwk.get("kty")
    crv = jwk.get("crv")
    kid = jwk.get("kid", "unknown")

    if kty == "OKP":
        if crv == "X25519":
            if use != "enc":
                raise JWKValidationError(
                    f"JWK {kid} is X25519 key but marked for use='{use}'. X25519 keys should have use='enc'"
                )
        elif crv in {"Ed25519", "Ed448"}:
            if use != "sig":
                raise JWKValidationError(
                    f"JWK {kid} is {crv} key but marked for use='{use}'. {crv} keys should have use='sig'"
                )
    elif kty == "RSA" or (kty == "EC" and crv in {"P-256", "P-384", "P-521"}):
        if use != "sig":
            raise JWKValidationError(
                f"JWK {kid} is {kty} key but marked for use='{use}'. {kty} keys should have use='sig'"
            )

    return use


def filter_keys_by_use(keys: List[Dict[str, Any]], use: str) -> List[Dict[str, Any]]:
    """
    Filter a list of JWKs to only include those with the specified use.

    Args:
        keys: List of JWK dictionaries
        use: The desired use value ("sig" or "enc")

    Returns:
        List of JWKs that have the specified use and are valid for that use
    """
    if use not in VALID_KEY_USES:
        raise ValueError(f"Invalid use value '{use}'. Valid values: {', '.join(VALID_KEY_USES)}")

    filtered_keys = []
    for jwk in keys:
        try:
            # First validate basic structure and use field
            jwk_use = validate_jwk_complete(jwk)
            if jwk_use == use:
                # For encryption keys, do additional validation
                if use == "enc":
                    validate_encryption_key(jwk)
                # For signing keys, do additional validation
                elif use == "sig":
                    validate_signing_key(jwk)
                filtered_keys.append(jwk)
        except JWKValidationError:
            # Skip invalid keys
            continue

    return filtered_keys


def validate_encryption_key(jwk: Dict[str, Any]) -> None:
    """
    Validate that a JWK is suitable for encryption.

    Args:
        jwk: The JWK dictionary to validate

    Raises:
        JWKValidationError: If the key is not suitable for encryption
    """
    use = validate_jwk_complete(jwk)
    if use != "enc":
        raise JWKValidationError(f"JWK {jwk.get('kid', 'unknown')} is not an encryption key (use={use})")

    # Additional validation for encryption keys
    kty = jwk.get("kty")
    crv = jwk.get("crv")

    # For encryption, we currently support X25519
    if kty == "OKP" and crv == "X25519":
        return  # Valid encryption key

    # Could add support for other encryption key types here in the future
    raise JWKValidationError(
        f"JWK {jwk.get('kid', 'unknown')} is not a supported encryption key type "
        f"(kty={kty}, crv={crv}). Currently only X25519 keys are supported."
    )


def validate_signing_key(jwk: Dict[str, Any]) -> None:
    """
    Validate that a JWK is suitable for signing.

    Args:
        jwk: The JWK dictionary to validate

    Raises:
        JWKValidationError: If the key is not suitable for signing
    """
    use = validate_jwk_complete(jwk)
    if use != "sig":
        raise JWKValidationError(f"JWK {jwk.get('kid', 'unknown')} is not a signing key (use={use})")

    # Additional validation for signing keys
    kty = jwk.get("kty")
    crv = jwk.get("crv")

    # For signing, we support Ed25519, RSA, and ECDSA
    if kty == "OKP" and crv in {"Ed25519", "Ed448"}:
        return  # Valid EdDSA signing key
    elif kty == "RSA":
        return  # Valid RSA signing key
    elif kty == "EC" and crv in {"P-256", "P-384", "P-521"}:
        return  # Valid ECDSA signing key

    raise JWKValidationError(
        f"JWK {jwk.get('kid', 'unknown')} is not a supported signing key type "
        f"(kty={kty}, crv={crv}). Supported types: Ed25519/Ed448, RSA, ECDSA P-256/P-384/P-521."
    )
