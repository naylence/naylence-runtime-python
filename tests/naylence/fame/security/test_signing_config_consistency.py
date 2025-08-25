"""
Test the updated SigningConfig with consistency validation.
"""

import pytest
from pydantic import ValidationError

from naylence.fame.security.policy.security_policy import SigningConfig, SigningMaterial


def test_raw_key_defaults():
    """Test that RAW_KEY with default settings works."""
    config = SigningConfig(signing_material=SigningMaterial.RAW_KEY)

    assert config.signing_material == SigningMaterial.RAW_KEY
    assert config.validate_cert_name_constraints is True
    assert config.require_cert_sid_match is False
    assert config.require_cert_logical_match is False

    print("✓ RAW_KEY with defaults works")


def test_x509_chain_with_settings():
    """Test that X509_CHAIN allows certificate settings."""
    config = SigningConfig(
        signing_material=SigningMaterial.X509_CHAIN,
        validate_cert_name_constraints=True,
        require_cert_sid_match=True,
        require_cert_logical_match=True,
    )

    assert config.signing_material == SigningMaterial.X509_CHAIN
    assert config.validate_cert_name_constraints is True
    assert config.require_cert_sid_match is True
    assert config.require_cert_logical_match is True

    print("✓ X509_CHAIN with certificate settings works")


def test_raw_key_with_cert_validation_modified_fails():
    """Test that RAW_KEY with modified cert validation settings fails validation."""
    with pytest.raises(ValidationError) as exc_info:
        SigningConfig(
            signing_material=SigningMaterial.RAW_KEY,
            validate_cert_name_constraints=False,
        )

    assert "X.509 validation options present but signing_material is RAW_KEY" in str(exc_info.value)
    print("✓ RAW_KEY with modified cert validation correctly fails")


def test_raw_key_with_cert_validation_disabled_fails():
    """Test that RAW_KEY with cert validation disabled fails."""
    with pytest.raises(ValidationError) as exc_info:
        SigningConfig(
            signing_material=SigningMaterial.RAW_KEY,
            validate_cert_name_constraints=False,
        )

    assert "X.509 validation options present but signing_material is RAW_KEY" in str(exc_info.value)
    print("✓ RAW_KEY with disabled cert validation correctly fails")


def test_raw_key_with_sid_match_fails():
    """Test that RAW_KEY with SID matching enabled fails."""
    with pytest.raises(ValidationError) as exc_info:
        SigningConfig(signing_material=SigningMaterial.RAW_KEY, require_cert_sid_match=True)

    assert "X.509 validation options present but signing_material is RAW_KEY" in str(exc_info.value)
    print("✓ RAW_KEY with SID matching correctly fails")


def test_raw_key_with_logical_match_fails():
    """Test that RAW_KEY with logical matching enabled fails."""
    with pytest.raises(ValidationError) as exc_info:
        SigningConfig(signing_material=SigningMaterial.RAW_KEY, require_cert_logical_match=True)

    assert "X.509 validation options present but signing_material is RAW_KEY" in str(exc_info.value)
    print("✓ RAW_KEY with logical matching correctly fails")


def test_x509_chain_defaults():
    """Test that X509_CHAIN with defaults works."""
    config = SigningConfig(signing_material=SigningMaterial.X509_CHAIN)

    assert config.signing_material == SigningMaterial.X509_CHAIN
    assert config.validate_cert_name_constraints is True
    assert config.require_cert_sid_match is False
    assert config.require_cert_logical_match is False

    print("✓ X509_CHAIN with defaults works")


if __name__ == "__main__":
    print("Testing SigningConfig consistency validation")
    print("=" * 50)

    test_raw_key_defaults()
    test_x509_chain_with_settings()
    test_raw_key_with_cert_validation_modified_fails()
    test_raw_key_with_cert_validation_disabled_fails()
    test_raw_key_with_sid_match_fails()
    test_raw_key_with_logical_match_fails()
    test_x509_chain_defaults()

    print("=" * 50)
    print("✅ All consistency validation tests passed!")
    print("\nThe removed ambiguous 'allow_certificate_keys' flag eliminates confusion.")
    print("X.509 validation options are now clearly tied to signing_material setting.")
