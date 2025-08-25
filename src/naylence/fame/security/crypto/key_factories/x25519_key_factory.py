from __future__ import annotations

from naylence.fame.security.util import require_crypto
from naylence.fame.util.crypto_util import DevKeyPair


def create_x25519_keypair(kid: str = "dev-x25519") -> DevKeyPair:
    require_crypto()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519

    # Generate X25519 private key
    priv = x25519.X25519PrivateKey.generate()

    # Serialize private PEM
    private_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    # Get public key and serialize to PEM
    pub = priv.public_key()
    public_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # X25519 keys don't need JWK format since they're for encryption, not JWT signing
    # Return with empty jwks
    return DevKeyPair(private_pem=private_pem, public_pem=public_pem, jwks={"keys": []})
