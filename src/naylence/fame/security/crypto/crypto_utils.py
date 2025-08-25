"""
crypto_utils.py: Sealed envelope encryption helpers for Naylence overlay security.

Implements X25519 ephemeral-static ECDH and AEAD (ChaCha20-Poly1305) encryption for sealed envelopes.
"""

import os

from naylence.fame.security.util import require_crypto


def sealed_encrypt(plaintext: bytes, recip_pub_bytes: bytes) -> bytes:
    """
    Encrypts plaintext using sender-ephemeral x recipient-static X25519 (ECIES) and ChaCha20-Poly1305.
    Returns: eph_pub(32) || nonce(12) || ciphertext || tag(16)
    """
    require_crypto()
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    # Generate ephemeral keypair
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    recip_pub = X25519PublicKey.from_public_bytes(recip_pub_bytes)
    # ECDH
    shared = eph_priv.exchange(recip_pub)
    # Derive symmetric key
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"naylence-sealed-envelope",
    ).derive(shared)
    # Encrypt
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    ct = aead.encrypt(nonce, plaintext, None)
    # Output: eph_pub || nonce || ct
    return eph_pub + nonce + ct


def sealed_decrypt(blob: bytes, recip_priv) -> bytes:
    """
    Decrypts a sealed envelope blob using recipient's static private key.
    Expects: eph_pub(32) || nonce(12) || ciphertext || tag(16)
    """
    require_crypto()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    eph_pub = X25519PublicKey.from_public_bytes(blob[:32])
    nonce = blob[32:44]
    ct = blob[44:]
    shared = recip_priv.exchange(eph_pub)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"naylence-sealed-envelope",
    ).derive(shared)
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ct, None)
