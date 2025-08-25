from __future__ import annotations

from naylence.fame.security.util import require_crypto
from naylence.fame.util.crypto_util import DevKeyPair, generate_key_pair_and_jwks


def create_ed25519_keypair(kid: str = "dev") -> DevKeyPair:
    require_crypto()
    from cryptography.hazmat.primitives.asymmetric import ed25519

    data = generate_key_pair_and_jwks(
        kid=kid,
        key_gen_fn=ed25519.Ed25519PrivateKey.generate,
        algorithm="EdDSA",
    )
    data["jwks"]["keys"][0]["kid"] = kid
    return DevKeyPair(**data)
