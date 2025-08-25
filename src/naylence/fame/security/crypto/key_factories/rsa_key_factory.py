from __future__ import annotations

from naylence.fame.security.util import require_crypto
from naylence.fame.util.crypto_util import DevKeyPair, generate_key_pair_and_jwks


def create_rsa_keypair(kid: str = "dev") -> DevKeyPair:
    require_crypto()
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    data = generate_key_pair_and_jwks(
        kid=kid,
        key_gen_fn=lambda: rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        ),
        algorithm="RS256",
    )

    # attach the kid
    data["jwks"]["keys"][0]["kid"] = kid
    return DevKeyPair(**data)
