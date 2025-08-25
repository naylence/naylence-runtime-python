from __future__ import annotations

from typing import Any, Callable, Dict, NamedTuple, Optional


# Lazy import cryptography and jwt only when needed
def _get_crypto_modules():
    """Get cryptography and jwt modules, importing them lazily."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm

        return {
            "serialization": serialization,
            "ec": ec,
            "ed448": ed448,
            "ed25519": ed25519,
            "rsa": rsa,
            "load_pem_public_key": load_pem_public_key,
            "ECAlgorithm": ECAlgorithm,
            "OKPAlgorithm": OKPAlgorithm,
            "RSAAlgorithm": RSAAlgorithm,
        }
    except ImportError:
        raise ImportError(
            "This functionality requires cryptography and pyjwt packages. "
            "Install with: pip install 'naylence-fame-runtime[crypto]'"
        )


def generate_key_pair_and_jwks(
    *,
    key_gen_fn: Callable[[], Any],
    algorithm: str,
    kid: str,
) -> dict[str, Any]:
    """
    :param key_gen_fn: zero-arg that returns a private_key object
    :param algorithm: e.g. "RS256", "ES256", "EdDSA"
    :param kid: key identifier
    :returns: dict with private_pem, public_pem, and jwks={"keys":[...]}
    """
    # Get crypto modules lazily
    crypto = _get_crypto_modules()
    serialization = crypto["serialization"]
    RSAAlgorithm = crypto["RSAAlgorithm"]
    ECAlgorithm = crypto["ECAlgorithm"]
    OKPAlgorithm = crypto["OKPAlgorithm"]

    # 1) generate private key
    priv = key_gen_fn()

    # 2) serialize private PEM
    private_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    # 3) get public key object and PEM
    pub = priv.public_key()
    public_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # 4) pick correct algorithm class to call .to_jwk(...)
    alg = algorithm.upper()
    if alg.startswith("RS"):
        jwk_dict = RSAAlgorithm.to_jwk(pub, as_dict=True)
    elif alg.startswith("ES"):
        jwk_dict = ECAlgorithm.to_jwk(pub, as_dict=True)
    elif alg.startswith("ED"):
        jwk_dict = OKPAlgorithm.to_jwk(pub, as_dict=True)
    else:
        raise ValueError(f"Unsupported algorithm {algorithm!r}")

    # 5) enrich and return
    jwk_dict.update(
        {
            "kid": kid,
            "alg": algorithm,
            "use": "sig",
        }
    )
    return {
        "private_pem": private_pem,
        "public_pem": public_pem,
        "jwks": {"keys": [jwk_dict]},
    }


class DevKeyPair(NamedTuple):
    private_pem: str
    public_pem: str
    jwks: Dict[str, Any]


def detect_alg(pem: str) -> str:
    """
    Inspect a public-key PEM and return the matching JWT alg:
      - RSA keys    -> RS256
      - EC P-256    -> ES256
      - EC P-384    -> ES384
      - EC P-521    -> ES512
      - Ed25519     -> EdDSA
      - Ed448       -> EdDSA
    """
    # Get crypto modules lazily
    crypto = _get_crypto_modules()
    load_pem_public_key = crypto["load_pem_public_key"]
    rsa = crypto["rsa"]
    ec = crypto["ec"]
    ed25519 = crypto["ed25519"]
    ed448 = crypto["ed448"]

    key = load_pem_public_key(pem.encode())
    # RSA
    if isinstance(key, rsa.RSAPublicKey):
        return "RS256"
    # ECDSA
    if isinstance(key, ec.EllipticCurvePublicKey):
        curve = key.curve
        if isinstance(curve, ec.SECP256R1):
            return "ES256"
        if isinstance(curve, ec.SECP384R1):
            return "ES384"
        if isinstance(curve, ec.SECP521R1):
            return "ES512"
        raise ValueError(f"Unsupported EC curve: {curve.name}")
    # EdDSA
    if isinstance(key, ed25519.Ed25519PublicKey) or isinstance(key, ed448.Ed448PublicKey):
        return "EdDSA"
    raise ValueError("Could not detect algorithm from PEM")


def jwk_from_pem(
    pem: str,
    *,
    algorithm: Optional[str] = None,
    kid: str,
) -> Dict[str, Any]:
    """
    Convert a public-key PEM into a JWK dict, inferring or using the provided alg and tagging with kid.
    """
    # Get crypto modules lazily
    crypto = _get_crypto_modules()
    load_pem_public_key = crypto["load_pem_public_key"]
    RSAAlgorithm = crypto["RSAAlgorithm"]
    ECAlgorithm = crypto["ECAlgorithm"]
    OKPAlgorithm = crypto["OKPAlgorithm"]

    key_obj = load_pem_public_key(pem.encode())

    # determine algorithm
    alg = algorithm or detect_alg(pem)
    alg_upper = alg.upper()

    # build the JWK via PyJWT algorithm classes
    if alg_upper.startswith("RS"):
        jwk = RSAAlgorithm.to_jwk(key_obj, as_dict=True)  # type: ignore
    elif alg_upper.startswith("ES"):
        jwk = ECAlgorithm.to_jwk(key_obj, as_dict=True)  # type: ignore
    elif alg_upper.startswith("ED"):
        jwk = OKPAlgorithm.to_jwk(key_obj, as_dict=True)  # type: ignore
    else:
        raise ValueError(f"Unsupported JWK alg: {alg}")

    # enrich
    jwk.update(
        {
            "kid": kid,
            "alg": alg,
            "use": "sig",
        }
    )
    return jwk
