"""The ONLY module that touches the SLH-DSA library.

FIPS 205 SLH-DSA-SHA2-128s in *pure* mode (not HashSLH-DSA) with a fixed context string.
Internally the library signs M' = 0x00 || len(ctx) || ctx || M  (FIPS 205, Algorithm 22).
Swapping to liboqs-python or another backend only requires changing this file.
"""
from pqcrypto.sign import slh_dsa_sha2_128s as _slh

ALG = "SLH-DSA-SHA2-128s"
CTX = b"QuantumCert-v1"

PUBLIC_KEY_SIZE = _slh.PUBLIC_KEY_SIZE  # 32
SECRET_KEY_SIZE = _slh.SECRET_KEY_SIZE  # 64
SIGNATURE_SIZE = _slh.SIGNATURE_SIZE    # 7856


def keygen() -> tuple[bytes, bytes]:
    """Return (public_key, secret_key)."""
    pk, sk = _slh.keygen()
    return bytes(pk), bytes(sk)


def sign(secret_key: bytes, message: bytes) -> bytes:
    return bytes(_slh.sign(secret_key, message, CTX))


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` is a valid pure-mode signature over `message` with ctx CTX."""
    if len(public_key) != PUBLIC_KEY_SIZE or len(signature) != SIGNATURE_SIZE:
        return False
    try:
        _slh.verify(public_key, message, signature, CTX)
        return True
    except Exception:
        return False
