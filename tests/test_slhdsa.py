"""The SLH-DSA wrapper is FIPS 205 pure-mode SLH-DSA-SHA2-128s with ctx 'QuantumCert-v1'."""
import json
from pathlib import Path

import pytest

from app.crypto import slhdsa

VECTORS = json.loads((Path(__file__).parent / "vectors" / "slhdsa_sha2_128s_sigver_pure.json").read_text())


def test_parameter_set_and_sizes():
    pk, sk = slhdsa.keygen()
    assert slhdsa.ALG == "SLH-DSA-SHA2-128s"
    assert (len(pk), len(sk)) == (32, 64)
    assert len(slhdsa.sign(sk, b"m")) == 7856


@pytest.mark.parametrize("tc", VECTORS["group"]["tests"], ids=lambda t: f"tc{t['tcId']}")
def test_nist_acvp_sigver_vectors(tc):
    """NIST ACVP SLH-DSA-sigVer-FIPS205, SHA2-128s, external interface, pure (with context strings).
    A pre-standard SPHINCS+ implementation cannot pass the valid cases (different message encoding)."""
    from pqcrypto.sign import slh_dsa_sha2_128s as raw
    try:
        raw.verify(bytes.fromhex(tc["pk"]), bytes.fromhex(tc["message"]), bytes.fromhex(tc["signature"]),
                   bytes.fromhex(tc["context"]))
        ok = True
    except Exception:
        ok = False
    assert ok == tc["testPassed"], tc["reason"]


def test_context_string_is_bound():
    from pqcrypto.sign import slh_dsa_sha2_128s as raw
    pk, sk = slhdsa.keygen()
    sig = slhdsa.sign(sk, b"payload")
    assert slhdsa.verify(pk, b"payload", sig)
    for other_ctx in (b"", b"QuantumCert-v2"):
        with pytest.raises(Exception):
            raw.verify(pk, b"payload", sig, other_ctx)


def test_rejects_modified_message_wrong_key_and_bad_lengths():
    pk, sk = slhdsa.keygen()
    pk2, _ = slhdsa.keygen()
    sig = slhdsa.sign(sk, b"payload")
    assert not slhdsa.verify(pk, b"payloaD", sig)
    assert not slhdsa.verify(pk2, b"payload", sig)
    assert not slhdsa.verify(pk, b"payload", sig[:-1])
    assert not slhdsa.verify(pk[:-1], b"payload", sig)


def test_pure_mode_not_prehash():
    """A HashSLH-DSA (pre-hash) signature must not verify in our pure-mode wrapper."""
    from pqcrypto import HashAlgorithm
    from pqcrypto.sign import slh_dsa_sha2_128s as raw
    pk, sk = slhdsa.keygen()
    prehash_sig = raw.sign(sk, b"payload", slhdsa.CTX, hash_algorithm=HashAlgorithm.Sha256)
    assert not slhdsa.verify(pk, b"payload", prehash_sig)
