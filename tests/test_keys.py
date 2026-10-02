import json

import pytest

from app.crypto import keys, slhdsa


def test_key_id_is_sha256_prefix():
    pk, _ = slhdsa.keygen()
    import hashlib
    assert keys.key_id_for(pk) == hashlib.sha256(pk).hexdigest()[:16]


def test_secret_key_encryption_roundtrip_and_failures():
    pk, sk = slhdsa.keygen()
    kid = keys.key_id_for(pk)
    blob = keys.encrypt_secret_key(sk, "pass phrase", kid)
    assert sk.hex() not in json.dumps(blob)
    assert keys.decrypt_secret_key(blob, "pass phrase") == sk
    with pytest.raises(keys.KeyError_):
        keys.decrypt_secret_key(blob, "wrong")
    tampered = dict(blob, key_id="0" * 16)  # AAD binds the key_id
    with pytest.raises(keys.KeyError_):
        keys.decrypt_secret_key(tampered, "pass phrase")


def test_generate_rotate_and_old_key_still_trusted(tmp_path):
    k1 = keys.generate_issuer_key(tmp_path, "pw-123456")
    priv = keys.private_key_path(tmp_path, k1)
    assert oct(priv.stat().st_mode)[-3:] == "600"
    kid, sk1 = keys.load_signing_key(tmp_path, "pw-123456")
    assert kid == k1
    sig_old = slhdsa.sign(sk1, b"old certificate")

    k2 = keys.generate_issuer_key(tmp_path, "pw-123456")
    ks = keys.Keystore.load(keys.keystore_path(tmp_path))
    assert ks.get(k1).status == "RETIRED" and ks.get(k2).status == "ACTIVE"
    assert keys.load_signing_key(tmp_path, "pw-123456")[0] == k2
    assert slhdsa.verify(ks.get(k1).public_key, b"old certificate", sig_old)
    # the keystore file contains only public material
    assert "ct" not in keys.keystore_path(tmp_path).read_text()


def test_keystore_rejects_entry_whose_key_id_does_not_match(tmp_path):
    keys.generate_issuer_key(tmp_path, "pw-123456")
    p = keys.keystore_path(tmp_path)
    data = json.loads(p.read_text())
    (kid, entry), = data["keys"].items()
    data["keys"]["ffffffffffffffff"] = entry
    del data["keys"][kid]
    p.write_text(json.dumps(data))
    with pytest.raises(keys.KeyError_):
        keys.Keystore.load(p)


def test_public_key_file_roundtrip():
    pk, _ = slhdsa.keygen()
    assert keys.decode_public_key(keys.encode_public_key(pk)) == pk
    assert keys.decode_public_key(pk) == pk
