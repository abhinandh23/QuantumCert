"""Offline verifier CLI: trust rests only on the supplied public key."""
from app.crypto import keys, slhdsa
from cli.verify import main as verify_main
from demo.tamper import edit_visible_regenerate


def test_offline_cli_genuine_and_tampered(tmp_path, genuine, keystore, capsys):
    pub = tmp_path / "issuer.pub"
    pub.write_text(keys.encode_public_key(keystore.active().public_key))
    good, bad = tmp_path / "good.pdf", tmp_path / "bad.pdf"
    good.write_bytes(genuine.pdf)
    bad.write_bytes(edit_visible_regenerate(genuine))

    assert verify_main([str(good), "--pubkey", str(pub)]) == 0
    out = capsys.readouterr().out
    assert "VERDICT: VALID" in out and "revocation status was not checked" in out

    assert verify_main([str(bad), "--pubkey", str(pub)]) == 1
    assert "VERDICT: INVALID" in capsys.readouterr().out


def test_offline_cli_wrong_pubkey_fails(tmp_path, genuine, capsys):
    other_pk, _ = slhdsa.keygen()
    pub = tmp_path / "other.pub"
    pub.write_text(keys.encode_public_key(other_pk))
    pdf = tmp_path / "good.pdf"
    pdf.write_bytes(genuine.pdf)
    assert verify_main([str(pdf), "--pubkey", str(pub)]) == 1
    assert "not in the trusted keystore" in capsys.readouterr().out


def test_offline_cli_with_keystore_file(tmp_path, genuine, settings):
    pdf = tmp_path / "good.pdf"
    pdf.write_bytes(genuine.pdf)
    assert verify_main([str(pdf), "--keystore", str(keys.keystore_path(settings.keys_dir))]) == 0
