"""Every attack in the brief (§5) is detected — online (with issuer DB) and offline (public key only)."""
import pytest

from app.core import verifier
from app.core.canonical import b64url
from app.core.results import FAIL, NA, PASS
from app.services import issuance, verification
from demo.tamper import SCENARIOS, Genuine
from tests.conftest import issue

LIMITS = dict(max_bytes=5 * 1024 * 1024, max_pages=1)


@pytest.fixture(scope="module")
def certs(app):
    """One genuine, one revoked and one expired certificate in the issuer DB."""
    _, genuine = issue(app)
    rev_cert, revoked = issue(app, recipient_name="Ravi Kumar")
    with app.state.sessionmaker() as db:
        c = db.get(type(rev_cert), rev_cert.id)
        issuance.revoke_certificate(db, c, "issued in error", None)
    _, expired = issue(app, recipient_name="Meera Nair", issue_date="2023-06-30", expiry_date="2025-06-30")
    return {None: genuine, "revoked": revoked, "expired": expired}


@pytest.mark.parametrize("sc", SCENARIOS, ids=lambda s: f"{s.num}-{s.slug}")
def test_scenario_online(sc, certs, db, keystore):
    g: Genuine = certs[sc.needs]
    res = verification.verify_uploaded_pdf(db, keystore, sc.make(g), **LIMITS)
    failed = set(res.failed_checks())
    assert res.verdict == sc.verdict, [(c.key, c.status, c.reason) for c in res.checks]
    assert sc.must_fail <= failed, f"expected {sc.must_fail} to fail, failed: {failed}"
    if sc.verdict in ("VALID", "REVOKED", "EXPIRED"):
        # status problems never hide the cryptographic fact that the signature is valid
        assert res.signature_valid is True
        assert res.check("signature").status == PASS
        assert failed == sc.must_fail
    if sc.verdict == "INVALID" and "format" not in sc.must_fail:
        assert res.payload is None or res.signature_valid  # never display unsigned data as signed


@pytest.mark.parametrize("sc", [s for s in SCENARIOS if s.needs != "revoked"], ids=lambda s: f"{s.num}-{s.slug}")
def test_scenario_offline(sc, certs, keystore):
    """Offline CLI path: no DB, trust rests only on the public key."""
    res = verifier.verify_pdf(sc.make(certs[sc.needs]), keystore, lookup=None)
    assert res.verdict == sc.verdict
    assert res.check("record").status == NA and res.check("status").status == NA


def test_revoked_offline_cannot_know(certs, keystore):
    res = verifier.verify_pdf(certs["revoked"].pdf, keystore, lookup=None)
    assert res.verdict == "VALID" and res.check("status").status == NA
    assert "offline" in res.check("status").reason


def test_attacker_key_rejected_even_though_signature_is_mathematically_valid(certs, keystore):
    """Scenario 5 in detail: the forged certificate verifies under the attacker's own key, but that
    key is not trusted — and a public key embedded by the attacker is never consulted."""
    import io, json
    from pypdf import PdfReader
    from app.core.canonical import canonical_bytes
    from app.core.pdfread import read_attachment
    from demo.tamper import attacker_own_key
    pdf = attacker_own_key(certs[None])
    doc = json.loads(read_attachment(PdfReader(io.BytesIO(pdf))))
    res = verifier.verify_pdf(pdf, keystore, lookup=None)
    assert res.verdict == "INVALID"
    assert "not in the trusted keystore" in res.check("signature").reason
    assert doc["key_id"] not in keystore.keys


# ---------------------------------------------------------------- QR / ID path (§4.2)

def test_id_lookup_genuine(certs, db, keystore):
    g = certs[None]
    res = verification.verify_by_id(db, keystore, g.payload["cert_id"], None, method="ID")
    assert res.verdict == "VALID" and res.payload == g.payload
    assert res.check("qr_digest").status == NA


def test_qr_link_genuine(certs, db, keystore):
    from app.core.canonical import canonical_bytes, digest
    g = certs[None]
    d = b64url(digest(canonical_bytes(g.payload)))
    res = verification.verify_by_id(db, keystore, g.payload["cert_id"], d, method="QR")
    assert res.verdict == "VALID" and res.check("qr_digest").status == PASS


def test_07d_random_id_is_unknown(db, keystore):
    from app.core.payload import new_cert_id
    res = verification.verify_by_id(db, keystore, new_cert_id(), None, method="ID")
    assert res.verdict == "UNKNOWN" and res.payload is None


def test_garbage_id_is_unknown(db, keystore):
    res = verification.verify_by_id(db, keystore, "../../etc/passwd", None, method="ID")
    assert res.verdict == "UNKNOWN"


def test_qr_digest_mismatch_is_invalid(certs, db, keystore):
    g = certs[None]
    res = verification.verify_by_id(db, keystore, g.payload["cert_id"], b64url(b"\x00" * 32), method="QR")
    assert res.verdict == "INVALID" and res.check("qr_digest").status == FAIL
    assert "QR/record mismatch" in res.check("qr_digest").reason


def test_revoked_and_expired_by_id(certs, db, keystore):
    r = verification.verify_by_id(db, keystore, certs["revoked"].payload["cert_id"], None, method="ID")
    assert r.verdict == "REVOKED" and r.signature_valid and r.revocation["reason"] == "issued in error"
    e = verification.verify_by_id(db, keystore, certs["expired"].payload["cert_id"], None, method="ID")
    assert e.verdict == "EXPIRED" and e.signature_valid


def test_expiry_uses_injected_clock(certs, db, keystore):
    from datetime import date
    g = certs["expired"]
    assert verification.verify_by_id(db, keystore, g.payload["cert_id"], None, method="ID",
                                     today=date(2025, 6, 30)).verdict == "VALID"  # last valid day
    assert verification.verify_by_id(db, keystore, g.payload["cert_id"], None, method="ID",
                                     today=date(2025, 7, 1)).verdict == "EXPIRED"


def test_database_tampering_detected(app, keystore):
    """Step 7: someone edits the stored record directly in SQLite (e.g. raises the CGPA)."""
    cert, g = issue(app, recipient_name="Db Tamper")
    with app.state.sessionmaker() as db:
        c = db.get(type(cert), cert.id)
        c.payload_canonical = c.payload_canonical.replace(b'"grade":"8.20"', b'"grade":"9.90"')
        db.commit()
        by_id = verification.verify_by_id(db, keystore, cert.cert_id, None, method="ID")
        assert by_id.verdict == "INVALID" and by_id.check("signature").status == FAIL
        by_pdf = verification.verify_uploaded_pdf(db, keystore, g.pdf, **LIMITS)
        assert by_pdf.verdict == "INVALID" and by_pdf.check("record").status == FAIL
