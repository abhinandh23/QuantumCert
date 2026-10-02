import json

import pytest

from app.core import pdfgen, pdfread, qr
from app.core.canonical import canonical_bytes, digest
from app.core.payload import CertificateInput, build_payload, new_cert_id
from app.crypto import slhdsa

BASE = "http://localhost:8000"


def make(**over):
    base = dict(recipient_id="2023BCS0041", recipient_name="Asha Ménon",
                program="B.Tech Computer Science and Engineering", institution="Example Institute of Technology",
                issue_date="2026-06-30", grade="8.20", expiry_date=None)
    base.update(over)
    p = build_payload(CertificateInput(**base), new_cert_id(), "3f9a1c0be47d2a56")
    return p, pdfgen.render_certificate(p, b"\x01" * slhdsa.SIGNATURE_SIZE, BASE)


@pytest.mark.parametrize("over", [
    {},
    {"recipient_name": "Ñuñez O'Brien-Østergaard", "grade": None, "expiry_date": "2030-12-31"},
    {"recipient_name": "X" * 150, "program": "Doctor of Philosophy in " + "Very Long Programme Name " * 5},
    {"recipient_name": "Zoë Ľudmila Šťastná", "institution": "Université de Montréal"},
])
def test_visible_text_roundtrip(over):
    p, pdf = make(**over)
    assert pdfread.extract_visible(pdf) == pdfgen.visible_values(p)


def test_attachment_and_structure():
    p, pdf = make()
    reader = pdfread.open_pdf(pdf, 5 << 20, 2)
    doc = json.loads(pdfread.read_attachment(reader))
    assert doc["payload"] == p and doc["key_id"] == p["issuer_key_id"] and doc["ctx"] == "QuantumCert-v1"
    assert pdfread.page_structure(pdf) == {"images": 1, "annotations": 0, "filled_shapes": 0}


def test_qr_decodes_to_verify_url_with_digest():
    p, pdf = make()
    texts = qr.decode_qr_from_pdf(pdf, pdfgen.QR_BOX)
    link = qr.parse_verify_url(texts[0])
    assert link.cert_id == p["cert_id"]
    assert link.digest == digest(canonical_bytes(p))
    assert link.host == "localhost:8000"


def test_qr_never_contains_signature():
    p, pdf = make()
    assert len(qr.decode_qr_from_pdf(pdf, pdfgen.QR_BOX)[0]) < 120


@pytest.mark.parametrize("bad", ["ftp://x/verify/QC-7K2M9Q4XHT3B", "http://x/other/QC-7K2M9Q4XHT3B",
                                 "http://x/verify/QC-7K2M9Q4XHT3B?d=abc", "http://x/verify/not-an-id"])
def test_parse_verify_url_rejects(bad):
    with pytest.raises(ValueError):
        qr.parse_verify_url(bad)
