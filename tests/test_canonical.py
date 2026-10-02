"""Canonicalization: the exact bytes that get signed (docs/CANONICALIZATION.md)."""
import pytest

from app.core.canonical import b64url, b64url_decode, canonical_bytes, digest, normalize_text
from app.core.payload import CertificateInput, PayloadError, build_payload, new_cert_id, validate_payload

GOLDEN_PAYLOAD = {
    "schema_version": 1, "cert_id": "QC-7K2M9Q4XHT3B", "recipient_id": "2023BCS0041",
    "recipient_name": "Asha Ménon", "program": "B.Tech Computer Science and Engineering",
    "institution": "Example Institute of Technology", "grade": "8.20", "issue_date": "2026-06-30",
    "expiry_date": None, "issuer_key_id": "3f9a1c0be47d2a56", "alg": "SLH-DSA-SHA2-128s",
}
GOLDEN_BYTES = ('{"alg":"SLH-DSA-SHA2-128s","cert_id":"QC-7K2M9Q4XHT3B","expiry_date":null,"grade":"8.20",'
                '"institution":"Example Institute of Technology","issue_date":"2026-06-30",'
                '"issuer_key_id":"3f9a1c0be47d2a56","program":"B.Tech Computer Science and Engineering",'
                '"recipient_id":"2023BCS0041","recipient_name":"Asha Ménon","schema_version":1}').encode("utf-8")
# independently computed with: printf '%s' '<GOLDEN_BYTES>' | sha256sum
GOLDEN_SHA256 = "3fb51ec1d2334507571c3419ae41693e92a1e779f67617f1cd3876be55454b53"


def inp(**over):
    base = dict(recipient_id="2023BCS0041", recipient_name="Asha Ménon",
                program="B.Tech Computer Science and Engineering", institution="Example Institute of Technology",
                issue_date="2026-06-30", grade="8.20", expiry_date=None)
    base.update(over)
    return CertificateInput(**base)


def test_golden_bytes_and_digest():
    assert canonical_bytes(validate_payload(dict(GOLDEN_PAYLOAD))) == GOLDEN_BYTES
    assert digest(GOLDEN_BYTES).hex() == GOLDEN_SHA256


def test_key_order_does_not_matter():
    shuffled = dict(reversed(list(GOLDEN_PAYLOAD.items())))
    assert canonical_bytes(shuffled) == GOLDEN_BYTES


def test_rfc8785_basics():
    # sorted keys, no whitespace, literal UTF-8 (not \u escapes), minimal escaping
    assert canonical_bytes({"b": 1, "a": "é\n\"", "c": None}) == '{"a":"é\\n\\"","b":1,"c":null}'.encode()


def test_nfc_trim_and_whitespace_collapse_at_issuance():
    decomposed = "Asha Ménon"  # e + combining acute
    assert decomposed != "Asha Ménon"
    p1 = build_payload(inp(recipient_name=f"  {decomposed}\t "), "QC-7K2M9Q4XHT3B", "3f9a1c0be47d2a56")
    p2 = build_payload(inp(recipient_name="Asha   Ménon"), "QC-7K2M9Q4XHT3B", "3f9a1c0be47d2a56")
    assert p1["recipient_name"] == p2["recipient_name"] == "Asha Ménon"
    assert canonical_bytes(p1) == canonical_bytes(p2) == GOLDEN_BYTES
    assert normalize_text(" a \n b ") == "a b"


def test_grade_formatting():
    for raw, want in [("8.2", "8.20"), ("8", "8.00"), (" 9.456 ", "9.46"), ("", None), (None, None)]:
        assert build_payload(inp(grade=raw), new_cert_id(), "3f9a1c0be47d2a56")["grade"] == want
    for bad in ("A+", "100", "-1", "NaN"):
        with pytest.raises(PayloadError):
            build_payload(inp(grade=bad), new_cert_id(), "3f9a1c0be47d2a56")


@pytest.mark.parametrize("mutate, why", [
    (lambda p: p.update(grade=8.2), "float instead of string"),
    (lambda p: p.update(schema_version="1"), "schema_version as string"),
    (lambda p: p.update(schema_version=True), "bool is not int"),
    (lambda p: p.update(extra="x"), "unexpected field"),
    (lambda p: p.pop("grade"), "missing field (grade must be present, possibly null)"),
    (lambda p: p.update(issue_date="30-06-2026"), "wrong date format"),
    (lambda p: p.update(issue_date="2026-02-30"), "impossible date"),
    (lambda p: p.update(expiry_date="2025-01-01"), "expiry before issue"),
    (lambda p: p.update(recipient_name="Asha Ménon"), "not NFC at verify time"),
    (lambda p: p.update(recipient_name=" Asha Ménon"), "untrimmed at verify time"),
    (lambda p: p.update(recipient_name="Asha‮Ménon"), "bidi override"),
    (lambda p: p.update(grade="८.२०"), "non-ASCII digits"),
    (lambda p: p.update(cert_id="QC-0000000000IL"), "cert_id outside Crockford alphabet"),
    (lambda p: p.update(alg="SLH-DSA-SHA2-128f"), "other algorithm"),
    (lambda p: p.update(issuer_key_id="3F9A1C0BE47D2A56"), "uppercase key id"),
])
def test_validate_rejects_non_canonical(mutate, why):
    p = dict(GOLDEN_PAYLOAD)
    mutate(p)
    with pytest.raises(PayloadError):
        validate_payload(p)


def test_control_chars_rejected_at_issuance():
    with pytest.raises(PayloadError):
        build_payload(inp(recipient_name="Asha\x00Ménon"), new_cert_id(), "3f9a1c0be47d2a56")


def test_unicode_names_supported():
    p = build_payload(inp(recipient_name="അനന്യ കൃഷ്ണൻ"), new_cert_id(), "3f9a1c0be47d2a56")  # Malayalam (ZWJ-free)
    validate_payload(p)


def test_cert_ids_are_random_and_valid():
    ids = {new_cert_id() for _ in range(200)}
    assert len(ids) == 200
    for i in ids:
        validate_payload(dict(GOLDEN_PAYLOAD, cert_id=i))


def test_b64url_roundtrip():
    d = digest(b"x")
    assert len(b64url(d)) == 43 and "=" not in b64url(d)
    assert b64url_decode(b64url(d)) == d
