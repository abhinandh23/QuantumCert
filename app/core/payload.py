"""The signed certificate payload: schema, issuance-time normalisation and strict validation."""
import re
import secrets
from dataclasses import dataclass
from datetime import date
from decimal import Decimal

from app.core.canonical import has_forbidden_chars, is_normalized, normalize_text
from app.crypto import slhdsa

SCHEMA_VERSION = 1
FIELDS = ("schema_version", "cert_id", "recipient_id", "recipient_name", "program", "institution",
          "grade", "issue_date", "expiry_date", "issuer_key_id", "alg")

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CERT_ID_RE = re.compile(r"QC-[0-9A-HJKMNP-TV-Z]{12}")
RECIPIENT_ID_RE = re.compile(r"[A-Za-z0-9/_-]{1,64}")
GRADE_RE = re.compile(r"[0-9]{1,2}\.[0-9]{2}")  # [0-9], not \d: \d matches non-ASCII digits
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
KEY_ID_RE = re.compile(r"[0-9a-f]{16}")
TEXT_MAX = 150


class PayloadError(ValueError):
    pass


def new_cert_id() -> str:
    """QC- + 12 random Crockford base32 chars (60 bits): not sequential, not enumerable."""
    return "QC-" + "".join(secrets.choice(CROCKFORD) for _ in range(12))


@dataclass
class CertificateInput:
    """What the admin types in. Loose; build_payload() normalises and validates it."""
    recipient_id: str
    recipient_name: str
    program: str
    institution: str
    issue_date: str
    grade: str | None = None
    expiry_date: str | None = None


def _norm_grade(g: str | None) -> str | None:
    if g is None or not g.strip():
        return None
    if not re.fullmatch(r"[0-9]{1,2}(\.[0-9]+)?", g.strip()):
        raise PayloadError("grade must be a number like 8.20")
    value = Decimal(g.strip()).quantize(Decimal("0.01"))
    if value >= 100:
        raise PayloadError("grade must be between 0.00 and 99.99")
    return str(value)


def build_payload(inp: CertificateInput, cert_id: str, issuer_key_id: str) -> dict:
    """Normalise admin input into a canonical payload (raises PayloadError)."""
    def text(name, v):
        if v is None:
            raise PayloadError(f"{name} is required")
        v = normalize_text(v)  # tabs/newlines collapse to spaces; other control chars are then rejected
        if has_forbidden_chars(v):
            raise PayloadError(f"{name} contains control characters")
        return v

    payload = {
        "schema_version": SCHEMA_VERSION,
        "cert_id": cert_id,
        "recipient_id": text("recipient_id", inp.recipient_id),
        "recipient_name": text("recipient_name", inp.recipient_name),
        "program": text("program", inp.program),
        "institution": text("institution", inp.institution),
        "grade": _norm_grade(inp.grade),
        "issue_date": (inp.issue_date or "").strip(),
        "expiry_date": (inp.expiry_date or "").strip() or None,
        "issuer_key_id": issuer_key_id,
        "alg": slhdsa.ALG,
    }
    validate_payload(payload)
    return payload


def _parse_date(name: str, v) -> date:
    if not isinstance(v, str) or not DATE_RE.fullmatch(v):
        raise PayloadError(f"{name} must be a YYYY-MM-DD string")
    try:
        return date.fromisoformat(v)
    except ValueError:
        raise PayloadError(f"{name} is not a real calendar date")


def validate_payload(p) -> dict:
    """Strict check used at issuance AND verification. Never normalises: non-canonical input fails."""
    if not isinstance(p, dict):
        raise PayloadError("payload must be a JSON object")
    keys = set(p)
    if keys != set(FIELDS):
        missing, extra = set(FIELDS) - keys, keys - set(FIELDS)
        raise PayloadError(f"payload fields wrong (missing: {sorted(missing)}, unexpected: {sorted(extra)})")

    if type(p["schema_version"]) is not int or p["schema_version"] != SCHEMA_VERSION:
        raise PayloadError(f"schema_version must be the integer {SCHEMA_VERSION}")
    for name in ("cert_id", "recipient_id", "recipient_name", "program", "institution",
                 "issue_date", "issuer_key_id", "alg"):
        if not isinstance(p[name], str):
            raise PayloadError(f"{name} must be a string")
    for name in ("grade", "expiry_date"):
        if p[name] is not None and not isinstance(p[name], str):
            raise PayloadError(f"{name} must be a string or null")

    if not CERT_ID_RE.fullmatch(p["cert_id"]):
        raise PayloadError("cert_id has the wrong format")
    if not RECIPIENT_ID_RE.fullmatch(p["recipient_id"]):
        raise PayloadError("recipient_id may only contain letters, digits, / _ - (max 64)")
    for name in ("recipient_name", "program", "institution"):
        v = p[name]
        if not 1 <= len(v) <= TEXT_MAX:
            raise PayloadError(f"{name} must be 1-{TEXT_MAX} characters")
        if has_forbidden_chars(v):
            raise PayloadError(f"{name} contains control characters")
        if not is_normalized(v):
            raise PayloadError(f"{name} is not in canonical form (NFC, trimmed, single spaces)")
    if p["grade"] is not None and not GRADE_RE.fullmatch(p["grade"]):
        raise PayloadError("grade must look like 8.20")
    issued = _parse_date("issue_date", p["issue_date"])
    if p["expiry_date"] is not None and _parse_date("expiry_date", p["expiry_date"]) < issued:
        raise PayloadError("expiry_date is before issue_date")
    if not KEY_ID_RE.fullmatch(p["issuer_key_id"]):
        raise PayloadError("issuer_key_id must be 16 lowercase hex chars")
    if p["alg"] != slhdsa.ALG:
        raise PayloadError(f"alg must be {slhdsa.ALG}")
    return p
