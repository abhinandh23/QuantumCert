"""The verification pipeline. Pure: no web framework, no database.

The web app passes a `lookup(cert_id) -> Record | None` backed by the database; the offline CLI
passes lookup=None, which skips the record/status checks. Only keys from the trusted keystore are
ever used to verify; any key material found in a PDF or QR code is ignored.
"""
import base64
import binascii
import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Callable

from app.config import MAX_PDF_PAGES, MAX_UPLOAD_BYTES
from app.core import pdfread, qr
from app.core.canonical import b64url_decode, canonical_bytes, digest
from app.core.pdfgen import ATTACHMENT_FORMAT, ATTACHMENT_NAME, FIELD_LABELS, QR_BOX, visible_values
from app.core.payload import CERT_ID_RE, PayloadError, validate_payload
from app.core.results import FAIL, PASS, Check, VerificationResult
from app.crypto import slhdsa
from app.crypto.keys import Keystore


@dataclass
class Record:
    """What the issuer database holds for one certificate."""
    cert_id: str
    payload_canonical: bytes
    digest: bytes
    signature: bytes
    key_id: str
    status: str                      # ACTIVE | REVOKED
    revoked_reason: str | None = None
    revoked_at: str | None = None


Lookup = Callable[[str], Record | None]

FIELD_NAMES = {"institution": "Institution", "recipient_name": "Name", "program": "Programme", **FIELD_LABELS}


def utc_today() -> date:
    return datetime.now(timezone.utc).date()


def _short(b: bytes) -> str:
    return b.hex()[:16] + "…"


def _reject_constant(name):
    raise ValueError(f"invalid JSON constant {name}")


def _verify_with_keystore(keystore: Keystore, key_id: str, message: bytes, sig: bytes) -> tuple[bool, str]:
    tk = keystore.get(key_id)
    if tk is None:
        return False, (f"key_id {key_id} is not in the trusted keystore — the certificate was signed "
                       f"by an unknown key (any public key shipped with the document is ignored)")
    if tk.alg != slhdsa.ALG:
        return False, f"trusted key {key_id} is for {tk.alg}, not {slhdsa.ALG}"
    if not slhdsa.verify(tk.public_key, message, sig):
        return False, f"{slhdsa.ALG} signature does NOT verify under trusted key {key_id}"
    retired = " (key since retired; certificates issued before retirement stay valid)" if tk.status == "RETIRED" else ""
    return True, f"valid {slhdsa.ALG} signature by trusted issuer key {key_id}{retired}"


def _status_and_expiry(res: VerificationResult, rec: Record | None, payload: dict | None,
                       status: Check, expiry: Check, today: date, online: bool) -> None:
    if not online:
        status.skipped("offline mode — revocation can only be checked against the issuer's records")
    elif rec is None:
        status.skipped("skipped: no issuer record")
    else:
        res.cert_status = rec.status
        if rec.status == "REVOKED":
            res.revocation = {"reason": rec.revoked_reason, "revoked_at": rec.revoked_at}
            status.failed(f"revoked on {rec.revoked_at}: {rec.revoked_reason}")
        else:
            status.passed("not revoked")

    if payload is None or not res.signature_valid:
        expiry.skipped("skipped: no signed data to read the expiry date from")
    elif payload["expiry_date"] is None:
        expiry.passed("certificate does not expire")
    elif date.fromisoformat(payload["expiry_date"]) >= today:
        expiry.passed(f"valid until {payload['expiry_date']} (today is {today.isoformat()} UTC)")
    else:
        expiry.failed(f"expired on {payload['expiry_date']} (today is {today.isoformat()} UTC)")


# ------------------------------------------------------------------------------- PDF upload

def verify_pdf(data: bytes, keystore: Keystore, lookup: Lookup | None = None, today: date | None = None,
               max_bytes: int = MAX_UPLOAD_BYTES, max_pages: int = MAX_PDF_PAGES,
               expected_host: str | None = None) -> VerificationResult:
    """Full check of an uploaded certificate PDF (brief §4.1, steps 1-9)."""
    online = lookup is not None
    today = today or utc_today()
    c_format = Check("format", "1. File format")
    c_qr = Check("qr", "2. QR code")
    c_emb = Check("embedded", "3. Embedded signed data")
    c_vis = Check("visible", "4. Printed text matches signed data")
    c_int = Check("integrity", "5. Integrity (SHA-256 digest)")
    c_sig = Check("signature", "6. SLH-DSA signature (trusted key)")
    c_rec = Check("record", "7. Issuer record")
    c_status = Check("status", "8. Revocation status")
    c_exp = Check("expiry", "9. Expiry")
    res = VerificationResult("PDF" if online else "OFFLINE",
                             [c_format, c_qr, c_emb, c_vis, c_int, c_sig, c_rec, c_status, c_exp])

    # 1. format
    try:
        reader = pdfread.open_pdf(data, max_bytes, max_pages)
        c_format.passed(f"valid PDF, {len(reader.pages)} page(s), {len(data) // 1024} KB")
    except pdfread.PdfFormatError as e:
        c_format.failed(str(e))
        for c in res.checks[1:]:
            c.skipped("skipped: the file is not an acceptable PDF")
        res.decide(online)
        return res

    # 2. QR
    link = None
    try:
        texts = qr.decode_qr_from_pdf(data, QR_BOX)
    except Exception as e:
        texts = []
        c_qr.failed(f"page could not be rendered ({type(e).__name__})")
    if texts:
        errors = []
        for t in texts:
            try:
                link = qr.parse_verify_url(t)
                break
            except ValueError as e:
                errors.append(str(e))
        if link:
            c_qr.passed(f"decoded link to {link.cert_id}" + ("" if link.digest else " (no digest)"))
            if expected_host and link.host != expected_host:
                res.warnings.append(f"QR points to host '{link.host}', not this server ('{expected_host}')")
        else:
            c_qr.failed("; ".join(errors))
    elif c_qr.status != FAIL:
        c_qr.failed("no readable QR code found on page 1")

    # 3. embedded data
    payload = sig = cbytes = dig = None
    raw = pdfread.read_attachment(reader)
    if raw is None:
        c_emb.failed(f"no {ATTACHMENT_NAME} attachment — this may be a scanned or re-created copy; "
                     f"use the certificate-ID check instead")
    else:
        try:
            doc = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
            if not isinstance(doc, dict) or doc.get("format") != ATTACHMENT_FORMAT:
                raise PayloadError(f"attachment is not in {ATTACHMENT_FORMAT} format")
            payload = validate_payload(doc.get("payload"))
            try:
                sig = base64.b64decode(doc.get("signature") or "", validate=True)
            except (binascii.Error, TypeError):
                raise PayloadError("signature is not valid base64")
            # unsigned copies of signed fields must agree; the signed values are authoritative
            if doc.get("key_id") != payload["issuer_key_id"]:
                raise PayloadError("attachment key_id differs from the signed issuer_key_id")
            if doc.get("alg") != payload["alg"]:
                raise PayloadError("attachment alg differs from the signed alg")
            if doc.get("ctx") != slhdsa.CTX.decode():
                raise PayloadError(f"attachment ctx is not {slhdsa.CTX.decode()}")
            cbytes = canonical_bytes(payload)
            dig = digest(cbytes)
            res.cert_id, res.key_id = payload["cert_id"], payload["issuer_key_id"]
            c_emb.passed(f"{ATTACHMENT_NAME} found; payload for {payload['cert_id']} is well-formed and canonical")
        except (UnicodeDecodeError, ValueError) as e:  # JSONDecodeError and PayloadError are ValueErrors
            payload = None
            c_emb.failed(f"{ATTACHMENT_NAME} is malformed: {e}")

    # 4. visible text vs embedded payload
    if payload is None:
        c_vis.skipped("skipped: no valid embedded data to compare with")
    else:
        try:
            printed = pdfread.extract_visible(data)
            struct = pdfread.page_structure(data)
            problems = [f"{FIELD_NAMES[k]}: printed '{printed[k]}' but signed '{v}'"
                        for k, v in visible_values(payload).items() if printed[k] != v]
            if struct["images"] != 1:
                problems.append(f"page has {struct['images']} images (template has exactly 1, the QR code)")
            if struct["annotations"]:
                problems.append(f"page has {struct['annotations']} annotation(s) (template has none)")
            if struct["filled_shapes"]:
                problems.append(f"page has {struct['filled_shapes']} filled shape(s) — possible cover-up overlay")
            if problems:
                c_vis.failed("; ".join(problems))
            else:
                c_vis.passed(f"all {len(printed)} printed fields match the signed data; no overlays found")
        except Exception as e:
            c_vis.failed(f"could not extract page text ({type(e).__name__})")

    # record lookup (needed by 5 and 7)
    rec = None
    lookup_id = payload["cert_id"] if payload else (link.cert_id if link else None)
    res.cert_id = res.cert_id or lookup_id
    if online and lookup_id:
        rec = lookup(lookup_id)
        res.record_found = rec is not None

    # 5. integrity
    if dig is None:
        c_int.skipped("skipped: no valid embedded data to hash")
    else:
        problems, ok = [], []
        if link:
            if link.cert_id != payload["cert_id"]:
                problems.append(f"QR is for {link.cert_id} but the signed data is for {payload['cert_id']}")
            if link.digest is None:
                problems.append("QR carries no digest")
            elif link.digest != dig:
                problems.append(f"digest {_short(dig)} ≠ QR digest {_short(link.digest)}")
            else:
                ok.append("QR")
        if rec is not None:
            if rec.digest != dig:
                problems.append(f"digest {_short(dig)} ≠ issuer record digest {_short(rec.digest)}")
            else:
                ok.append("issuer record")
        if problems:
            c_int.failed("; ".join(problems))
        elif ok:
            c_int.passed(f"SHA-256 {_short(dig)} matches the {' and '.join(ok)}")
        else:
            c_int.skipped("nothing to compare the digest with (no QR, no record)")

    # 6. signature
    if payload is None:
        c_sig.skipped("skipped: no valid embedded data")
    else:
        good, why = _verify_with_keystore(keystore, payload["issuer_key_id"], cbytes, sig)
        res.signature_valid = good
        (c_sig.passed if good else c_sig.failed)(why)
        if good:
            res.payload = payload

    # 7. issuer record
    if not online:
        c_rec.skipped("offline mode — no issuer database")
    elif not lookup_id:
        c_rec.skipped("skipped: no certificate ID found in the document")
    elif rec is None:
        c_rec.failed(f"no certificate with ID {lookup_id} in the issuer's records")
    else:
        rec_ok, why = _verify_with_keystore(keystore, rec.key_id, rec.payload_canonical, rec.signature)
        if not rec_ok:
            c_rec.failed(f"stored record fails its own signature check — database tampering? ({why})")
        elif digest(rec.payload_canonical) != rec.digest:
            c_rec.failed("stored record digest does not match its stored data — database tampering?")
        elif cbytes is not None and rec.payload_canonical != cbytes:
            c_rec.failed("document's signed data differs from the issuer's record")
        else:
            c_rec.passed("issuer record exists and its stored signature verifies")

    # 8-9.
    _status_and_expiry(res, rec, payload, c_status, c_exp, today, online)
    res.decide(online)
    return res


# ------------------------------------------------------------------------------- QR scan / ID

def verify_record(cert_id: str, d: str | None, keystore: Keystore, lookup: Lookup,
                  today: date | None = None, method: str = "ID") -> VerificationResult:
    """Record-level check for a scanned QR (with digest `d`) or a typed certificate ID (brief §4.2)."""
    today = today or utc_today()
    cert_id = (cert_id or "").strip().upper()
    c_rec = Check("record", "1. Issuer record")
    c_sig = Check("signature", "2. SLH-DSA signature of the record (trusted key)")
    c_qr = Check("qr_digest", "3. QR digest matches record")
    c_status = Check("status", "4. Revocation status")
    c_exp = Check("expiry", "5. Expiry")
    res = VerificationResult(method, [c_rec, c_sig, c_qr, c_status, c_exp], cert_id=cert_id)

    rec = lookup(cert_id) if CERT_ID_RE.fullmatch(cert_id) else None
    res.record_found = rec is not None
    if rec is None:
        c_rec.failed(f"no certificate with ID '{cert_id}' in the issuer's records"
                     if CERT_ID_RE.fullmatch(cert_id) else f"'{cert_id}' is not a valid certificate ID")
        for c in res.checks[1:]:
            c.skipped("skipped: no issuer record")
        res.decide(online=True)
        return res
    c_rec.passed(f"record {cert_id} found")

    payload = None
    try:
        payload = validate_payload(json.loads(rec.payload_canonical.decode("utf-8")))
        if canonical_bytes(payload) != rec.payload_canonical or digest(rec.payload_canonical) != rec.digest:
            raise PayloadError("stored data is not in canonical form / digest mismatch")
        good, why = _verify_with_keystore(keystore, payload["issuer_key_id"], rec.payload_canonical, rec.signature)
    except (UnicodeDecodeError, ValueError) as e:
        good, why = False, f"stored record is corrupt: {e}"
    res.signature_valid = good
    res.key_id = payload["issuer_key_id"] if payload else rec.key_id
    if good:
        c_sig.passed(why)
        res.payload = payload
    else:
        c_sig.failed(why + " — database tampering?")

    if d is None:
        c_qr.skipped("certificate ID entered manually — no QR digest to compare")
    else:
        try:
            qd = b64url_decode(d)
        except ValueError:
            qd = b""
        if qd == rec.digest:
            c_qr.passed(f"QR digest {_short(qd)} matches the record")
        else:
            c_qr.failed("QR/record mismatch: the QR code's digest does not match this certificate's record")

    _status_and_expiry(res, rec, payload, c_status, c_exp, today, online=True)
    res.decide(online=True)
    return res
