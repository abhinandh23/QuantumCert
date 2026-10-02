"""Attacker toolkit: every forgery/tamper scenario from the brief (§5), as functions.

Each attack takes a genuine certificate (payload + signature) and returns forged PDF bytes.
Used by demo/make_samples.py (presentation samples) and tests/test_tamper.py (automated proof).
The attacker never has the issuer's private key — that is the whole point.
"""
import io
from dataclasses import dataclass, field
from typing import Callable

from pypdf import PdfReader, PdfWriter
from reportlab.lib.colors import white
from reportlab.pdfgen import canvas

from app.core import pdfgen, qr
from app.core.canonical import canonical_bytes, digest
from app.core.payload import new_cert_id
from app.crypto import keys, slhdsa


@dataclass
class Genuine:
    payload: dict
    signature: bytes
    base_url: str

    @property
    def pdf(self) -> bytes:
        return pdfgen.render_certificate(self.payload, self.signature, self.base_url)

    @property
    def qr_url(self) -> str:
        return qr.build_verify_url(self.base_url, self.payload["cert_id"], digest(canonical_bytes(self.payload)))


def _forge(g: Genuine, *, visible: dict | None = None, qr_url: str | None = None,
           payload: dict | None = None, signature: bytes | None = None, attach: bool = True) -> bytes:
    """Re-create the certificate PDF the way an attacker with a PDF editor could."""
    payload = payload or g.payload
    vis = pdfgen.visible_values(payload)
    vis.update(visible or {})
    att = pdfgen.build_attachment(payload, signature if signature is not None else g.signature) if attach else None
    return pdfgen.render_pdf(vis, qr_url or g.qr_url, att, g.base_url)


def _qr_for(g: Genuine, payload: dict) -> str:
    return qr.build_verify_url(g.base_url, payload["cert_id"], digest(canonical_bytes(payload)))


def _attacker_sign(payload: dict) -> tuple[bytes, bytes]:
    """Attacker generates their OWN SLH-DSA key and signs. Returns (signature, attacker_pk)."""
    pk, sk = slhdsa.keygen()
    return slhdsa.sign(sk, canonical_bytes(payload)), pk


# ------------------------------------------------------------------ 1. visible text edits

def edit_visible_regenerate(g: Genuine) -> bytes:
    """Printed CGPA raised to 9.80; embedded signed data and QR left untouched."""
    return _forge(g, visible={"grade": "9.80"})


def edit_visible_overlay(g: Genuine) -> bytes:
    """Classic PDF-editor trick: white box over the printed name, new name typed on top."""
    x0, top, x1, bottom = pdfgen.FIELD_BOXES["recipient_name"]
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(pdfgen.PAGE_W, pdfgen.PAGE_H))
    c.setFillColor(white)
    c.rect(x0, pdfgen.PAGE_H - bottom, x1 - x0, bottom - top, stroke=0, fill=1)
    c.setFillColor(pdfgen.INK)
    c.setFont("Serif-Bold", 28)
    c.drawCentredString((x0 + x1) / 2, pdfgen.PAGE_H - bottom + 8, "Mallory Forger")
    c.save()
    base = PdfReader(io.BytesIO(g.pdf))
    overlay = PdfReader(io.BytesIO(buf.getvalue())).pages[0]
    w = PdfWriter(clone_from=base)
    w.pages[0].merge_page(overlay)
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def edit_visible_date(g: Genuine) -> bytes:
    return _forge(g, visible={"issue_date": "2020-01-01", "program": "M.Tech Artificial Intelligence"})


def append_forged_page(g: Genuine) -> bytes:
    """Genuine certificate untouched, plus a forged second page ("transcript: CGPA 9.99, gold medal")."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(pdfgen.PAGE_W, pdfgen.PAGE_H))
    c.setFont("Serif-Bold", 22)
    c.drawString(72, pdfgen.PAGE_H - 120, "OFFICIAL TRANSCRIPT — addendum")
    c.setFont("Sans", 14)
    c.drawString(72, pdfgen.PAGE_H - 170, f"{g.payload['recipient_name']}: final CGPA 9.99, Gold Medal, rank 1")
    c.save()
    w = PdfWriter(clone_from=PdfReader(io.BytesIO(g.pdf)))
    w.add_page(PdfReader(io.BytesIO(buf.getvalue())).pages[0])
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


# ------------------------------------------------------------------ 2-4. embedded data / signature

def _tampered_payload(g: Genuine, **changes) -> dict:
    p = dict(g.payload)
    p.update(changes or {"grade": "9.80"})
    return p


def edit_embedded_payload(g: Genuine) -> bytes:
    """Change CGPA in the embedded JSON (and the printed text, consistently); keep signature + QR."""
    return _forge(g, payload=_tampered_payload(g))


def edit_payload_recompute_qr(g: Genuine) -> bytes:
    """Change CGPA, recompute the SHA-256 digest and print a fresh, matching QR. Signature can't be redone."""
    p = _tampered_payload(g)
    return _forge(g, payload=p, qr_url=_qr_for(g, p))


def flip_signature_bytes(g: Genuine) -> bytes:
    sig = bytearray(g.signature)
    for i in (0, 1000, 4000, len(sig) - 1):
        sig[i] ^= 0xFF
    return _forge(g, signature=bytes(sig))


# ------------------------------------------------------------------ 5. attacker's own key

def attacker_own_key(g: Genuine) -> bytes:
    """Fake certificate, correctly signed — but with the attacker's own SLH-DSA key."""
    p = _tampered_payload(g, cert_id=new_cert_id(), recipient_name="Mallory Forger", grade="9.95")
    pk, sk = slhdsa.keygen()
    p["issuer_key_id"] = keys.key_id_for(pk)
    return _forge(g, payload=p, signature=slhdsa.sign(sk, canonical_bytes(p)), qr_url=_qr_for(g, p))


def attacker_claims_trusted_key_id(g: Genuine) -> bytes:
    """Same, but the forged payload claims the issuer's real key_id."""
    p = _tampered_payload(g, cert_id=new_cert_id(), recipient_name="Mallory Forger", grade="9.95")
    sig, _ = _attacker_sign(p)
    return _forge(g, payload=p, signature=sig, qr_url=_qr_for(g, p))


# ------------------------------------------------------------------ 6. copied QR

def copy_genuine_qr(g: Genuine) -> bytes:
    """Attacker's own fake certificate with the genuine certificate's QR code pasted on it."""
    p = _tampered_payload(g, cert_id=new_cert_id(), recipient_name="Mallory Forger")
    sig, _ = _attacker_sign(p)
    return _forge(g, payload=p, signature=sig, qr_url=g.qr_url)


# ------------------------------------------------------------------ 7. cert_id changes

def change_cert_id_everywhere(g: Genuine) -> bytes:
    p = _tampered_payload(g, cert_id=new_cert_id())
    return _forge(g, payload=p, qr_url=_qr_for(g, p))


def change_cert_id_qr_only(g: Genuine) -> bytes:
    return _forge(g, qr_url=qr.build_verify_url(g.base_url, new_cert_id(), digest(canonical_bytes(g.payload))))


def change_cert_id_printed_only(g: Genuine) -> bytes:
    return _forge(g, visible={"cert_id": new_cert_id()})


# ------------------------------------------------------------------ 10. bad uploads

def not_a_pdf(g: Genuine) -> bytes:
    buf = io.BytesIO()
    qr.make_qr_image(g.qr_url).save(buf, "PNG")
    return buf.getvalue()  # a PNG renamed to .pdf


def truncated_pdf(g: Genuine) -> bytes:
    data = g.pdf
    return data[: len(data) // 3]


def encrypted_pdf(g: Genuine) -> bytes:
    w = PdfWriter(clone_from=PdfReader(io.BytesIO(g.pdf)))
    w.encrypt(user_password="secret", algorithm="AES-256")
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def oversized_pdf(g: Genuine) -> bytes:
    return g.pdf + b"\n%" + b"A" * (5 * 1024 * 1024) + b"\n"


def too_many_pages(g: Genuine) -> bytes:
    w = PdfWriter()
    page = PdfReader(io.BytesIO(g.pdf)).pages[0]
    for _ in range(3):
        w.add_page(page)
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def scanned_copy(g: Genuine) -> bytes:
    """A printed-and-scanned copy: just a picture of the page, no embedded signed data."""
    img = qr.render_pdf_page(g.pdf, 150)
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(pdfgen.PAGE_W, pdfgen.PAGE_H))
    from reportlab.lib.utils import ImageReader
    c.drawImage(ImageReader(img), 0, 0, pdfgen.PAGE_W, pdfgen.PAGE_H)
    c.save()
    return buf.getvalue()


# ------------------------------------------------------------------ scenario table

@dataclass
class Scenario:
    num: str
    slug: str
    attack: str
    make: Callable[[Genuine], bytes] | None
    verdict: str
    must_fail: set[str] = field(default_factory=set)
    needs: str | None = None  # "revoked" | "expired" — set up via the issuer database, not by the attacker


SCENARIOS = [
    Scenario("00", "genuine", "Genuine certificate, untouched", lambda g: g.pdf, "VALID"),
    Scenario("01a", "visible_cgpa_edited", "Printed CGPA changed (attachment untouched)",
             edit_visible_regenerate, "INVALID", {"visible"}),
    Scenario("01b", "visible_name_overlay", "Name covered with a white box and retyped",
             edit_visible_overlay, "INVALID", {"visible"}),
    Scenario("01c", "visible_date_degree_edited", "Printed date and degree changed",
             edit_visible_date, "INVALID", {"visible"}),
    Scenario("01d", "forged_page_appended", "Forged second page appended to a genuine certificate",
             append_forged_page, "INVALID", {"format"}),
    Scenario("02", "embedded_json_edited", "Embedded signed JSON edited (CGPA)",
             edit_embedded_payload, "INVALID", {"integrity", "signature"}),
    Scenario("03", "payload_edited_new_qr", "Payload edited, digest recomputed, new QR printed",
             edit_payload_recompute_qr, "INVALID", {"signature"}),
    Scenario("04", "signature_bytes_flipped", "Bytes flipped in the SLH-DSA signature",
             flip_signature_bytes, "INVALID", {"signature"}),
    Scenario("05a", "attacker_own_key", "Fake certificate signed with the attacker's own SLH-DSA key",
             attacker_own_key, "INVALID", {"signature"}),
    Scenario("05b", "attacker_claims_trusted_key", "Attacker's signature, claiming the issuer's key_id",
             attacker_claims_trusted_key_id, "INVALID", {"signature"}),
    Scenario("06", "genuine_qr_on_fake", "Genuine QR code copied onto a fake certificate",
             copy_genuine_qr, "INVALID", {"integrity"}),
    Scenario("07a", "cert_id_changed", "cert_id changed in payload, print and QR",
             change_cert_id_everywhere, "INVALID", {"signature"}),
    Scenario("07b", "cert_id_changed_qr_only", "QR pointed at a different cert_id",
             change_cert_id_qr_only, "INVALID", {"integrity"}),
    Scenario("07c", "cert_id_changed_print_only", "Printed cert_id changed",
             change_cert_id_printed_only, "INVALID", {"visible"}),
    Scenario("08", "revoked", "Genuine certificate, later revoked by the issuer",
             lambda g: g.pdf, "REVOKED", {"status"}, needs="revoked"),
    Scenario("09", "expired", "Genuine certificate past its expiry date",
             lambda g: g.pdf, "EXPIRED", {"expiry"}, needs="expired"),
    Scenario("10a", "not_a_pdf", "PNG image renamed to .pdf", not_a_pdf, "INVALID", {"format"}),
    Scenario("10b", "truncated", "Truncated / corrupted PDF", truncated_pdf, "INVALID", {"format"}),
    Scenario("10c", "encrypted", "Password-protected PDF", encrypted_pdf, "INVALID", {"format"}),
    Scenario("10d", "oversized", "Upload larger than 5 MB", oversized_pdf, "INVALID", {"format"}),
    Scenario("10e", "too_many_pages", "PDF with 3 pages", too_many_pages, "INVALID", {"format"}),
    Scenario("10f", "scanned_copy", "Printed & scanned copy (no embedded data)",
             scanned_copy, "INVALID", {"embedded"}),
]
