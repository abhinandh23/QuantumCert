"""Certificate PDF from a fixed template.

Every signed field is drawn as a single line inside a fixed box (FIELD_BOXES) so the verifier
can extract exactly that text later. Labels are drawn outside the boxes. The template draws no
filled shapes and exactly one image (the QR), which the verifier's structure heuristic relies on.
"""
import base64
import io
import json
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from reportlab.lib.colors import HexColor
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

from app.core import qr
from app.core.canonical import canonical_bytes, digest
from app.crypto import slhdsa

ATTACHMENT_NAME = "quantumcert.json"
ATTACHMENT_FORMAT = "quantumcert/1"

PAGE_W, PAGE_H = 841.89, 595.28  # A4 landscape, points

# (x0, top, x1, bottom) in points, top-left origin (pdfplumber's convention).
FIELD_BOXES = {
    "institution":    (60, 56, 782, 90),
    "recipient_name": (60, 166, 782, 204),
    "program":        (60, 236, 782, 264),
    "recipient_id":   (250, 298, 610, 320),
    "grade":          (250, 326, 610, 348),
    "issue_date":     (250, 354, 610, 376),
    "expiry_date":    (250, 382, 610, 404),
    "cert_id":        (250, 410, 610, 432),
    "issuer_key_id":  (250, 438, 610, 460),
}
FIELD_LABELS = {
    "recipient_id": "Register No.", "grade": "CGPA", "issue_date": "Date of issue",
    "expiry_date": "Valid until", "cert_id": "Certificate ID", "issuer_key_id": "Issuer key ID",
}
QR_BOX = (642, 296, 782, 436)

_FONT_DIR = Path(__file__).resolve().parent.parent / "static" / "fonts"
_FONTS = {"Sans": "DejaVuSans.ttf", "Sans-Bold": "DejaVuSans-Bold.ttf", "Serif": "DejaVuSerif.ttf",
          "Serif-Bold": "DejaVuSerif-Bold.ttf", "Serif-Italic": "DejaVuSerif-Italic.ttf"}
for _name, _file in _FONTS.items():
    if _name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(_name, str(_FONT_DIR / _file)))

# font, max size, alignment for each field box
_STYLE = {"institution": ("Serif-Bold", 24, "center"), "recipient_name": ("Serif-Bold", 28, "center"),
          "program": ("Serif", 18, "center")}
_DEFAULT_STYLE = ("Sans", 12, "left")
INK, ACCENT, MUTED = HexColor("#1b2a41"), HexColor("#8a6d1d"), HexColor("#5b6472")


def visible_values(payload: dict) -> dict[str, str]:
    """The exact text printed in each field box (also what the verifier expects to find)."""
    v = {k: payload[k] for k in FIELD_BOXES}
    v["grade"] = payload["grade"] if payload["grade"] is not None else "Not applicable"
    v["expiry_date"] = payload["expiry_date"] if payload["expiry_date"] is not None else "No expiry"
    return v


def build_attachment(payload: dict, signature: bytes) -> bytes:
    doc = {"format": ATTACHMENT_FORMAT, "payload": payload,
           "signature": base64.b64encode(signature).decode(),
           "key_id": payload["issuer_key_id"], "alg": payload["alg"], "ctx": slhdsa.CTX.decode()}
    return json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")


def _fit(c: canvas.Canvas, text: str, font: str, max_size: float, width: float, min_size: float = 6) -> float:
    w1 = pdfmetrics.stringWidth(text, font, 1) or 1
    return max(min_size, min(max_size, (width - 4) / w1))


def _draw_field(c: canvas.Canvas, name: str, text: str) -> None:
    x0, top, x1, bottom = FIELD_BOXES[name]
    font, max_size, align = _STYLE.get(name, _DEFAULT_STYLE)
    size = _fit(c, text, font, max_size, x1 - x0)
    baseline = PAGE_H - bottom + (bottom - top - size * 0.72) / 2
    c.setFont(font, size)
    c.setFillColor(INK)
    if align == "center":
        c.drawCentredString((x0 + x1) / 2, baseline, text)
    else:
        c.drawString(x0 + 2, baseline, text)


def _y(top: float) -> float:
    return PAGE_H - top


def render_pdf(visible: dict[str, str], qr_url: str, attachment: bytes | None, base_url: str,
               title: str = "QuantumCert certificate") -> bytes:
    """Low-level renderer. Normal issuance goes through render_certificate()."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(PAGE_W, PAGE_H), invariant=1)
    c.setTitle(title)
    c.setAuthor("QuantumCert")

    # frame (stroked only — the template never draws filled shapes)
    c.setStrokeColor(ACCENT)
    c.setLineWidth(3)
    c.rect(24, 24, PAGE_W - 48, PAGE_H - 48, stroke=1, fill=0)
    c.setLineWidth(0.8)
    c.rect(32, 32, PAGE_W - 64, PAGE_H - 64, stroke=1, fill=0)

    # decorative text (not signed fields)
    c.setFillColor(ACCENT)
    c.setFont("Sans-Bold", 13)
    c.drawCentredString(PAGE_W / 2, _y(118), "D E G R E E    C E R T I F I C A T E")
    c.setFillColor(MUTED)
    c.setFont("Serif-Italic", 13)
    c.drawCentredString(PAGE_W / 2, _y(152), "This is to certify that")
    c.drawCentredString(PAGE_W / 2, _y(226), "has fulfilled the requirements for and is awarded")

    # labels for the detail rows
    c.setFont("Sans", 11)
    for name, label in FIELD_LABELS.items():
        x0, top, x1, bottom = FIELD_BOXES[name]
        c.setFillColor(MUTED)
        c.drawRightString(x0 - 10, _y(bottom) + 6, label)

    for name, text in visible.items():
        _draw_field(c, name, text)

    # QR code
    x0, top, x1, bottom = QR_BOX
    c.drawImage(ImageReader(qr.make_qr_image(qr_url)), x0, _y(bottom), width=x1 - x0, height=bottom - top)
    c.setFillColor(MUTED)
    c.setFont("Sans", 9)
    c.drawCentredString((x0 + x1) / 2, _y(bottom + 14), "Scan to verify")

    c.setFont("Sans", 8)
    c.drawCentredString(PAGE_W / 2, _y(520),
                        f"Digitally signed with {slhdsa.ALG} (NIST FIPS 205, post-quantum hash-based signature).")
    c.drawCentredString(PAGE_W / 2, _y(533),
                        f"Verify the full document at {base_url.rstrip('/')}/verify — "
                        f"the embedded file {ATTACHMENT_NAME} allows offline verification.")
    c.showPage()
    c.save()

    reader = PdfReader(io.BytesIO(buf.getvalue()))
    writer = PdfWriter(clone_from=reader)
    if attachment is not None:
        writer.add_attachment(ATTACHMENT_NAME, attachment)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def render_certificate(payload: dict, signature: bytes, base_url: str) -> bytes:
    """The PDF for a genuine, signed certificate."""
    url = qr.build_verify_url(base_url, payload["cert_id"], digest(canonical_bytes(payload)))
    return render_pdf(visible_values(payload), url, build_attachment(payload, signature), base_url,
                      title=f"QuantumCert {payload['cert_id']} — {payload['recipient_name']}")
