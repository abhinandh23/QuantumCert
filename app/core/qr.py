"""QR code: build/parse the verify URL, render a QR image, decode QR codes from images and PDFs.

The QR holds only  {base_url}/verify/{cert_id}?d={base64url(SHA-256(canonical_bytes))}.
The signature (7,856 bytes) is far too large for a practical QR code and is never put in it.
"""
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

import cv2
import numpy as np
import qrcode
import zxingcpp
from PIL import Image

from app.core.canonical import b64url, b64url_decode
from app.core.payload import CERT_ID_RE


def build_verify_url(base_url: str, cert_id: str, digest: bytes) -> str:
    return f"{base_url.rstrip('/')}/verify/{cert_id}?d={b64url(digest)}"


@dataclass
class QrLink:
    url: str
    host: str
    cert_id: str
    digest: bytes | None


def parse_verify_url(url: str) -> QrLink:
    """Parse a QuantumCert verify URL; raises ValueError if it isn't one."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise ValueError("QR does not contain an http(s) URL")
    segs = [s for s in parts.path.split("/") if s]
    if len(segs) != 2 or segs[0] != "verify" or not CERT_ID_RE.fullmatch(segs[1]):
        raise ValueError("QR URL is not a QuantumCert /verify/<cert_id> link")
    d = parse_qs(parts.query).get("d", [None])[0]
    digest = None
    if d is not None:
        digest = b64url_decode(d)
        if len(digest) != 32:
            raise ValueError("QR digest parameter is not a SHA-256 value")
    return QrLink(url=url, host=parts.netloc, cert_id=segs[1], digest=digest)


def make_qr_image(data: str) -> Image.Image:
    # Level L keeps our ~90-char URL at QR version 5 (37x37) instead of 6 (41x41 at level M):
    # larger modules make webcam scanning far more reliable; the PDF's QR is clean, not damaged paper.
    qr =qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").get_image().convert("RGB")


def _gray(img) -> np.ndarray:
    arr = np.asarray(img.convert("L")) if isinstance(img, Image.Image) else img
    if arr.ndim == 3:
        arr = cv2.cvtColor(arr, cv2.COLOR_BGR2GRAY)
    return np.ascontiguousarray(arr)


def _zxing(arr: np.ndarray) -> list[str]:
    return [r.text for r in zxingcpp.read_barcodes(arr, formats=zxingcpp.BarcodeFormat.QRCode) if r.text]


def _variants(arr: np.ndarray):
    """Preprocessing that rescues small or slightly blurred webcam/photo QR codes."""
    h, w = arr.shape[:2]
    if max(h, w) > 1600:  # huge photos: decode a downscaled copy first (faster, often better)
        s = 1600 / max(h, w)
        yield cv2.resize(arr, (int(w * s), int(h * s)), interpolation=cv2.INTER_AREA)
    if max(h, w) <= 1400:
        up = cv2.resize(arr, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        yield up
        yield cv2.addWeighted(up, 1.8, cv2.GaussianBlur(up, (0, 0), 3), -0.8, 0)  # unsharp mask
    yield cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(arr)  # glare / low contrast


def decode_qr_fast(img) -> list[str]:
    """Quick decode for live webcam frames: zxing-cpp on the frame plus a few enhanced variants."""
    arr = _gray(img)
    for a in (arr, *_variants(arr)):
        found = _zxing(a)
        if found:
            return found
    return []


def decode_qr_image(img) -> list[str]:
    """Thorough decode (PDF pages, uploaded photos): zxing-cpp first, then OpenCV's detectors."""
    found = decode_qr_fast(img)
    if found:
        return found
    arr = _gray(img)
    attempts = [arr, cv2.threshold(arr, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)[1]]
    for detector in (cv2.QRCodeDetector(), cv2.QRCodeDetectorAruco()):
        for a in attempts:
            try:
                text, _, _ = detector.detectAndDecode(a)
            except cv2.error:
                continue
            if text:
                return [text]
    return []


def render_pdf_page(pdf_bytes: bytes, dpi: int = 200, page_index: int = 0) -> Image.Image:
    import pypdfium2 as pdfium
    doc = pdfium.PdfDocument(pdf_bytes)
    try:
        page = doc[page_index]
        return page.render(scale=dpi / 72).to_pil()
    finally:
        doc.close()


def decode_qr_from_pdf(pdf_bytes: bytes, qr_box: tuple[float, float, float, float] | None = None) -> list[str]:
    """Render page 1 and decode. Retries at a higher DPI, then on a crop of the known QR region."""
    for dpi in (200, 300):
        page = render_pdf_page(pdf_bytes, dpi)
        found = decode_qr_image(page)
        if found:
            return found
        if qr_box:
            s, pad = dpi / 72, 20
            x0, top, x1, bottom = qr_box
            crop = page.crop((max(0, (x0 - pad) * s), max(0, (top - pad) * s), (x1 + pad) * s, (bottom + pad) * s))
            found = decode_qr_image(crop)
            if found:
                return found
    return []
