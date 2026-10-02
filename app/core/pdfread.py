"""Reading an uploaded PDF: format limits, embedded attachment, visible text, page structure."""
import io
import logging
import re

import pdfplumber
from pypdf import PdfReader

from app.core.pdfgen import ATTACHMENT_NAME, FIELD_BOXES

logging.getLogger("pypdf").setLevel(logging.ERROR)
logging.getLogger("pdfminer").setLevel(logging.ERROR)

_WS = re.compile(r"\s+")


class PdfFormatError(ValueError):
    pass


def open_pdf(data: bytes, max_bytes: int, max_pages: int) -> PdfReader:
    if not data:
        raise PdfFormatError("empty upload")
    if len(data) > max_bytes:
        raise PdfFormatError(f"file is larger than {max_bytes // (1024 * 1024)} MB")
    if b"%PDF-" not in data[:1024]:
        raise PdfFormatError("not a PDF file (missing %PDF- header)")
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise PdfFormatError("encrypted PDFs are not accepted")
        n = len(reader.pages)
        if n == 0:
            raise PdfFormatError("PDF has no pages")
        if n > max_pages:
            raise PdfFormatError(f"PDF has {n} pages; a QuantumCert certificate has {max_pages} page — "
                                 f"extra pages are not covered by the signature and are rejected")
        reader.pages[0].mediabox  # force parsing of the first page
    except PdfFormatError:
        raise
    except Exception as e:
        raise PdfFormatError(f"PDF could not be parsed ({type(e).__name__})") from e
    return reader


def read_attachment(reader: PdfReader) -> bytes | None:
    try:
        files = reader.attachments.get(ATTACHMENT_NAME)
    except Exception:
        return None
    return files[0] if files else None


def collapse(s: str | None) -> str:
    return _WS.sub(" ", s or "").strip()


def extract_visible(data: bytes) -> dict[str, str]:
    """Text found inside each field box on page 1 (whitespace collapsed)."""
    out = {}
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        page = pdf.pages[0]
        for name, box in FIELD_BOXES.items():
            out[name] = collapse(page.crop(box, strict=False).extract_text())
    return out


def page_structure(data: bytes) -> dict:
    """Facts used by the overlay heuristic: our template has 1 image, no annotations, no filled shapes."""
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        page = pdf.pages[0]
        filled = [o for o in page.rects + page.curves if o.get("fill")]
        return {"images": len(page.images), "annotations": len(page.annots), "filled_shapes": len(filled)}
