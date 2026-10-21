"""Public verification pages (no login): PDF upload, certificate ID, QR link, QR image."""
import io
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse
from PIL import Image, UnidentifiedImageError
from sqlalchemy.orm import Session

from app.core import qr
from app.core.results import FAIL
from app.deps import client_ip, get_db, read_limited, templates
from app.services import verification

router = APIRouter()

Image.MAX_IMAGE_PIXELS = 40_000_000  # refuse decompression-bomb images


def _result_status(res) -> int:
    fmt = next((c for c in res.checks if c.key == "format"), None)
    if fmt is not None and fmt.status == FAIL:
        return 413 if "larger than" in fmt.reason else 400
    return 200


@router.get("/")
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {})


@router.get("/verify")
def verify_page(request: Request, error: str | None = None):
    return templates.TemplateResponse(request, "verify.html", {"error": error})


@router.post("/verify/pdf")
async def verify_pdf(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    s = request.app.state.settings
    data = await read_limited(file, s.max_upload_bytes)
    res = verification.verify_uploaded_pdf(
        db, request.app.state.keystore, data, client_ip=client_ip(request),
        expected_host=urlsplit(s.base_url).netloc, max_bytes=s.max_upload_bytes, max_pages=s.max_pages)
    return templates.TemplateResponse(request, "result.html", {"res": res, "filename": file.filename},
                                      status_code=_result_status(res))


@router.post("/verify/id")
def verify_id_form(cert_id: str = Form(...)):
    return RedirectResponse(f"/verify/{quote(cert_id.strip().upper(), safe='')}", status_code=303)


@router.post("/verify/qr-image")
async def verify_qr_image(request: Request, file: UploadFile = File(...)):
    """Fallback when the webcam scanner is unavailable: decode the QR from an uploaded image."""
    data = await read_limited(file, request.app.state.settings.max_upload_bytes)
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
        texts = qr.decode_qr_image(img.convert("RGB"))
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, ValueError):
        return RedirectResponse("/verify?error=" + quote("That file is not a readable image.") + "#scan", status_code=303)
    for t in texts:
        try:
            link = qr.parse_verify_url(t)
        except ValueError:
            continue
        d = f"?d={qr.b64url(link.digest)}" if link.digest else ""
        return RedirectResponse(f"/verify/{link.cert_id}{d}", status_code=303)
    msg = "No QuantumCert QR code found in that image." if not texts else "That QR code is not a QuantumCert link."
    return RedirectResponse("/verify?error=" + quote(msg) + "#scan", status_code=303)


MAX_FRAME_BYTES = 3 * 1024 * 1024


@router.post("/verify/scan-frame")
async def scan_frame(request: Request):
    """Decode one webcam frame (JPEG/PNG body) sent by the verify page's scanner.

    Frames are decoded in memory and discarded — never stored or logged. Decoding happens
    server-side with zxing-cpp because it is far more robust on small/blurry webcam images
    than browser-side JavaScript decoders.
    """
    if int(request.headers.get("content-length") or 0) > MAX_FRAME_BYTES:
        return JSONResponse({"found": False, "error": "frame too large"}, status_code=413)
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_FRAME_BYTES:
            return JSONResponse({"found": False, "error": "frame too large"}, status_code=413)
    try:
        img = Image.open(io.BytesIO(bytes(body)))
        img.load()
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, ValueError):
        return JSONResponse({"found": False, "error": "not an image"}, status_code=400)
    texts = await run_in_threadpool(qr.decode_qr_fast, img.convert("L"))
    if not texts:
        return {"found": False}
    for t in texts:
        try:
            link = qr.parse_verify_url(t)
        except ValueError:
            continue
        d = f"?d={qr.b64url(link.digest)}" if link.digest else ""
        return {"found": True, "cert_id": link.cert_id, "redirect": f"/verify/{link.cert_id}{d}"}
    return {"found": True, "redirect": None, "message": "That QR code is not a QuantumCert certificate link."}


@router.get("/verify/{cert_id}")
def verify_by_id(request: Request, cert_id: str, d: str | None = None, db: Session = Depends(get_db)):
    res = verification.verify_by_id(db, request.app.state.keystore, cert_id, d,
                                    method="QR" if d is not None else "ID", client_ip=client_ip(request))
    return templates.TemplateResponse(request, "result.html", {"res": res})
