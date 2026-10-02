"""JSON API (public): same checks as the HTML pages, plus the trusted public keys."""
import base64
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, File, Request, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.deps import client_ip, get_db, read_limited
from app.routers.verify import _result_status
from app.services import verification

router = APIRouter(prefix="/api")


@router.post("/verify/pdf")
async def api_verify_pdf(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    s = request.app.state.settings
    data = await read_limited(file, s.max_upload_bytes)
    res = verification.verify_uploaded_pdf(
        db, request.app.state.keystore, data, client_ip=client_ip(request),
        expected_host=urlsplit(s.base_url).netloc, max_bytes=s.max_upload_bytes, max_pages=s.max_pages)
    return JSONResponse(res.to_dict(), status_code=_result_status(res))


@router.get("/verify/{cert_id}")
def api_verify_id(request: Request, cert_id: str, d: str | None = None, db: Session = Depends(get_db)):
    res = verification.verify_by_id(db, request.app.state.keystore, cert_id, d,
                                    method="QR" if d is not None else "ID", client_ip=client_ip(request))
    return res.to_dict()


@router.get("/keys")
def api_keys(request: Request):
    """Trusted issuer PUBLIC keys (for offline verification). Private keys are never exposed."""
    return {"keys": [{"key_id": k.key_id, "alg": k.alg, "status": k.status, "created_at": k.created_at,
                      "retired_at": k.retired_at, "public_key": base64.b64encode(k.public_key).decode()}
                     for k in request.app.state.keystore.keys.values()]}
