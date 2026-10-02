"""Admin (issuer) pages: dashboard, issue, details, download, revoke, verification history."""
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core import qr
from app.core.canonical import b64url
from app.core.payload import CertificateInput, PayloadError
from app.deps import check_csrf, current_admin, get_db, templates
from app.models import AdminUser, Certificate, VerificationHistory
from app.services import issuance

router = APIRouter(prefix="/admin")
PAGE_SIZE = 20


def _get_cert(db: Session, cert_id: str) -> Certificate:
    cert = db.scalar(select(Certificate).where(Certificate.cert_id == cert_id))
    if cert is None:
        raise HTTPException(404, "certificate not found")
    return cert


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


@router.get("")
def dashboard(request: Request, q: str = "", status: str = "all", page: int = 1,
              db: Session = Depends(get_db), admin: AdminUser = Depends(current_admin)):
    stmt = select(Certificate)
    if q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(Certificate.recipient_name.ilike(like), Certificate.recipient_id.ilike(like),
                              Certificate.cert_id.ilike(like), Certificate.program.ilike(like)))
    today = _today()
    if status == "active":
        stmt = stmt.where(Certificate.status == "ACTIVE",
                          or_(Certificate.expiry_date.is_(None), Certificate.expiry_date >= today))
    elif status == "revoked":
        stmt = stmt.where(Certificate.status == "REVOKED")
    elif status == "expired":
        stmt = stmt.where(Certificate.expiry_date < today)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    page = max(1, page)
    certs = db.scalars(stmt.order_by(Certificate.created_at.desc(), Certificate.id.desc())
                       .offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)).all()
    stats = {
        "total": db.scalar(select(func.count(Certificate.id))),
        "revoked": db.scalar(select(func.count(Certificate.id)).where(Certificate.status == "REVOKED")),
        "verifications": db.scalar(select(func.count(VerificationHistory.id))),
    }
    return templates.TemplateResponse(request, "admin/dashboard.html", {
        "admin": admin, "certs": certs, "q": q, "status": status, "page": page, "today": today,
        "pages": max(1, -(-total // PAGE_SIZE)), "total": total, "stats": stats,
        "signer": request.app.state.signer})


@router.get("/certificates/new")
def new_form(request: Request, admin: AdminUser = Depends(current_admin)):
    return templates.TemplateResponse(request, "admin/new.html", {
        "admin": admin, "error": None, "values": {"issue_date": _today()}, "signer": request.app.state.signer})


@router.post("/certificates/new", dependencies=[Depends(check_csrf)])
def create(request: Request, recipient_name: str = Form(""), recipient_id: str = Form(""),
           program: str = Form(""), institution: str = Form(""), grade: str = Form(""),
           issue_date: str = Form(""), expiry_date: str = Form(""),
           db: Session = Depends(get_db), admin: AdminUser = Depends(current_admin)):
    values = dict(recipient_name=recipient_name, recipient_id=recipient_id, program=program,
                  institution=institution, grade=grade, issue_date=issue_date, expiry_date=expiry_date)
    try:
        cert = issuance.issue_certificate(db, request.app.state.signer,
                                          CertificateInput(**{k: v or None for k, v in values.items()}),
                                          admin.id)
    except (PayloadError, issuance.IssuanceError) as e:
        return templates.TemplateResponse(request, "admin/new.html", {
            "admin": admin, "error": str(e), "values": values, "signer": request.app.state.signer},
            status_code=422)
    return RedirectResponse(f"/admin/certificates/{cert.cert_id}?issued=1", status_code=303)


@router.get("/certificates/{cert_id}")
def detail(request: Request, cert_id: str, issued: int = 0,
           db: Session = Depends(get_db), admin: AdminUser = Depends(current_admin)):
    cert = _get_cert(db, cert_id)
    history = db.scalars(select(VerificationHistory).where(VerificationHistory.cert_id == cert_id)
                         .order_by(VerificationHistory.created_at.desc()).limit(25)).all()
    base = request.app.state.settings.base_url
    return templates.TemplateResponse(request, "admin/detail.html", {
        "admin": admin, "cert": cert, "payload": json.loads(cert.payload_canonical), "issued": issued,
        "canonical": cert.payload_canonical.decode("utf-8"), "history": history, "today": _today(),
        "verify_url": qr.build_verify_url(base, cert.cert_id, cert.digest), "digest_b64": b64url(cert.digest)})


@router.get("/certificates/{cert_id}/pdf")
def download(request: Request, cert_id: str, db: Session = Depends(get_db),
             admin: AdminUser = Depends(current_admin)):
    cert = _get_cert(db, cert_id)
    pdf = issuance.certificate_pdf(cert, request.app.state.settings.base_url)
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{cert.cert_id}.pdf"'})


@router.get("/certificates/{cert_id}/preview.png")
def preview(request: Request, cert_id: str, db: Session = Depends(get_db),
            admin: AdminUser = Depends(current_admin)):
    cert = _get_cert(db, cert_id)
    img = qr.render_pdf_page(issuance.certificate_pdf(cert, request.app.state.settings.base_url), dpi=110)
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return Response(buf.getvalue(), media_type="image/png", headers={"Cache-Control": "private, max-age=300"})


@router.post("/certificates/{cert_id}/revoke", dependencies=[Depends(check_csrf)])
def revoke(cert_id: str, reason: str = Form(""), db: Session = Depends(get_db),
           admin: AdminUser = Depends(current_admin)):
    cert = _get_cert(db, cert_id)
    try:
        issuance.revoke_certificate(db, cert, reason, admin.id)
    except issuance.IssuanceError as e:
        raise HTTPException(400, str(e))
    return RedirectResponse(f"/admin/certificates/{cert_id}", status_code=303)


@router.get("/history")
def history(request: Request, verdict: str = "", page: int = 1,
            db: Session = Depends(get_db), admin: AdminUser = Depends(current_admin)):
    stmt = select(VerificationHistory)
    if verdict:
        stmt = stmt.where(VerificationHistory.verdict == verdict)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    page = max(1, page)
    rows = db.scalars(stmt.order_by(VerificationHistory.created_at.desc(), VerificationHistory.id.desc())
                      .offset((page - 1) * 50).limit(50)).all()
    for r in rows:
        r.failed = [c for c in json.loads(r.checks_json) if c["status"] == "FAIL"]
    return templates.TemplateResponse(request, "admin/history.html", {
        "admin": admin, "rows": rows, "verdict": verdict, "page": page, "pages": max(1, -(-total // 50))})
