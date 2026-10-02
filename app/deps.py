"""Shared FastAPI dependencies: DB session, templates, admin auth, CSRF, upload limits."""
import hmac
import secrets
from pathlib import Path

from fastapi import Depends, Form, HTTPException, Request, UploadFile
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.models import AdminUser

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


class LoginRequired(Exception):
    pass


def get_db(request: Request):
    db = request.app.state.sessionmaker()
    try:
        yield db
    finally:
        db.close()


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = request.session["csrf"] = secrets.token_urlsafe(32)
    return token


templates.env.globals["csrf_token"] = csrf_token


def check_csrf(request: Request, csrf_token: str = Form("")) -> None:
    expected = request.session.get("csrf", "")
    if not expected or not hmac.compare_digest(expected, csrf_token):
        raise HTTPException(403, "CSRF token missing or invalid — reload the page and try again")


def current_admin(request: Request, db: Session = Depends(get_db)) -> AdminUser:
    admin_id = request.session.get("admin_id")
    admin = db.get(AdminUser, admin_id) if admin_id else None
    if admin is None:
        raise LoginRequired()
    return admin


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def read_limited(upload: UploadFile, limit: int) -> bytes:
    """Read at most limit+1 bytes, so oversize files are detected without buffering them fully."""
    chunks, total = [], 0
    while chunk := await upload.read(64 * 1024):
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            break
    return b"".join(chunks)[: limit + 1]
