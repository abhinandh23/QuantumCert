"""Admin login/logout: argon2id password hashes, session cookie, CSRF, simple throttle."""
import secrets
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.deps import check_csrf, client_ip, get_db, templates
from app.models import AdminUser

router = APIRouter(prefix="/admin")
hasher = PasswordHasher()
_DUMMY_HASH = hasher.hash(secrets.token_hex(16))

MAX_FAILURES, WINDOW_S = 5, 300
_failures: dict[str, deque] = defaultdict(deque)


def _throttled(ip: str) -> bool:
    q = _failures[ip]
    while q and q[0] < time.monotonic() - WINDOW_S:
        q.popleft()
    return len(q) >= MAX_FAILURES


@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(request, "admin/login.html", {"error": None})


@router.post("/login", dependencies=[Depends(check_csrf)])
def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    ip = client_ip(request) or "?"
    if _throttled(ip):
        return templates.TemplateResponse(request, "admin/login.html",
                                          {"error": "Too many failed attempts. Try again in a few minutes."},
                                          status_code=429)
    user = db.scalar(select(AdminUser).where(AdminUser.username == username.strip()))
    try:
        hasher.verify(user.password_hash if user else _DUMMY_HASH, password)  # constant-ish time either way
        ok = user is not None
    except VerificationError:
        ok = False
    if not ok:
        _failures[ip].append(time.monotonic())
        return templates.TemplateResponse(request, "admin/login.html",
                                          {"error": "Wrong username or password."}, status_code=401)
    _failures.pop(ip, None)
    request.session.clear()  # fresh session + fresh CSRF token on privilege change
    request.session["admin_id"] = user.id
    request.session["admin_name"] = user.username
    return RedirectResponse("/admin", status_code=303)


@router.post("/logout", dependencies=[Depends(check_csrf)])
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


def create_admin(db: Session, username: str, password: str) -> AdminUser:
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    if db.scalar(select(AdminUser).where(AdminUser.username == username)):
        raise ValueError(f"admin '{username}' already exists")
    user = AdminUser(username=username, password_hash=hasher.hash(password))
    db.add(user)
    db.commit()
    return user
