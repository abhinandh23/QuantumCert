"""FastAPI application factory.  Run:  uvicorn app.main:app --reload"""
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import Settings
from app.crypto.keys import Keystore, keystore_path
from app.db import make_sessionmaker
from app.deps import LoginRequired, templates
from app.routers import admin, api, auth, verify
from app.services.issuance import Signer

log = logging.getLogger("quantumcert")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data: blob:; media-src 'self' blob:; object-src 'none'; frame-ancestors 'none'; "
       "base-uri 'none'; form-action 'self'")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(title="QuantumCert", docs_url="/api/docs", redoc_url=None)
    app.state.settings = settings
    app.state.sessionmaker = make_sessionmaker(settings.db_url)
    app.state.keystore = Keystore.load(keystore_path(settings.keys_dir))
    app.state.signer = Signer(settings.keys_dir, settings.key_passphrase)
    if not app.state.keystore.keys:
        log.warning("trusted keystore is empty — run `python -m cli.keys generate`")
    if not app.state.signer.ready:
        log.warning("issuing disabled: %s", app.state.signer.error)

    app.add_middleware(SessionMiddleware, secret_key=settings.session_secret, session_cookie="qc_session",
                       max_age=8 * 3600, same_site="strict", https_only=settings.base_url.startswith("https"))

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(self)")
        return response

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired):
        return RedirectResponse("/admin/login", status_code=303)

    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
    templates.env.globals["base_url"] = settings.base_url
    for r in (verify.router, api.router, auth.router, admin.router):
        app.include_router(r)
    return app


def __getattr__(name):  # lazy `app` so importing this module (e.g. in tests) has no side effects
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
