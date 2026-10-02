import json

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.core.payload import CertificateInput
from app.crypto import keys
from app.main import create_app
from app.routers.auth import create_admin
from app.services import issuance
from demo.tamper import Genuine

PASSPHRASE = "test-passphrase-123"
BASE_URL = "http://testserver"
ADMIN_USER, ADMIN_PASS = "registrar", "correct horse battery"


@pytest.fixture(scope="session")
def settings(tmp_path_factory) -> Settings:
    root = tmp_path_factory.mktemp("qc")
    keys.generate_issuer_key(root / "keys", PASSPHRASE)
    return Settings(base_url=BASE_URL, db_url=f"sqlite:///{root / 'test.db'}", keys_dir=root / "keys",
                    key_passphrase=PASSPHRASE, session_secret="test-session-secret")


@pytest.fixture(scope="session")
def app(settings):
    app = create_app(settings)
    with app.state.sessionmaker() as db:
        create_admin(db, ADMIN_USER, ADMIN_PASS)
    return app


@pytest.fixture(scope="session")
def keystore(app):
    return app.state.keystore


@pytest.fixture
def db(app):
    with app.state.sessionmaker() as s:
        yield s


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin_client(client):
    csrf = csrf_from(client.get("/admin/login").text)
    r = client.post("/admin/login", data={"username": ADMIN_USER, "password": ADMIN_PASS, "csrf_token": csrf},
                    follow_redirects=False)
    assert r.status_code == 303, r.text
    return client


def csrf_from(html: str) -> str:
    return html.split('name="csrf_token" value="')[1].split('"')[0]


def sample_input(**over) -> CertificateInput:
    base = dict(recipient_id="2023BCS0041", recipient_name="Asha Ménon",
                program="B.Tech Computer Science and Engineering", institution="Example Institute of Technology",
                issue_date="2026-06-30", grade="8.20", expiry_date=None)
    base.update(over)
    return CertificateInput(**base)


def issue(app, **over):
    with app.state.sessionmaker() as db:
        cert = issuance.issue_certificate(db, app.state.signer, sample_input(**over), None)
        return cert, Genuine(json.loads(cert.payload_canonical), cert.signature, BASE_URL)


@pytest.fixture(scope="session")
def genuine(app) -> Genuine:
    return issue(app)[1]
