"""HTTP layer: auth, CSRF, issue → download → verify → revoke, history, and no private-key leaks."""
import re

import pytest

from app.crypto import keys
from demo.tamper import edit_visible_regenerate, not_a_pdf, oversized_pdf
from tests.conftest import ADMIN_PASS, ADMIN_USER, PASSPHRASE, csrf_from

ADMIN_PAGES = ["/admin", "/admin/certificates/new", "/admin/history"]


@pytest.mark.parametrize("path", ADMIN_PAGES)
def test_admin_pages_require_login(client, path):
    r = client.get(path, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/admin/login"


def test_admin_posts_require_login(client):
    csrf = csrf_from(client.get("/admin/login").text)
    r = client.post("/admin/certificates/new", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/admin/login"


def test_wrong_password(client):
    csrf = csrf_from(client.get("/admin/login").text)
    r = client.post("/admin/login", data={"username": ADMIN_USER, "password": "nope", "csrf_token": csrf})
    assert r.status_code == 401


def test_login_requires_csrf(client):
    client.get("/admin/login")
    r = client.post("/admin/login", data={"username": ADMIN_USER, "password": ADMIN_PASS})
    assert r.status_code == 403


def test_full_issue_download_verify_revoke_flow(admin_client):
    c = admin_client
    csrf = csrf_from(c.get("/admin/certificates/new").text)

    # CSRF is enforced on issuance
    assert c.post("/admin/certificates/new", data={"recipient_name": "x", "csrf_token": "bad"}).status_code == 403

    # validation errors are shown, not 500s
    r = c.post("/admin/certificates/new", data={"csrf_token": csrf, "recipient_name": "Anu", "recipient_id": "R1",
                                                 "program": "BSc", "institution": "EIT", "issue_date": "2026-13-45"})
    assert r.status_code == 422 and "calendar date" in r.text

    r = c.post("/admin/certificates/new", follow_redirects=False, data={
        "csrf_token": csrf, "recipient_name": "  Anu  Thomas ", "recipient_id": "2023BCS0099",
        "program": "B.Tech Electronics", "institution": "Example Institute of Technology",
        "grade": "9.1", "issue_date": "2026-07-01", "expiry_date": ""})
    assert r.status_code == 303
    cert_id = re.search(r"/admin/certificates/(QC-[0-9A-Z]{12})", r.headers["location"]).group(1)

    detail = c.get(f"/admin/certificates/{cert_id}")
    assert "Anu Thomas" in detail.text and "9.10" in detail.text
    assert c.get(f"/admin/certificates/{cert_id}/preview.png").headers["content-type"] == "image/png"
    pdf = c.get(f"/admin/certificates/{cert_id}/pdf")
    assert pdf.headers["content-type"] == "application/pdf" and pdf.content.startswith(b"%PDF-")

    # public verification (no login needed — use the API)
    r = c.post("/api/verify/pdf", files={"file": ("cert.pdf", pdf.content, "application/pdf")})
    assert r.status_code == 200 and r.json()["verdict"] == "VALID"
    assert c.get(f"/api/verify/{cert_id}").json()["verdict"] == "VALID"
    html = c.post("/verify/pdf", files={"file": ("cert.pdf", pdf.content, "application/pdf")})
    assert "VALID" in html.text and "Anu Thomas" in html.text

    # revoke: reason required, then REVOKED with signature still valid
    assert c.post(f"/admin/certificates/{cert_id}/revoke", data={"csrf_token": csrf, "reason": " "}).status_code == 400
    r = c.post(f"/admin/certificates/{cert_id}/revoke", data={"csrf_token": csrf, "reason": "Duplicate"},
               follow_redirects=False)
    assert r.status_code == 303
    j = c.post("/api/verify/pdf", files={"file": ("cert.pdf", pdf.content, "application/pdf")}).json()
    assert j["verdict"] == "REVOKED" and j["signature_valid"] is True
    assert j["revocation"]["reason"] == "Duplicate"

    # history recorded every attempt, visible to admin
    hist = c.get("/admin/history").text
    assert cert_id in hist and "REVOKED" in hist
    assert "Search" in c.get("/admin?q=Anu&status=revoked").text and cert_id in c.get("/admin?q=Anu").text


def test_public_pages_and_bad_uploads(client, genuine):
    assert client.get("/").status_code == 200
    assert "webcam" in client.get("/verify").text
    r = client.post("/verify/pdf", files={"file": ("x.pdf", not_a_pdf(genuine), "application/pdf")})
    assert r.status_code == 400 and "not a PDF" in r.text
    r = client.post("/api/verify/pdf", files={"file": ("x.pdf", oversized_pdf(genuine), "application/pdf")})
    assert r.status_code == 413 and r.json()["verdict"] == "INVALID"
    r = client.post("/api/verify/pdf", files={"file": ("x.pdf", b"", "application/pdf")})
    assert r.status_code == 400
    r = client.post("/api/verify/pdf", files={"file": ("x.pdf", edit_visible_regenerate(genuine), "application/pdf")})
    assert r.json()["verdict"] == "INVALID" and "visible" in [c["key"] for c in r.json()["checks"] if c["status"] == "FAIL"]


def test_verify_by_id_form_and_qr_link(client, genuine):
    r = client.post("/verify/id", data={"cert_id": genuine.payload["cert_id"].lower()}, follow_redirects=False)
    assert r.headers["location"] == f"/verify/{genuine.payload['cert_id']}"
    page = client.get(genuine.qr_url.replace("http://testserver", ""))
    assert page.status_code == 200 and "VALID" in page.text and "record is genuine" in page.text
    assert "UNKNOWN" in client.get("/verify/QC-000000000000").text


def test_qr_image_upload_fallback(client, genuine):
    import io
    from app.core import qr
    buf = io.BytesIO()
    qr.make_qr_image(genuine.qr_url).save(buf, "PNG")
    r = client.post("/verify/qr-image", files={"file": ("qr.png", buf.getvalue(), "image/png")},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith(f"/verify/{genuine.payload['cert_id']}?d=")
    r = client.post("/verify/qr-image", files={"file": ("x.png", b"not an image", "image/png")},
                    follow_redirects=False)
    assert r.status_code == 303 and "error=" in r.headers["location"]


def test_security_headers(client):
    h = client.get("/verify").headers
    assert "script-src 'self'" in h["content-security-policy"]
    assert h["x-frame-options"] == "DENY"


def test_no_endpoint_leaks_private_key(app, admin_client, genuine, settings):
    """Route-table audit + response scan: the secret key never leaves the server."""
    _, sk = keys.load_signing_key(settings.keys_dir, PASSPHRASE)
    secrets_ = [sk.hex(), sk[:32].hex(), __import__("base64").b64encode(sk).decode()]
    paths = {r.path for r in app.routes if hasattr(r, "path")}
    assert not any(re.search(r"private|secret|\bsk\b", p) for p in paths)
    cert_id = genuine.payload["cert_id"]
    for path in ["/", "/verify", "/api/keys", f"/api/verify/{cert_id}", f"/verify/{cert_id}", "/admin",
                 f"/admin/certificates/{cert_id}", "/admin/history", "/api/docs", "/openapi.json"]:
        body = admin_client.get(path).text
        assert not any(s in body for s in secrets_), path
    # keys dir is not served as static files
    kid = genuine.payload["issuer_key_id"]
    assert admin_client.get(f"/static/../keys/private/{kid}.sk.json").status_code == 404
    pub = admin_client.get("/api/keys").json()["keys"]
    assert [k["key_id"] for k in pub] == [kid] and set(pub[0]) >= {"public_key", "alg", "status"}
