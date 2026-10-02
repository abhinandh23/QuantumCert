"""Webcam scanner backend: frames like a laptop webcam would produce are decoded server-side."""
import io

import cv2
import numpy as np
import pytest

from app.core import qr

URL_HOST = "http://localhost:8000"


def webcam_frame(url: str, size: int, blur: float, contrast: float = 1.0, tilt: float = 0.0,
                 w: int = 1280, h: int = 720, seed: int = 0) -> bytes:
    """A QR of `size` px somewhere in a grey camera frame, optionally blurred / low-contrast /
    perspective-tilted, with sensor noise and JPEG compression."""
    rng = np.random.default_rng(seed)
    frame = np.full((h, w), 120, np.uint8)
    q = cv2.resize(np.asarray(qr.make_qr_image(url).convert("L")), (size, size), interpolation=cv2.INTER_AREA)
    q = (q.astype(float) * contrast + (1 - contrast) * 128).astype(np.uint8)
    if tilt:
        d = int(size * tilt)
        m = cv2.getPerspectiveTransform(np.float32([[0, 0], [size, 0], [size, size], [0, size]]),
                                        np.float32([[d, 0], [size - d // 2, d // 2], [size, size - d], [0, size]]))
        q = cv2.warpPerspective(q, m, (size, size), borderValue=120)
    x, y = (w - size) // 2 + int(rng.integers(-40, 40)), (h - size) // 2 + int(rng.integers(-40, 40))
    frame[y:y + size, x:x + size] = q
    if blur:
        frame = cv2.GaussianBlur(frame, (0, 0), blur)
    frame = np.clip(frame + rng.normal(0, 6, frame.shape), 0, 255).astype(np.uint8)
    return cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 80])[1].tobytes()


@pytest.mark.parametrize("size, blur, contrast, tilt", [
    (160, 0, 1.0, 0), (120, 1.0, 1.0, 0), (160, 1.5, 1.0, 0), (200, 1.2, 0.5, 0.08), (260, 2.0, 0.6, 0.05),
])
def test_scan_frame_decodes_realistic_webcam_frames(client, genuine, size, blur, contrast, tilt):
    jpg = webcam_frame(genuine.qr_url, size, blur, contrast, tilt)
    r = client.post("/verify/scan-frame", content=jpg, headers={"content-type": "image/jpeg"})
    body = r.json()
    assert r.status_code == 200 and body["found"] is True, body
    assert body["cert_id"] == genuine.payload["cert_id"]
    assert body["redirect"] == genuine.qr_url.replace("http://testserver", "")


def test_scan_frame_no_qr(client):
    blank = cv2.imencode(".jpg", np.full((720, 1280), 128, np.uint8))[1].tobytes()
    assert client.post("/verify/scan-frame", content=blank).json() == {"found": False}


def test_scan_frame_foreign_qr(client):
    jpg = webcam_frame("https://example.com/some/other/link", 200, 0)
    body = client.post("/verify/scan-frame", content=jpg).json()
    assert body["found"] is True and body["redirect"] is None and "not a QuantumCert" in body["message"]


def test_scan_frame_rejects_junk_and_oversize(client):
    assert client.post("/verify/scan-frame", content=b"not an image").status_code == 400
    assert client.post("/verify/scan-frame", content=b"\xff" * (3 * 1024 * 1024 + 1)).status_code == 413


def test_scan_frame_does_not_log_history(client, app, genuine):
    from sqlalchemy import func, select
    from app.models import VerificationHistory
    with app.state.sessionmaker() as db:
        before = db.scalar(select(func.count(VerificationHistory.id)))
        client.post("/verify/scan-frame", content=webcam_frame(genuine.qr_url, 200, 0))
        assert db.scalar(select(func.count(VerificationHistory.id))) == before


def test_pdf_qr_is_version_5_level_l(genuine):
    import qrcode
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
    q.add_data(genuine.qr_url.replace("http://testserver", URL_HOST))
    q.make(fit=True)
    assert q.version == 5
