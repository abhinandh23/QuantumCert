"""Issuing and revoking certificates. The only place the issuer private key is used."""
import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import pdfgen
from app.core.canonical import canonical_bytes, digest
from app.core.payload import CertificateInput, build_payload, new_cert_id
from app.crypto import keys, slhdsa
from app.models import Certificate, Revocation, utcnow


class IssuanceError(Exception):
    pass


class Signer:
    """Holds the decrypted ACTIVE issuer key in memory. Never serialised, logged or returned."""

    def __init__(self, keys_dir: Path, passphrase: str | None):
        self.key_id: str | None = None
        self._sk: bytes | None = None
        self.error: str | None = None
        if not passphrase:
            self.error = "QC_KEY_PASSPHRASE is not set — issuing is disabled (verification still works)"
            return
        try:
            self.key_id, self._sk = keys.load_signing_key(keys_dir, passphrase)
        except keys.KeyError_ as e:
            self.error = str(e)

    @property
    def ready(self) -> bool:
        return self._sk is not None

    def sign(self, message: bytes) -> bytes:
        if self._sk is None:
            raise IssuanceError(self.error or "no signing key")
        return slhdsa.sign(self._sk, message)

    def __repr__(self) -> str:
        return f"<Signer key_id={self.key_id} ready={self.ready}>"


def issue_certificate(db: Session, signer: Signer, inp: CertificateInput, admin_id: int | None) -> Certificate:
    """Validate → canonical payload → SHA-256 → SLH-DSA sign → store (brief §3, steps 2-4)."""
    if not signer.ready:
        raise IssuanceError(signer.error or "issuer key not loaded")
    cert_id = new_cert_id()
    while db.scalar(select(Certificate.id).where(Certificate.cert_id == cert_id)):
        cert_id = new_cert_id()
    payload = build_payload(inp, cert_id, signer.key_id)  # raises PayloadError
    cbytes = canonical_bytes(payload)
    cert = Certificate(
        cert_id=cert_id, payload_canonical=cbytes, digest=digest(cbytes), signature=signer.sign(cbytes),
        key_id=signer.key_id, alg=slhdsa.ALG, status="ACTIVE",
        recipient_name=payload["recipient_name"], recipient_id=payload["recipient_id"],
        program=payload["program"], issue_date=payload["issue_date"], expiry_date=payload["expiry_date"],
        created_by=admin_id)
    db.add(cert)
    db.commit()
    return cert


def certificate_pdf(cert: Certificate, base_url: str) -> bytes:
    """(Re)generate the PDF from the stored record; PDFs themselves are not stored."""
    return pdfgen.render_certificate(json.loads(cert.payload_canonical), cert.signature, base_url)


def revoke_certificate(db: Session, cert: Certificate, reason: str, admin_id: int | None) -> None:
    reason = (reason or "").strip()
    if not reason:
        raise IssuanceError("a revocation reason is required")
    if cert.status == "REVOKED":
        raise IssuanceError("certificate is already revoked")
    cert.status = "REVOKED"
    db.add(Revocation(cert_id=cert.cert_id, reason=reason[:500], revoked_by=admin_id, revoked_at=utcnow()))
    db.commit()
