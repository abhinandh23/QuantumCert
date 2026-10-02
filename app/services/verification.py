"""Glue between the pure verifier and the database: record lookup + verification history."""
import json
from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import verifier
from app.core.results import VerificationResult
from app.crypto.keys import Keystore
from app.models import Certificate, VerificationHistory


def db_lookup(db: Session) -> verifier.Lookup:
    def lookup(cert_id: str) -> verifier.Record | None:
        c = db.scalar(select(Certificate).where(Certificate.cert_id == cert_id))
        if c is None:
            return None
        rev = c.revocation
        return verifier.Record(
            cert_id=c.cert_id, payload_canonical=c.payload_canonical, digest=c.digest, signature=c.signature,
            key_id=c.key_id, status=c.status, revoked_reason=rev.reason if rev else None,
            revoked_at=rev.revoked_at.strftime("%Y-%m-%d %H:%M UTC") if rev else None)
    return lookup


def record_history(db: Session, res: VerificationResult, client_ip: str | None) -> None:
    checks = [{"key": c.key, "status": c.status, "reason": c.reason} for c in res.checks]
    db.add(VerificationHistory(cert_id=(res.cert_id or None) and res.cert_id[:64], method=res.method,
                               verdict=res.verdict, checks_json=json.dumps(checks), client_ip=client_ip))
    db.commit()


def verify_uploaded_pdf(db: Session, keystore: Keystore, data: bytes, *, client_ip: str | None = None,
                        expected_host: str | None = None, today: date | None = None,
                        max_bytes: int, max_pages: int) -> VerificationResult:
    res = verifier.verify_pdf(data, keystore, db_lookup(db), today=today, max_bytes=max_bytes,
                              max_pages=max_pages, expected_host=expected_host)
    record_history(db, res, client_ip)
    return res


def verify_by_id(db: Session, keystore: Keystore, cert_id: str, d: str | None, *, method: str,
                 client_ip: str | None = None, today: date | None = None) -> VerificationResult:
    res = verifier.verify_record(cert_id, d, keystore, db_lookup(db), today=today, method=method)
    record_history(db, res, client_ip)
    return res
