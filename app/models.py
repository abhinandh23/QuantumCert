"""Database tables. The trusted keystore is deliberately NOT here (see keys/trusted_keys.json)."""
from datetime import datetime, timezone

from sqlalchemy import ForeignKey, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


class Base(DeclarativeBase):
    pass


class AdminUser(Base):
    __tablename__ = "admin_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Certificate(Base):
    __tablename__ = "certificates"
    id: Mapped[int] = mapped_column(primary_key=True)
    cert_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    payload_canonical: Mapped[bytes] = mapped_column(LargeBinary)  # the exact signed bytes
    digest: Mapped[bytes] = mapped_column(LargeBinary(32))
    signature: Mapped[bytes] = mapped_column(LargeBinary)
    key_id: Mapped[str] = mapped_column(String(16))
    alg: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")  # ACTIVE | REVOKED
    # denormalised copies for search/listing only — never used for verification
    recipient_name: Mapped[str] = mapped_column(String(150), index=True)
    recipient_id: Mapped[str] = mapped_column(String(64), index=True)
    program: Mapped[str] = mapped_column(String(150))
    issue_date: Mapped[str] = mapped_column(String(10))
    expiry_date: Mapped[str | None] = mapped_column(String(10))
    created_by: Mapped[int | None] = mapped_column(ForeignKey("admin_users.id"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    revocation: Mapped["Revocation | None"] = relationship(back_populates="certificate", uselist=False)


class Revocation(Base):
    __tablename__ = "revocations"
    id: Mapped[int] = mapped_column(primary_key=True)
    cert_id: Mapped[str] = mapped_column(ForeignKey("certificates.cert_id"), unique=True)
    reason: Mapped[str] = mapped_column(Text)
    revoked_by: Mapped[int | None] = mapped_column(ForeignKey("admin_users.id"))
    revoked_at: Mapped[datetime] = mapped_column(default=utcnow)

    certificate: Mapped[Certificate] = relationship(back_populates="revocation")


class VerificationHistory(Base):
    __tablename__ = "verification_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    cert_id: Mapped[str | None] = mapped_column(String(64), index=True)
    method: Mapped[str] = mapped_column(String(8))  # PDF | QR | ID
    verdict: Mapped[str] = mapped_column(String(8))
    checks_json: Mapped[str] = mapped_column(Text)
    client_ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
