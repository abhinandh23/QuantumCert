"""Verification result model: per-check PASS/FAIL/NOT_APPLICABLE plus an overall verdict.

Cryptographic validity (the signature) is reported separately from certificate status
(revoked / expired), so a revoked certificate can still show "signature valid".
"""
from dataclasses import asdict, dataclass, field

PASS, FAIL, NA = "PASS", "FAIL", "NOT_APPLICABLE"
VALID, INVALID, REVOKED, EXPIRED, UNKNOWN = "VALID", "INVALID", "REVOKED", "EXPIRED", "UNKNOWN"

VERDICT_TEXT = {
    VALID: "Genuine certificate, issued by a trusted key, not revoked and not expired.",
    INVALID: "This certificate failed an integrity, authenticity or format check. Do not trust it.",
    REVOKED: "The certificate was genuinely issued but has since been revoked by the issuer.",
    EXPIRED: "The certificate was genuinely issued but its validity period has ended.",
    UNKNOWN: "No certificate with this ID exists in the issuer's records.",
}

# checks whose failure means the document itself cannot be trusted
STATUS_CHECKS = {"status", "expiry"}


@dataclass
class Check:
    key: str
    title: str
    status: str = NA
    reason: str = ""

    def passed(self, reason: str) -> "Check":
        self.status, self.reason = PASS, reason
        return self

    def failed(self, reason: str) -> "Check":
        self.status, self.reason = FAIL, reason
        return self

    def skipped(self, reason: str) -> "Check":
        self.status, self.reason = NA, reason
        return self


@dataclass
class VerificationResult:
    method: str                      # PDF | QR | ID | OFFLINE
    checks: list[Check]
    verdict: str = INVALID
    cert_id: str | None = None
    payload: dict | None = None      # the signed data to show (only set when its signature verified)
    key_id: str | None = None
    signature_valid: bool | None = None
    record_found: bool | None = None
    cert_status: str | None = None   # ACTIVE | REVOKED (from the issuer database)
    revocation: dict | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def verdict_text(self) -> str:
        return VERDICT_TEXT[self.verdict]

    def check(self, key: str) -> Check:
        return next(c for c in self.checks if c.key == key)

    def failed_checks(self) -> list[str]:
        return [c.key for c in self.checks if c.status == FAIL]

    def decide(self, online: bool) -> str:
        """INVALID > UNKNOWN > REVOKED > EXPIRED > VALID."""
        failed = set(self.failed_checks())
        not_found = online and self.record_found is False
        hard = failed - STATUS_CHECKS - ({"record"} if not_found else set())
        if hard:
            self.verdict = INVALID
        elif not_found:
            self.verdict = UNKNOWN
        elif "status" in failed:
            self.verdict = REVOKED
        elif "expiry" in failed:
            self.verdict = EXPIRED
        else:
            self.verdict = VALID
        return self.verdict

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict_text"] = self.verdict_text
        return d
