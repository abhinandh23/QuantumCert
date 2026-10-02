"""Canonical bytes, digest and encoding helpers. See docs/CANONICALIZATION.md."""
import base64
import hashlib
import re
import unicodedata

import rfc8785

_WS = re.compile(r"\s+")
# Bidi embedding/override/isolate controls enable visual spoofing ("Trojan Source"); reject them.
_BIDI_CONTROLS = set("‪‫‬‭‮⁦⁧⁨⁩")


def has_forbidden_chars(s: str) -> bool:
    return any(unicodedata.category(c) == "Cc" or c in _BIDI_CONTROLS for c in s)


def normalize_text(s: str) -> str:
    """Issuance-time normalisation: NFC, collapse whitespace runs to one space, trim."""
    return _WS.sub(" ", unicodedata.normalize("NFC", s)).strip()


def is_normalized(s: str) -> bool:
    return normalize_text(s) == s


def canonical_bytes(payload: dict) -> bytes:
    """RFC 8785 (JCS): keys sorted, no insignificant whitespace, UTF-8.

    The payload only ever contains strings, the integer schema_version and null,
    so JCS number serialisation never comes into play.
    """
    return rfc8785.dumps(payload)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
