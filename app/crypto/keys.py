"""Issuer keys: key_id, encrypted private key files, and the trusted public keystore.

Layout under keys_dir:
    trusted_keys.json          trust anchor: public keys only (safe to publish)
    private/<key_id>.sk.json   SLH-DSA secret key, scrypt + AES-256-GCM encrypted (gitignored)
"""
import base64
import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from app.crypto import slhdsa

KEYSTORE_FILE = "trusted_keys.json"
PRIVATE_DIR = "private"
PUB_HEADER = f"-----BEGIN {slhdsa.ALG} PUBLIC KEY-----"
PUB_FOOTER = f"-----END {slhdsa.ALG} PUBLIC KEY-----"

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1


class KeyError_(Exception):
    """Problem loading or decrypting a key."""


def key_id_for(public_key: bytes) -> str:
    """First 16 hex chars of SHA-256(pk). A lookup handle only; trust comes from the keystore."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------- private key encryption

def _aad(key_id: str, alg: str) -> bytes:
    return f"QuantumCert-sk|{key_id}|{alg}".encode()


def _kek(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode())


def encrypt_secret_key(sk: bytes, passphrase: str, key_id: str, alg: str = slhdsa.ALG) -> dict:
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    ct = AESGCM(_kek(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)).encrypt(nonce, sk, _aad(key_id, alg))
    b64 = lambda b: base64.b64encode(b).decode()
    return {"key_id": key_id, "alg": alg, "kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
            "salt": b64(salt), "cipher": "AES-256-GCM", "nonce": b64(nonce), "ct": b64(ct)}


def decrypt_secret_key(blob: dict, passphrase: str) -> bytes:
    try:
        kek = _kek(passphrase, base64.b64decode(blob["salt"]), blob["n"], blob["r"], blob["p"])
        return AESGCM(kek).decrypt(base64.b64decode(blob["nonce"]), base64.b64decode(blob["ct"]),
                                   _aad(blob["key_id"], blob["alg"]))
    except Exception as e:  # InvalidTag, missing fields, bad base64
        raise KeyError_("could not decrypt issuer private key (wrong passphrase or corrupted file)") from e


# ---------------------------------------------------------------- public key files

def encode_public_key(pk: bytes) -> str:
    return f"{PUB_HEADER}\n{base64.b64encode(pk).decode()}\n{PUB_FOOTER}\n"


def decode_public_key(text: str | bytes) -> bytes:
    """Accept the armored .pub format, bare base64, or raw 32 bytes."""
    if isinstance(text, bytes):
        if len(text) == slhdsa.PUBLIC_KEY_SIZE:
            return text
        text = text.decode("ascii", errors="strict")
    body = "".join(l for l in text.strip().splitlines() if not l.startswith("-----"))
    pk = base64.b64decode(body, validate=True)
    if len(pk) != slhdsa.PUBLIC_KEY_SIZE:
        raise KeyError_(f"public key must be {slhdsa.PUBLIC_KEY_SIZE} bytes, got {len(pk)}")
    return pk


# ---------------------------------------------------------------- trusted keystore

@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    alg: str
    public_key: bytes
    status: str  # ACTIVE | RETIRED
    created_at: str
    retired_at: str | None = None


class Keystore:
    """Trusted public keys keyed by key_id. Verification uses ONLY keys from here."""

    def __init__(self, keys: dict[str, TrustedKey] | None = None, path: Path | None = None):
        self.keys = dict(keys or {})
        self.path = path

    @classmethod
    def load(cls, path: Path) -> "Keystore":
        if not path.exists():
            return cls({}, path)
        raw = json.loads(path.read_text())
        keys = {}
        for kid, k in raw.get("keys", {}).items():
            pk = base64.b64decode(k["public_key"])
            if key_id_for(pk) != kid:
                raise KeyError_(f"keystore entry {kid} does not match its public key")
            keys[kid] = TrustedKey(kid, k["alg"], pk, k["status"], k["created_at"], k.get("retired_at"))
        return cls(keys, path)

    @classmethod
    def from_public_key(cls, pk: bytes) -> "Keystore":
        kid = key_id_for(pk)
        return cls({kid: TrustedKey(kid, slhdsa.ALG, pk, "ACTIVE", _now())})

    def save(self) -> None:
        data = {"comment": "QuantumCert trusted issuer public keys. Retired keys stay so old certificates verify.",
                "keys": {k.key_id: {"alg": k.alg, "public_key": base64.b64encode(k.public_key).decode(),
                                    "status": k.status, "created_at": k.created_at, "retired_at": k.retired_at}
                         for k in self.keys.values()}}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2) + "\n")

    def get(self, key_id: str) -> TrustedKey | None:
        return self.keys.get(key_id)

    def active(self) -> TrustedKey | None:
        return next((k for k in self.keys.values() if k.status == "ACTIVE"), None)


# ---------------------------------------------------------------- key lifecycle

def keystore_path(keys_dir: Path) -> Path:
    return keys_dir / KEYSTORE_FILE


def private_key_path(keys_dir: Path, key_id: str) -> Path:
    return keys_dir / PRIVATE_DIR / f"{key_id}.sk.json"


def generate_issuer_key(keys_dir: Path, passphrase: str) -> str:
    """Create a new key pair, make it the ACTIVE key and retire any previous active key."""
    if not passphrase:
        raise KeyError_("a passphrase is required to encrypt the private key")
    pk, sk = slhdsa.keygen()
    kid = key_id_for(pk)
    priv = private_key_path(keys_dir, kid)
    priv.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(priv.parent, 0o700)
    fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(encrypt_secret_key(sk, passphrase, kid), f, indent=2)

    ks = Keystore.load(keystore_path(keys_dir))
    for old in list(ks.keys.values()):
        if old.status == "ACTIVE":
            ks.keys[old.key_id] = TrustedKey(old.key_id, old.alg, old.public_key, "RETIRED", old.created_at, _now())
    ks.keys[kid] = TrustedKey(kid, slhdsa.ALG, pk, "ACTIVE", _now())
    ks.save()
    return kid


def load_signing_key(keys_dir: Path, passphrase: str) -> tuple[str, bytes]:
    """Return (key_id, sk) for the ACTIVE key, checking sk matches the trusted public key."""
    ks = Keystore.load(keystore_path(keys_dir))
    active = ks.active()
    if active is None:
        raise KeyError_("no ACTIVE issuer key; run `python -m cli.keys generate`")
    priv = private_key_path(keys_dir, active.key_id)
    if not priv.exists():
        raise KeyError_(f"private key file for {active.key_id} not found")
    sk = decrypt_secret_key(json.loads(priv.read_text()), passphrase)
    # FIPS 205 sk = SK.seed || SK.prf || PK.seed || PK.root; its last 32 bytes are the public key.
    if sk[-slhdsa.PUBLIC_KEY_SIZE:] != active.public_key:
        raise KeyError_("private key does not match the trusted public key")
    return active.key_id, sk
