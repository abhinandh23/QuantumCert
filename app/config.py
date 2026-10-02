"""Runtime settings, read from environment variables (and an optional .env file)."""
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
# Certificates are exactly one page. Extra pages would not be covered by the printed-text and overlay
# checks (which inspect page 1), so a forged page could be appended to a genuine certificate.
MAX_PDF_PAGES = 1


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines; real environment variables win."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Settings:
    base_url: str = "http://localhost:8000"
    db_url: str = f"sqlite:///{PROJECT_ROOT / 'quantumcert.db'}"
    keys_dir: Path = PROJECT_ROOT / "keys"
    key_passphrase: str | None = None
    session_secret: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    max_upload_bytes: int = MAX_UPLOAD_BYTES
    max_pages: int = MAX_PDF_PAGES

    @classmethod
    def from_env(cls) -> "Settings":
        _load_dotenv(PROJECT_ROOT / ".env")
        env = os.environ
        kwargs = {}
        if "QC_BASE_URL" in env:
            kwargs["base_url"] = env["QC_BASE_URL"].rstrip("/")
        if "QC_DB_URL" in env:
            kwargs["db_url"] = env["QC_DB_URL"]
        if "QC_KEYS_DIR" in env:
            p = Path(env["QC_KEYS_DIR"])
            kwargs["keys_dir"] = p if p.is_absolute() else PROJECT_ROOT / p
        if env.get("QC_KEY_PASSPHRASE"):
            kwargs["key_passphrase"] = env["QC_KEY_PASSPHRASE"]
        if env.get("QC_SESSION_SECRET"):
            kwargs["session_secret"] = env["QC_SESSION_SECRET"]
        return cls(**kwargs)
