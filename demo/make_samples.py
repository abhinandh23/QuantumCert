"""Create the live-demo samples: one genuine certificate and one forged PDF per attack.

    python -m demo.make_samples

Issues 3 real certificates into the configured database (genuine, to-be-revoked, expired) with the
real issuer key, revokes one, then runs every attack from demo/tamper.py. Output: demo/samples/*.pdf
and demo/samples/manifest.json (expected verdict per file). Upload any of them at /verify.
"""
import json
from pathlib import Path

from app.config import Settings
from app.core.payload import CertificateInput
from app.db import make_sessionmaker
from app.services import issuance
from demo.tamper import SCENARIOS, Genuine

OUT = Path(__file__).parent / "samples"


def _issue(db, signer, base_url, **over):
    data = dict(recipient_id="2023BCS0041", recipient_name="Asha Ménon",
                program="B.Tech Computer Science and Engineering", institution="Example Institute of Technology",
                issue_date="2026-06-30", grade="8.20", expiry_date=None)
    data.update(over)
    cert = issuance.issue_certificate(db, signer, CertificateInput(**data), None)
    return cert, Genuine(json.loads(cert.payload_canonical), cert.signature, base_url)


def main() -> int:
    s = Settings.from_env()
    signer = issuance.Signer(s.keys_dir, s.key_passphrase)
    if not signer.ready:
        raise SystemExit(f"cannot issue: {signer.error}")
    db = make_sessionmaker(s.db_url)()
    _, genuine = _issue(db, signer, s.base_url)
    rev_cert, revoked = _issue(db, signer, s.base_url, recipient_id="2023BCS0077", recipient_name="Ravi Kumar",
                               grade="7.45")
    issuance.revoke_certificate(db, rev_cert, "Issued in error — demo revocation", None)
    _, expired = _issue(db, signer, s.base_url, recipient_id="2021BCS0012", recipient_name="Meera Nair",
                        program="Certificate in Network Security", issue_date="2024-01-15",
                        expiry_date="2025-01-15", grade=None)
    certs = {None: genuine, "revoked": revoked, "expired": expired}

    OUT.mkdir(exist_ok=True)
    for old in OUT.glob("*.pdf"):
        old.unlink()
    manifest = []
    for sc in SCENARIOS:
        name = f"{sc.num}_{sc.slug}.pdf"
        (OUT / name).write_bytes(sc.make(certs[sc.needs]))
        manifest.append({"file": name, "attack": sc.attack, "expected": sc.verdict,
                         "must_fail": sorted(sc.must_fail), "cert_id": certs[sc.needs].payload["cert_id"]})
        print(f"  {name:38} {sc.attack}")
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\nwrote {len(manifest)} samples to {OUT}")
    print(f"genuine certificate: {genuine.payload['cert_id']}  (try it by ID at {s.base_url}/verify)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
