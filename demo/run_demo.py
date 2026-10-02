"""Verify every demo sample and print a verdict table (for the live presentation).

    python -m demo.run_demo              # online: uses the issuer database (revocation visible)
    python -m demo.run_demo --offline    # trusted public keys only, like cli/verify.py
"""
import argparse
import json
import textwrap
from pathlib import Path

from app.config import Settings
from app.core import verifier
from app.crypto.keys import Keystore, keystore_path
from app.db import make_sessionmaker
from app.services import verification

SAMPLES = Path(__file__).parent / "samples"
COLOR = {"VALID": "\033[32m", "INVALID": "\033[31m", "REVOKED": "\033[33m", "EXPIRED": "\033[33m",
         "UNKNOWN": "\033[90m"}
RESET = "\033[0m"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true", help="print the reason for each failed check")
    args = ap.parse_args()
    s = Settings.from_env()
    ks = Keystore.load(keystore_path(s.keys_dir))
    manifest = json.loads((SAMPLES / "manifest.json").read_text())
    db = make_sessionmaker(s.db_url)()

    print(f"{'sample':38} {'expected':9} {'got':9}  failed checks")
    print("-" * 100)
    all_ok = True
    for m in manifest:
        data = (SAMPLES / m["file"]).read_bytes()
        if args.offline:
            res = verifier.verify_pdf(data, ks, lookup=None)
            expected = "VALID" if m["expected"] == "REVOKED" else m["expected"]  # revocation is online-only
        else:
            res = verification.verify_uploaded_pdf(db, ks, data, client_ip="demo",
                                                   max_bytes=s.max_upload_bytes, max_pages=s.max_pages)
            expected = m["expected"]
        ok = res.verdict == expected
        all_ok &= ok
        mark = "✓" if ok else "✗ MISMATCH"
        print(f"{m['file']:38} {expected:9} {COLOR[res.verdict]}{res.verdict:9}{RESET}  "
              f"{', '.join(res.failed_checks()) or '—'}  {mark}")
        if args.verbose:
            for c in res.checks:
                if c.status == "FAIL":
                    print(textwrap.indent(textwrap.fill(f"{c.key}: {c.reason}", 96), "      "))
    print("-" * 100)
    print("ALL SAMPLES BEHAVED AS EXPECTED" if all_ok else "SOME SAMPLES DID NOT MATCH")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
