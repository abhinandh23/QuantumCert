"""Offline verifier — no server, no database. Trust rests only on the public key you supply.

    python -m cli.verify cert.pdf --pubkey keys/issuer.pub
    python -m cli.verify cert.pdf --keystore keys/trusted_keys.json

Runs checks 1-6 (format, QR, embedded data, printed text, digest, signature) plus expiry.
Revocation CANNOT be checked offline; use the website for that.
Exit code 0 = VALID, 1 = anything else.
"""
import argparse
import sys
from pathlib import Path

from app.core.results import FAIL, PASS, VALID
from app.core.verifier import verify_pdf
from app.crypto import keys

SYMBOL = {PASS: "PASS", FAIL: "FAIL", "NOT_APPLICABLE": " N/A"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m cli.verify", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pdf", type=Path)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--pubkey", type=Path, help="issuer public key (.pub, base64 or raw 32 bytes)")
    g.add_argument("--keystore", type=Path, help="trusted_keys.json")
    args = ap.parse_args(argv)

    try:
        if args.pubkey:
            raw = args.pubkey.read_bytes()
            ks = keys.Keystore.from_public_key(keys.decode_public_key(raw if len(raw) == 32 else raw.decode()))
        else:
            ks = keys.Keystore.load(args.keystore)
        data = args.pdf.read_bytes()
    except (OSError, ValueError, keys.KeyError_) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    res = verify_pdf(data, ks, lookup=None, max_bytes=5 * 1024 * 1024)
    print(f"QuantumCert offline verification of {args.pdf}")
    print(f"trusted key(s): {', '.join(ks.keys) or '(none)'}\n")
    for c in res.checks:
        print(f"  [{SYMBOL[c.status]}] {c.title}")
        if c.reason:
            print(f"         {c.reason}")
    if res.payload:
        p = res.payload
        print(f"\n  Signed data: {p['recipient_name']} ({p['recipient_id']}) — {p['program']}, {p['institution']};"
              f" CGPA {p['grade'] or 'n/a'}; issued {p['issue_date']}; cert {p['cert_id']}")
    text = ("Genuine and unmodified: signed by the trusted issuer key and in date." if res.verdict == VALID
            else res.verdict_text)
    print(f"\nVERDICT: {res.verdict} — {text}")
    print("NOTE: revocation status was not checked (offline). Check online for revocation.")
    return 0 if res.verdict == VALID else 1


if __name__ == "__main__":
    raise SystemExit(main())
