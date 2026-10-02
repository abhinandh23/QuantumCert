"""Issuer key management.

    python -m cli.keys generate          # first key (needs QC_KEY_PASSPHRASE)
    python -m cli.keys rotate            # new ACTIVE key; old one RETIRED but still trusted
    python -m cli.keys list
    python -m cli.keys export-public [--out keys/issuer.pub] [--key-id ID]
"""
import argparse
import getpass
import sys

from app.config import Settings
from app.crypto import keys


def _passphrase(settings: Settings) -> str:
    if settings.key_passphrase:
        return settings.key_passphrase
    p1 = getpass.getpass("Passphrase to encrypt the issuer private key: ")
    if p1 != getpass.getpass("Repeat passphrase: "):
        sys.exit("passphrases do not match")
    return p1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m cli.keys", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate")
    sub.add_parser("rotate")
    sub.add_parser("list")
    exp = sub.add_parser("export-public")
    exp.add_argument("--out", default=None)
    exp.add_argument("--key-id", default=None)
    args = ap.parse_args(argv)
    s = Settings.from_env()
    ks = keys.Keystore.load(keys.keystore_path(s.keys_dir))

    if args.cmd in ("generate", "rotate"):
        if args.cmd == "generate" and ks.active():
            sys.exit(f"an ACTIVE key ({ks.active().key_id}) already exists; use `rotate` to replace it")
        kid = keys.generate_issuer_key(s.keys_dir, _passphrase(s))
        print(f"new ACTIVE issuer key {kid}")
        print(f"  public : {keys.keystore_path(s.keys_dir)}")
        print(f"  private: {keys.private_key_path(s.keys_dir, kid)} (encrypted, gitignored)")
        pub = s.keys_dir / "issuer.pub"
        pub.write_text(keys.encode_public_key(ks_pk(s, kid)))
        print(f"  exported public key to {pub}")
    elif args.cmd == "list":
        for k in ks.keys.values():
            print(f"{k.key_id}  {k.alg}  {k.status:8}  created {k.created_at}"
                  + (f"  retired {k.retired_at}" if k.retired_at else ""))
        if not ks.keys:
            print("(keystore empty)")
    elif args.cmd == "export-public":
        k = ks.get(args.key_id) if args.key_id else ks.active()
        if k is None:
            sys.exit("no such key")
        out = keys.encode_public_key(k.public_key)
        if args.out:
            open(args.out, "w").write(out)
            print(f"wrote {args.out} ({k.key_id})")
        else:
            print(out, end="")
    return 0


def ks_pk(s: Settings, kid: str) -> bytes:
    return keys.Keystore.load(keys.keystore_path(s.keys_dir)).get(kid).public_key


if __name__ == "__main__":
    raise SystemExit(main())
