"""Create an issuer admin account:  python -m cli.create_admin <username>"""
import argparse
import getpass
import sys

from app.config import Settings
from app.db import make_sessionmaker
from app.routers.auth import create_admin


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m cli.create_admin")
    ap.add_argument("username")
    ap.add_argument("--password", help="(for scripts; otherwise prompted)")
    args = ap.parse_args(argv)
    password = args.password or getpass.getpass("Password (min 8 chars): ")
    if not args.password and password != getpass.getpass("Repeat password: "):
        sys.exit("passwords do not match")
    db = make_sessionmaker(Settings.from_env().db_url)()
    try:
        create_admin(db, args.username.strip(), password)
    except ValueError as e:
        sys.exit(str(e))
    print(f"admin '{args.username}' created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
