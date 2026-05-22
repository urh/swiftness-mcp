#!/usr/bin/env python3
"""Dump Swiftness pension/gemel/keren-hishtalmut balances."""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
from pathlib import Path

from swiftness_mcp.client import SwiftnessError, load_credentials, pull_savings


def _snapshot_to_dict(s) -> dict:
    d = dataclasses.asdict(s)
    d.pop("xml", None)
    return d


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pretty", action="store_true")
    p.add_argument("--user", help="only pull this user label")
    p.add_argument("--otp", help="pre-provided OTP code")
    p.add_argument("--xml-out", type=Path, help="write consolidated portfolio XML")
    p.add_argument("--cred-path", type=Path, help="alternate credentials path")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        cfg = load_credentials(args.cred_path)
    except (SwiftnessError, FileNotFoundError, OSError) as e:
        sys.stderr.write(f"swiftness: cannot load credentials: {e}\n")
        return 2

    users = cfg["users"]
    if args.user:
        users = [u for u in users if u.get("label") == args.user]
        if not users:
            sys.stderr.write(f"swiftness: no user with label {args.user!r}\n")
            return 2

    if args.otp and len(users) > 1:
        sys.stderr.write("swiftness: --otp requires a single --user\n")
        return 2

    fetch_xml = args.xml_out is not None
    results = []
    for u in users:
        try:
            snap = pull_savings(
                user_label=u["label"],
                id_number=u["id_number"],
                email=u["email"],
                otp=args.otp,
                gmail_token_path=Path(
                    u.get("gmail_token_path")
                    or str(Path.home() / ".config" / "gmail-mcp" / "credentials.json")
                ),
                gmail_oauth_path=Path(
                    u.get("gmail_oauth_path")
                    or str(Path.home() / ".config" / "gmail-mcp" / "gcp-oauth.keys.json")
                ),
                fetch_xml=fetch_xml,
            )
        except Exception as e:
            results.append({"user_label": u.get("label"), "error": str(e)})
            continue

        if fetch_xml and snap.xml is not None:
            out_path = args.xml_out
            if len(users) > 1:
                out_path = args.xml_out.with_name(
                    args.xml_out.stem + f".{u['label']}" + args.xml_out.suffix
                )
            out_path.write_text(snap.xml, encoding="utf-8")

        results.append(_snapshot_to_dict(snap))

    json.dump(results, sys.stdout, ensure_ascii=False, indent=2 if args.pretty else None)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
