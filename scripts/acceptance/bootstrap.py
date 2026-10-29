#!/usr/bin/env python3
"""Prepares a fresh lab or CI server for the acceptance harness: signs in, creates a test customer (or reuses it) and
prints an enrolment token for its agents.

    python3 scripts/acceptance/bootstrap.py --server http://127.0.0.1:8080 --email admin@fenrir.local --password ...

Prints ``TOKEN=...`` and ``TENANT=...``, so a CI step can read them.
"""
from __future__ import annotations

import argparse
import sys
import time
import urllib.error

from fenrir_acceptance import Api, ApiError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--server", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--customer", default="Acceptance Lab")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--wait", type=float, default=90.0, help="seconds to wait for the server to start")
    args = parser.parse_args()
    api = Api(args.server, insecure=args.insecure)
    deadline = time.monotonic() + args.wait
    while True:
        try:
            api.login(args.email, args.password)
            break
        except (urllib.error.URLError, ConnectionError, ApiError) as exc:
            if time.monotonic() > deadline:
                print(f"Could not sign in to {args.server}: {exc}", file=sys.stderr)
                return 1
            time.sleep(2)
    tenant = next((t for t in api.get("tenants") if t.get("name") == args.customer), None)
    tenant = tenant or api.post("tenants", {"name": args.customer, "template": "balanced"})
    token = api.post("enrollment-tokens", {"tenantId": tenant["id"], "label": "acceptance"})["token"]
    print(f"TENANT={tenant['id']}")
    print(f"TOKEN={token}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
