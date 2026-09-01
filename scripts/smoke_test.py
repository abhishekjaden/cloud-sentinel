#!/usr/bin/env python3
"""
Post-deploy smoke test.

Checks the deployed system from the outside, the way a browser meets it. This
exists because a deployment once shipped a config.json pointing at
http://localhost:8000: the build succeeded, every unit test passed, cdk-nag
reported nothing, and CI was green, yet the dashboard was entirely broken for
anyone who opened it. Unit tests verify components in isolation; this verifies
that the deployed pieces can actually reach each other.

Usage:
    python scripts/smoke_test.py
    python scripts/smoke_test.py --dashboard https://example.cloudfront.net
"""
import argparse
import json
import socket
import sys
from urllib.parse import urlparse

import requests

DEFAULT_DASHBOARD = "https://d2tb90osqfrb0m.cloudfront.net"
TIMEOUT = 15

failures: list[str] = []
checks = 0


def check(name: str, condition: bool, detail: str = "") -> bool:
    global checks
    checks += 1
    if condition:
        print(f"  PASS  {name}")
        return True
    print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""))
    failures.append(name)
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dashboard", default=DEFAULT_DASHBOARD)
    args = ap.parse_args()
    dashboard = args.dashboard.rstrip("/")

    print(f"\nSmoke testing {dashboard}\n")

    # --- the dashboard itself is served -----------------------------------
    print("Dashboard")
    try:
        r = requests.get(dashboard, timeout=TIMEOUT)
        check("root returns 200", r.status_code == 200, f"got {r.status_code}")
        check("root serves HTML", "text/html" in r.headers.get("content-type", ""),
              r.headers.get("content-type", "none"))
    except requests.RequestException as e:
        check("dashboard is reachable", False, str(e))
        return report()

    # --- runtime configuration --------------------------------------------
    print("\nRuntime configuration")
    api_url = None
    try:
        r = requests.get(f"{dashboard}/config.json", timeout=TIMEOUT)
        if check("config.json is served", r.status_code == 200, f"got {r.status_code}"):
            cfg = json.loads(r.text)
            api_url = (cfg.get("apiUrl") or "").rstrip("/")
            check("config.json declares apiUrl", bool(api_url), repr(cfg))

            host = urlparse(api_url).hostname or ""
            # The specific regression this script was written for.
            check("apiUrl is not a local address",
                  host not in ("localhost", "127.0.0.1", "0.0.0.0", "::1"),
                  f"apiUrl points at {host!r} — a developer config was deployed")
            check("apiUrl uses https", api_url.startswith("https://"), api_url)
    except (requests.RequestException, json.JSONDecodeError) as e:
        check("config.json is valid JSON", False, str(e))

    if not api_url or not api_url.startswith("https://"):
        print("\nSkipping API checks: no usable apiUrl.")
        return report()

    # --- the API the dashboard was told to use ----------------------------
    print(f"\nAPI at {api_url}")

    # The serving stack is deployed on demand and torn down between sessions.
    # A hostname that does not resolve means it is simply absent, which is not
    # the same as a deployed API that is failing — reporting them identically
    # would train the reader to ignore a red result.
    host = urlparse(api_url).hostname or ""
    try:
        socket.getaddrinfo(host, 443)
    except socket.gaierror:
        print(f"  SKIP  {host} does not resolve — the API stack is not deployed")
        print("        (deploy CloudSentinel-Api and re-run to check it)")
        return report()

    try:
        r = requests.get(f"{api_url}/health", timeout=TIMEOUT)
        check("health returns 200", r.status_code == 200, f"got {r.status_code}")
        check("health reports healthy",
              r.json().get("status") == "healthy", r.text[:120])
    except requests.RequestException as e:
        check("API is reachable at the configured URL", False, str(e))
        return report()

    # --- the security boundary, verified from outside ---------------------
    print("\nAuthorization")
    for path in ("/stats", "/findings", "/remediations", "/approvals"):
        try:
            r = requests.get(f"{api_url}{path}", timeout=TIMEOUT)
            check(f"{path} rejects unauthenticated callers",
                  r.status_code == 401, f"got {r.status_code}")
        except requests.RequestException as e:
            check(f"{path} is reachable", False, str(e))

    # --- the browser can actually call the API ----------------------------
    print("\nCross-origin access")
    try:
        r = requests.options(
            f"{api_url}/stats",
            headers={
                "Origin": dashboard,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            },
            timeout=TIMEOUT,
        )
        allowed = r.headers.get("access-control-allow-origin", "")
        check("preflight succeeds", r.status_code in (200, 204), f"got {r.status_code}")
        check("dashboard origin is allowed", allowed == dashboard,
              f"allow-origin is {allowed!r}")
        check("origin is not a wildcard", allowed != "*",
              "any site could issue credentialed requests")
    except requests.RequestException as e:
        check("preflight is reachable", False, str(e))

    return report()


def report() -> int:
    print(f"\n{'-' * 52}")
    if failures:
        print(f"{len(failures)} of {checks} checks failed:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"All {checks} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
