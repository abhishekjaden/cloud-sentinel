#!/usr/bin/env python3
"""
Visit the honeypot's lure page from time to time, and keep a log of the
addresses the visits came from.

The honeypot's third run captures every packet header that reaches it, and
the flows are labelled by who began them (docs/generalization-protocol.md,
section 3): the operator's visits are the one kind of benign traffic from the
internet the capture will hold. This script makes those visits — a GET of the
lure page every so often, at irregular intervals — and writes one JSON line
per visit with the time, the public address it was made from (asked of
checkip.amazonaws.com just before), the status and the round trip. The log is
committed with the flows, and scripts/pcap_flows.py --visits reads the
addresses from it.

    python scripts/honeypot_visit.py http://203.0.113.9/ --log docs/honeypot-visits-2026-11.jsonl
    python scripts/honeypot_visit.py http://203.0.113.9/ --once --log docs/honeypot-visits-2026-11.jsonl

Leave it running in a terminal while the laptop is on; stop it with Ctrl-C.
A visit from a network the operator does not usually use (a phone's
hotspot, the college) is still a visit — the address is in the log either
way, which is the point of logging it rather than listing addresses by hand.
"""
import argparse
import json
import random
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CHECK_IP = "https://checkip.amazonaws.com"


def public_ip(opener=urllib.request.urlopen, timeout=10):
    with opener(CHECK_IP, timeout=timeout) as resp:
        return resp.read().decode("ascii").strip()


def visit(url, opener=urllib.request.urlopen, timeout=10):
    """One GET; the status, or the error, and how long it took."""
    started = time.monotonic()
    req = urllib.request.Request(url, headers={"User-Agent": "cloudsentinel-operator-visit/1"})
    try:
        with opener(req, timeout=timeout) as resp:
            resp.read(4096)
            status, error = resp.status, None
    except Exception as exc:         # a refused connection or a timeout is a result too
        status, error = None, f"{type(exc).__name__}: {exc}"
    return status, error, round((time.monotonic() - started) * 1000)


def entry(url, ip, status, error, ms, now=None):
    now = now or datetime.now(timezone.utc)
    line = {"at": now.isoformat(timespec="seconds").replace("+00:00", "Z"), "public_ip": ip, "url": url,
            "status": status, "ms": ms}
    if error:
        line["error"] = error
    return line


def next_wait(every_minutes, jitter_minutes, rng=random):
    """Minutes until the next visit: the interval, plus or minus up to the jitter."""
    return max(1.0, every_minutes + rng.uniform(-jitter_minutes, jitter_minutes))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("url", help="the lure page, http://PUBLIC-IP/")
    parser.add_argument("--log", required=True, help="JSON lines file to append to")
    parser.add_argument("--every", type=float, default=20, help="minutes between visits (default 20)")
    parser.add_argument("--jitter", type=float, default=10, help="minutes of random variation (default 10)")
    parser.add_argument("--once", action="store_true", help="one visit, then exit")
    args = parser.parse_args()
    path = Path(args.log)
    path.parent.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            ip = public_ip()
        except Exception as exc:
            ip = None
            print(f"could not learn the public address: {exc}", file=sys.stderr)
        status, error, ms = visit(args.url)
        line = entry(args.url, ip, status, error, ms)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")
        print(f"{line['at']}  from {ip}  {status if status else error}  {ms} ms")
        if args.once:
            return
        wait = next_wait(args.every, args.jitter)
        print(f"  next visit in {wait:.0f} min", flush=True)
        time.sleep(wait * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
