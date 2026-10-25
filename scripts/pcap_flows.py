#!/usr/bin/env python3
"""
Turn the honeypot's packet captures into flows on the detector's schema, each
with the label it earns by construction.

The honeypot's third run writes headers-only pcap files to its capture bucket
(cdk/lib/stacks/honeypot-stack.ts, generation 4). Download them, then:

    aws s3 sync s3://BUCKET/captures/ ~/Downloads/honeypot-captures/ --profile cs-workload
    python scripts/pcap_flows.py ~/Downloads/honeypot-captures --host 10.99.0.12 \\
        --visits docs/honeypot-visits-2026-11.jsonl --out ml/harmonized/honeypot-flows.csv
    python ml/evaluation/harmonize.py flows --data ml/harmonized/honeypot-flows.csv --out ml/harmonized/honeypot.npz

A flow is a bidirectional conversation between two address-and-port pairs on
one protocol, assembled the way the corrected CICFlowMeter assembles one: the
first packet's direction is forward; a flow ends when both sides have sent
FIN (the final ACK is kept with it if it comes within two seconds), when
either sends RST, or 120 seconds after it began, after which the next packet
starts a new flow. Its features are those of `ml/evaluation/harmonize.py`
(`FEATURES`), computed by the same function, with bytes counted at the IP
layer from each packet's total-length field — which the capture keeps even
though it cuts the payload off.

The label needs no judgement (docs/generalization-protocol.md, section 3):

- a flow the honeypot itself began is benign, category `self-initiated` —
  its uploads to S3, DNS, NTP and the metadata service, the only traffic it
  can originate;
- a flow begun by an address named with --benign-source, or recorded in the
  visit log of scripts/honeypot_visit.py given with --visits, is benign,
  category `operator`;
- every other flow was begun by someone on the internet toward a machine
  that invited nobody: attack, category `unsolicited inbound`.

--summary prints the counts and stops; --out writes the CSV, one row per flow,
with the remote address, the port and the times beside the features so that
the record can be read per attacker and per service.
"""
import argparse
import csv
import ipaddress
import json
import struct
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml" / "evaluation"))
from harmonize import FEATURES, derive  # noqa: E402

FLOW_TIMEOUT = 120.0        # seconds since the flow's first packet, as CICFlowMeter
FINAL_ACK_GRACE = 2.0       # seconds after both FINs in which the closing ACK still belongs to the flow
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
COLUMNS = FEATURES + ["dst_port", "label", "category", "remote", "host_port", "protocol", "first_seen", "last_seen",
                      "packets", "ended_by"]


# ---------------------------------------------------------------- the pcap
def records(path):
    """(timestamp, captured bytes, original length) for each record of a pcap
    file: little- or big-endian, microsecond or nanosecond timestamps."""
    with open(path, "rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            return
        magic = struct.unpack("<I", head[:4])[0]
        endian, scale = {0xA1B2C3D4: ("<", 1e-6), 0xA1B23C4D: ("<", 1e-9),
                         0xD4C3B2A1: (">", 1e-6), 0x4D3CB2A1: (">", 1e-9)}.get(magic, (None, None))
        if endian is None:
            raise ValueError(f"{path}: not a pcap file (magic {magic:#x})")
        link = struct.unpack(endian + "I", head[20:24])[0]
        if link != 1:
            raise ValueError(f"{path}: link type {link}; only Ethernet captures are read")
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, orig = struct.unpack(endian + "IIII", rec)
            data = fh.read(incl)
            if len(data) < incl:
                return                      # a file cut short mid-record: what was read stands
            yield sec + frac * scale, data, orig


class Packet:
    __slots__ = ("ts", "src", "dst", "sport", "dport", "proto", "ip_len", "flags", "payload")

    def __init__(self, ts, src, dst, sport, dport, proto, ip_len, flags, payload):
        self.ts, self.src, self.dst, self.sport, self.dport = ts, src, dst, sport, dport
        self.proto, self.ip_len, self.flags, self.payload = proto, ip_len, flags, payload


def parse(ts, frame):
    """An IPv4 packet's addresses, ports, protocol, IP-layer length, TCP flags
    and payload length, from a frame that may hold only its headers; None
    for anything that is not IPv4 over Ethernet."""
    n = len(frame)
    if n < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if ethertype == 0x8100 and n >= 18:
        ethertype = struct.unpack("!H", frame[16:18])[0]
        off = 18
    if ethertype != 0x0800 or n < off + 20:
        return None
    ihl = (frame[off] & 0x0F) * 4
    ip_len = struct.unpack("!H", frame[off + 2:off + 4])[0]
    proto = frame[off + 9]
    src = ".".join(str(b) for b in frame[off + 12:off + 16])
    dst = ".".join(str(b) for b in frame[off + 16:off + 20])
    t = off + ihl
    sport = dport = 0
    flags = 0
    transport = 0
    if proto == 6 and n >= t + 14:
        sport, dport = struct.unpack("!HH", frame[t:t + 4])
        transport = (frame[t + 12] >> 4) * 4
        flags = frame[t + 13]
    elif proto == 17 and n >= t + 4:
        sport, dport = struct.unpack("!HH", frame[t:t + 4])
        transport = 8
    elif proto in (1,):
        transport = 8
    payload = max(ip_len - ihl - transport, 0)
    return Packet(ts, src, dst, sport, dport, proto, ip_len, flags, payload)


# ---------------------------------------------------------------- the flows
class Flow:
    def __init__(self, p):
        self.initiator, self.responder, self.proto = (p.src, p.sport), (p.dst, p.dport), p.proto
        self.first, self.last = p.ts, p.ts
        self.pkts = [0, 0]           # forward, backward
        self.bytes = [0, 0]
        self.gaps = [0.0, 0.0]       # sum of inter-arrival gaps each way
        self.last_in = [None, None]  # last timestamp each way
        self.fin = [False, False]
        self.closing_since = None
        self.done = False            # the closing ACK has been taken; nothing more joins
        self.only_syns = True        # nothing but the initiator's SYNs so far (retransmissions join)
        self.ended_by = "end of capture"
        self.add(p)

    def direction(self, p):
        return 0 if (p.src, p.sport) == self.initiator else 1

    def add(self, p):
        d = self.direction(p)
        self.pkts[d] += 1
        self.bytes[d] += p.ip_len
        if self.last_in[d] is not None:
            self.gaps[d] += p.ts - self.last_in[d]
        self.last_in[d] = p.ts
        self.last = max(self.last, p.ts)
        if d == 1 or p.flags & ~SYN or self.proto != 6:
            self.only_syns = False
        if self.proto == 6:
            if p.flags & FIN:
                self.fin[d] = True
                if all(self.fin) and self.closing_since is None:
                    self.closing_since = p.ts
                    self.ended_by = "both FINs"
            if p.flags & RST:
                self.closing_since = p.ts
                self.ended_by = "RST"

    @property
    def closed(self):
        return self.closing_since is not None

    def reopened_by(self, p):
        """A fresh SYN on a conversation that got past its handshake is a new
        connection on a reused port, not more of this one."""
        return self.proto == 6 and p.flags & SYN and not p.flags & ACK and not self.only_syns

    def takes_final_ack(self, p):
        """After both FINs, the last ACK (and only that) still belongs here."""
        return (self.ended_by == "both FINs" and not self.done and p.ts - self.closing_since <= FINAL_ACK_GRACE
                and p.flags & ACK and not p.flags & (SYN | FIN | RST) and p.payload == 0)

    def features(self):
        fwd, bwd = self.pkts
        iat = [self.gaps[d] / (self.pkts[d] - 1) if self.pkts[d] > 1 else 0.0 for d in (0, 1)]
        X = derive([self.last - self.first], [fwd], [bwd], [self.bytes[0]], [self.bytes[1]],
                   [iat[0]], [iat[1]], [self.proto])
        return [float(v) for v in X[0]]


def flow_key(p):
    a, b = (p.src, p.sport), (p.dst, p.dport)
    return (min(a, b), max(a, b), p.proto)


def assemble(packets, on_flow):
    """Feed packets in time order; calls on_flow for each finished flow."""
    active = {}
    for p in packets:
        k = flow_key(p)
        flow = active.get(k)
        if flow is not None:
            if p.ts - flow.first > FLOW_TIMEOUT:
                flow.ended_by = "timeout"
                on_flow(active.pop(k))
            elif flow.closed:
                if flow.takes_final_ack(p):
                    flow.add(p)
                    flow.done = True
                    continue
                on_flow(active.pop(k))
            elif flow.reopened_by(p):
                flow.ended_by = "new SYN"
                on_flow(active.pop(k))
            else:
                flow.add(p)
                if flow.ended_by == "RST":
                    on_flow(active.pop(k))
                continue
        active[k] = Flow(p)
    for flow in sorted(active.values(), key=lambda f: f.first):
        on_flow(flow)


# --------------------------------------------------------------- labelling
def benign_sources(cidrs=(), visits=None):
    nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
    if visits:
        for line in Path(visits).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            ip = json.loads(line).get("public_ip")
            if ip:
                nets.append(ipaddress.ip_network(ip + "/32"))
    return nets


def label(flow, host, benign):
    """(label, category, remote address, the honeypot's port)."""
    (src, sport), (dst, dport) = flow.initiator, flow.responder
    # 0.0.0.0 is the instance asking for its address at boot; loopback is the
    # instance talking to itself — the capture sees every interface.
    if src == host or src == "0.0.0.0" or src.startswith("127."):
        return "benign", "self-initiated", dst, sport
    addr = ipaddress.ip_address(src)
    if any(addr in net for net in benign):
        return "benign", "operator", src, dport
    return "attack", "unsolicited inbound", src, dport


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def row(flow, host, benign):
    lab, cat, remote, host_port = label(flow, host, benign)
    dst_port = flow.responder[1]
    return dict(zip(FEATURES, flow.features()), dst_port=dst_port, label=lab, category=cat, remote=remote,
                host_port=host_port, protocol=flow.proto, first_seen=iso(flow.first), last_seen=iso(flow.last),
                packets=sum(flow.pkts), ended_by=flow.ended_by)


# -------------------------------------------------------------------- files
def pcap_files(folder):
    path = Path(folder)
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*.pcap") if p.is_file())


def packets_of(files, counts):
    for path in files:
        for ts, data, _orig in records(path):
            counts["records"] += 1
            p = parse(ts, data)
            if p is None:
                counts["not ipv4"] += 1
                continue
            yield p
        counts["files"] += 1


def address_counts(files):
    """How many packets each address appears in, as source or destination,
    leaving out the ones no honeypot is ever known by: loopback, 0.0.0.0, and
    broadcast and multicast destinations."""
    seen = Counter()
    for path in files:
        for ts, data, _ in records(path):
            p = parse(ts, data)
            if p is None:
                continue
            for addr in {p.src, p.dst}:
                a = ipaddress.IPv4Address(addr)
                if not (a.is_loopback or a.is_unspecified or a.is_multicast or addr == "255.255.255.255"):
                    seen[addr] += 1
    return seen


PRIVATE_RANGES = [ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def guess_host(files, seen=None):
    """The honeypot's own address: the one in the most packets. Every packet
    the capture holds was sent or received by the instance, so its address is
    in all of them but the loopback and broadcast ones. A capture with one
    other party ties the two; the address in a private range is the
    instance's."""
    seen = address_counts(files) if seen is None else seen
    if not seen:
        sys.exit("no IPv4 packets in the capture")
    top = max(seen.values())
    tied = sorted(a for a, n in seen.items() if n == top)
    private = [a for a in tied if any(ipaddress.IPv4Address(a) in net for net in PRIVATE_RANGES)]
    return (private or tied)[0]


def check_host(host, seen):
    """Refuse a --host that cannot be the honeypot's address. Every flow's
    label turns on it: an address that is in no packet, or in fewer than the
    honeypot's own, labels the flows the honeypot began — its uploads to S3,
    its DNS and NTP — as attacks, silently. Found on 25 October 2026, when
    the first day's captures were run with the placeholder from the
    instructions in place of the address."""
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        sys.exit(f"--host {host!r} is not an IPv4 address: give the instance's private address "
                 "(aws ec2 describe-instances, PrivateIpAddress), or leave --host out to use the "
                 "commonest address in the capture")
    top = max(seen.values(), default=0)
    if top == 0 or seen.get(host, 0) < top:
        best = guess_host(None, seen) if seen else "no address"
        sys.exit(f"--host {host} is in {seen.get(host, 0):,} packets, but {best} is in "
                 f"{top:,}: the honeypot's own address is in every packet it captured")
    return host


def run(folder, host=None, cidrs=(), visits=None, out=None, log=print):
    files = pcap_files(folder)
    if not files:
        sys.exit(f"no .pcap files under {folder}")
    seen = address_counts(files)
    host = check_host(host, seen) if host else guess_host(files, seen)
    benign = benign_sources(cidrs, visits)
    counts = Counter()
    rows = []
    assemble(packets_of(files, counts), lambda f: rows.append(row(f, host, benign)))
    rows.sort(key=lambda r: r["first_seen"])
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=COLUMNS)
            w.writeheader()
            w.writerows(rows)
    summary = summarize(rows, counts, host, files)
    log(render(summary))
    if out:
        log(f"wrote {out}: {len(rows):,} flows")
    return rows, summary


def summarize(rows, counts, host, files):
    by_cat = Counter(r["category"] for r in rows)
    inbound = [r for r in rows if r["category"] == "unsolicited inbound"]
    return {
        "host": host, "files": len(files), "records": counts["records"], "not_ipv4": counts["not ipv4"],
        "flows": len(rows), "by_category": dict(by_cat),
        "first_seen": rows[0]["first_seen"] if rows else None, "last_seen": max((r["last_seen"] for r in rows), default=None),
        "remote_addresses_inbound": len({r["remote"] for r in inbound}),
        "inbound_by_port": dict(Counter(r["dst_port"] for r in inbound).most_common(12)),
        "inbound_ended_by": dict(Counter(r["ended_by"] for r in inbound)),
    }


def render(s):
    lines = [f"host {s['host']}: {s['files']} file(s), {s['records']:,} records, {s['not_ipv4']:,} not IPv4; "
             f"{s['flows']:,} flows from {s['first_seen']} to {s['last_seen']}"]
    for cat, n in sorted(s["by_category"].items()):
        lines.append(f"  {cat:<20} {n:,}")
    lines.append(f"  unsolicited inbound from {s['remote_addresses_inbound']:,} addresses; by port: "
                 + ", ".join(f"{p}: {n:,}" for p, n in s["inbound_by_port"].items()))
    lines.append("  inbound flows ended by: " + ", ".join(f"{k} {n:,}" for k, n in s["inbound_ended_by"].items()))
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("captures", help="a folder of .pcap files (searched recursively) or one file")
    parser.add_argument("--host", help="the honeypot's private address, refused unless it is the commonest address "
                                       "in the capture; the commonest address if omitted")
    parser.add_argument("--benign-source", action="append", default=[], metavar="CIDR",
                        help="an address or range whose flows are the operator's (repeatable)")
    parser.add_argument("--visits", help="scripts/honeypot_visit.py's log; its public addresses are the operator's")
    parser.add_argument("--out", help="the CSV to write; omit for the summary alone")
    args = parser.parse_args()
    run(args.captures, args.host, args.benign_source, args.visits, args.out)


if __name__ == "__main__":
    main()
