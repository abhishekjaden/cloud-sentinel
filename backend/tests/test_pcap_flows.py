"""
Tests for the honeypot's flow extractor and the visit logger.

The captures only exist once the third run has happened; what is pinned here
is that the extractor assembles flows the way the protocol says — forward is
the first packet's direction, both FINs or an RST or 120 seconds end a flow,
the closing ACK stays with it — that the features are the schema's, computed
by the same function the datasets go through, that bytes come from the IP
header even when the payload was cut off, and that every flow gets the label
its initiator earns and no other.
"""
import importlib.util
import json
import struct
import sys
from pathlib import Path

import pytest

pytest.importorskip("pandas")

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    sys.path.insert(0, str(ROOT / "ml" / "evaluation"))
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def flows():
    return load("pcap_flows")


@pytest.fixture(scope="module")
def visits():
    return load("honeypot_visit")


HOST, REMOTE, OPERATOR, RESOLVER = "10.99.0.12", "198.51.100.7", "203.0.113.5", "10.99.0.2"
FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10


def ip(addr):
    return bytes(int(x) for x in addr.split("."))


def tcp(src, dst, sport, dport, flags, payload=0, options=0):
    """An Ethernet frame holding an IPv4/TCP packet, cut after the headers the
    way the capture cuts it; the IP total length still counts the payload."""
    tcp_len = 20 + options
    total = 20 + tcp_len + payload
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0, ip(src), ip(dst))
    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, (tcp_len // 4) << 4, flags, 65535, 0, 0) + b"\0" * options
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip_hdr + tcp_hdr


def udp(src, dst, sport, dport, payload):
    total = 20 + 8 + payload
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0, ip(src), ip(dst))
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip_hdr + struct.pack("!HHHH", sport, dport, 8 + payload, 0)


def arp():
    return b"\xff" * 6 + b"\xbb" * 6 + b"\x08\x06" + b"\0" * 28


def pcap(frames, magic=0xA1B2C3D4, endian="<", scale=1e6):
    """A pcap file from (timestamp, frame, original length) triples."""
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 256, 1)
    for ts, frame, orig in frames:
        sec = int(ts)
        frac = int(round((ts - sec) * scale))
        out += struct.pack(endian + "IIII", sec, frac, len(frame), orig) + frame
    return out


T0 = 1_762_000_000.0


def brute_force(t=T0, sport=51000):
    """One SSH connection attempt: handshake, a little data each way, both FINs, the closing ACK."""
    return [
        (t + 0.00, tcp(REMOTE, HOST, sport, 22, SYN, options=20), 74),
        (t + 0.10, tcp(HOST, REMOTE, 22, sport, SYN | ACK, options=20), 74),
        (t + 0.20, tcp(REMOTE, HOST, sport, 22, ACK), 54),
        (t + 0.30, tcp(REMOTE, HOST, sport, 22, ACK, payload=40), 94),
        (t + 0.40, tcp(HOST, REMOTE, 22, sport, ACK, payload=60), 114),
        (t + 0.80, tcp(REMOTE, HOST, sport, 22, FIN | ACK), 54),
        (t + 0.90, tcp(HOST, REMOTE, 22, sport, FIN | ACK), 54),
        (t + 1.00, tcp(REMOTE, HOST, sport, 22, ACK), 54),
    ]


def write(tmp_path, frames, name="capture-20261101T000000Z.pcap", **kw):
    path = tmp_path / name
    path.write_bytes(pcap(frames, **kw))
    return path


def test_an_ssh_attempt_is_one_unsolicited_inbound_flow_with_the_schema_s_features(flows, tmp_path):
    write(tmp_path, brute_force())
    rows, summary = flows.run(tmp_path, host=HOST, log=lambda *_: None)
    assert len(rows) == 1
    r = rows[0]
    assert (r["label"], r["category"], r["remote"], r["dst_port"], r["host_port"]) == \
        ("attack", "unsolicited inbound", REMOTE, 22, 22)
    assert r["fwd_pkts"] == 5 and r["bwd_pkts"] == 3            # the closing ACK stays with the flow
    assert r["fwd_bytes"] == 60 + 40 + 40 + 80 + 40             # IP total lengths: headers and payload, no framing
    assert r["bwd_bytes"] == 60 + 100 + 40
    assert r["duration_s"] == pytest.approx(1.0)
    assert r["fwd_iat_mean_s"] == pytest.approx(0.25)           # four gaps over one second
    assert r["bwd_iat_mean_s"] == pytest.approx(0.4)
    assert r["fwd_mean_len"] == pytest.approx(52.0) and r["bwd_fwd_pkt_ratio"] == pytest.approx(0.6)
    assert (r["is_tcp"], r["is_udp"]) == (1.0, 0.0) and r["packets"] == 8 and r["ended_by"] == "both FINs"
    assert r["first_seen"].startswith("2025-11-01T") and r["first_seen"].endswith("Z")
    assert summary["by_category"] == {"unsolicited inbound": 1} and summary["inbound_by_port"] == {22: 1}


def test_bytes_come_from_the_ip_header_so_the_cut_payload_still_counts(flows):
    frame = tcp(REMOTE, HOST, 5000, 80, ACK, payload=1200)
    p = flows.parse(T0, frame)
    assert len(frame) == 54 and p.ip_len == 1240 and p.payload == 1200


def test_a_lone_probe_is_a_one_packet_flow_and_the_operator_s_visit_is_benign(flows, tmp_path):
    frames = [(T0, tcp(REMOTE, HOST, 40000, 3389, SYN), 54),
              (T0 + 5, tcp(OPERATOR, HOST, 50000, 80, SYN), 54),
              (T0 + 5.1, tcp(HOST, OPERATOR, 80, 50000, SYN | ACK), 54),
              (T0 + 5.2, tcp(OPERATOR, HOST, 50000, 80, ACK, payload=120), 174)]
    write(tmp_path, frames)
    rows, _ = flows.run(tmp_path, host=HOST, cidrs=["203.0.113.0/24"], log=lambda *_: None)
    probe, visit = rows
    assert (probe["label"], probe["category"], probe["dst_port"], probe["packets"]) == ("attack", "unsolicited inbound", 3389, 1)
    assert probe["bwd_pkts"] == 0 and probe["bwd_fwd_pkt_ratio"] == 0 and probe["duration_s"] == 0
    assert probe["pkt_rate"] == pytest.approx(1e6)             # the schema's floor, as in every dataset
    assert (visit["label"], visit["category"], visit["remote"], visit["dst_port"]) == ("benign", "operator", OPERATOR, 80)
    assert visit["ended_by"] == "end of capture"


def test_the_operator_s_addresses_can_come_from_the_visit_log(flows, tmp_path):
    log = tmp_path / "visits.jsonl"
    log.write_text(json.dumps({"at": "2026-11-01T00:00:00Z", "public_ip": OPERATOR, "status": 200}) + "\n\n"
                   + json.dumps({"at": "2026-11-01T00:30:00Z", "public_ip": None, "status": None}) + "\n")
    write(tmp_path, [(T0, tcp(OPERATOR, HOST, 50000, 80, SYN), 54), (T0 + 1, tcp(REMOTE, HOST, 50000, 80, SYN), 54)])
    rows, _ = flows.run(tmp_path, host=HOST, visits=str(log), log=lambda *_: None)
    assert [r["category"] for r in rows] == ["operator", "unsolicited inbound"]


def test_what_the_honeypot_itself_begins_is_benign_including_over_udp(flows, tmp_path):
    frames = [(T0, udp(HOST, RESOLVER, 44444, 53, 30), 72), (T0 + 0.02, udp(RESOLVER, HOST, 53, 44444, 90), 132),
              (T0 + 1, tcp("0.0.0.0", "255.255.255.255", 68, 67, 0), 54),
              (T0 + 2, tcp("127.0.0.1", "127.0.0.1", 40000, 80, SYN), 54)]
    write(tmp_path, frames)
    rows, summary = flows.run(tmp_path, host=HOST, log=lambda *_: None)
    dns, dhcp, loopback = rows
    assert (dns["label"], dns["category"], dns["remote"], dns["dst_port"]) == ("benign", "self-initiated", RESOLVER, 53)
    assert (dns["is_tcp"], dns["is_udp"]) == (0.0, 1.0) and dns["fwd_bytes"] == 58 and dns["bwd_bytes"] == 118
    assert dhcp["category"] == "self-initiated" and loopback["category"] == "self-initiated"
    assert summary["remote_addresses_inbound"] == 0


def test_a_flow_ends_after_120_seconds_and_at_an_rst_and_the_next_packet_starts_another(flows, tmp_path):
    frames = [(T0, tcp(REMOTE, HOST, 6000, 22, SYN), 54), (T0 + 60, tcp(REMOTE, HOST, 6000, 22, ACK), 54),
              (T0 + 130, tcp(REMOTE, HOST, 6000, 22, ACK), 54),             # more than 120 s after the first
              (T0 + 131, tcp(HOST, REMOTE, 22, 6000, RST | ACK), 54),        # ends the second flow
              (T0 + 132, tcp(REMOTE, HOST, 6000, 22, SYN), 54)]             # a third
    write(tmp_path, frames)
    rows, _ = flows.run(tmp_path, host=HOST, log=lambda *_: None)
    assert [r["ended_by"] for r in rows] == ["timeout", "RST", "end of capture"]
    assert [r["packets"] for r in rows] == [2, 2, 1]
    assert rows[0]["duration_s"] == pytest.approx(60.0)


def test_a_retransmitted_syn_joins_its_flow_but_a_syn_after_the_handshake_starts_another(flows, tmp_path):
    frames = [(T0, tcp(REMOTE, HOST, 6000, 22, SYN), 54), (T0 + 1, tcp(REMOTE, HOST, 6000, 22, SYN), 54),
              (T0 + 3, tcp(REMOTE, HOST, 6000, 22, SYN), 54),                 # three tries, no answer: one flow
              (T0 + 9, tcp(HOST, REMOTE, 22, 6000, SYN | ACK), 54),
              (T0 + 9.1, tcp(REMOTE, HOST, 6000, 22, ACK), 54),
              (T0 + 30, tcp(REMOTE, HOST, 6000, 22, SYN), 54)]                # the same port again: a new one
    write(tmp_path, frames)
    rows, _ = flows.run(tmp_path, host=HOST, log=lambda *_: None)
    assert [(r["packets"], r["ended_by"]) for r in rows] == [(5, "new SYN"), (1, "end of capture")]


def test_after_both_fins_only_a_prompt_bare_ack_joins_the_flow(flows, tmp_path):
    frames = brute_force()[:-1]
    frames.append((T0 + 5.0, tcp(REMOTE, HOST, 51000, 22, ACK), 54))        # too late: its own flow
    frames += brute_force(t=T0 + 10, sport=51000)[:7]                          # the port reused: a new SYN, a new flow
    frames.append((T0 + 10.95, tcp(REMOTE, HOST, 51000, 22, ACK, payload=10), 64))  # carries data: not the closing ACK
    write(tmp_path, frames)
    rows, _ = flows.run(tmp_path, host=HOST, log=lambda *_: None)
    assert [(r["packets"], r["ended_by"]) for r in rows] == \
        [(7, "both FINs"), (1, "new SYN"), (7, "both FINs"), (1, "end of capture")]


def test_frames_that_are_not_ipv4_are_counted_and_skipped_and_files_are_read_in_order(flows, tmp_path):
    write(tmp_path, [(T0 + 100, tcp(REMOTE, HOST, 7000, 23, SYN), 54), (T0 + 101, arp(), 42)],
          name="capture-20261101T001500Z.pcap")
    write(tmp_path, brute_force(), name="capture-20261101T000000Z.pcap")
    (tmp_path / "notes.txt").write_text("not a capture")
    rows, summary = flows.run(tmp_path, host=HOST, log=lambda *_: None)
    assert summary["files"] == 2 and summary["records"] == 10 and summary["not_ipv4"] == 1
    assert [r["dst_port"] for r in rows] == [22, 23]


def test_big_endian_and_nanosecond_captures_are_read_too(flows, tmp_path):
    write(tmp_path, brute_force(), name="a.pcap", magic=0xA1B23C4D, endian="<", scale=1e9)
    write(tmp_path, brute_force(t=T0 + 50), name="b.pcap", magic=0xA1B2C3D4, endian=">", scale=1e6)
    rows, _ = flows.run(tmp_path, host=HOST, log=lambda *_: None)
    assert len(rows) == 2 and all(r["duration_s"] == pytest.approx(1.0) for r in rows)
    with pytest.raises(ValueError, match="not a pcap"):
        list(flows.records(tmp_path / "notes.pcap")) if (tmp_path / "notes.pcap").write_bytes(b"\0" * 40) else None


def test_the_host_is_guessed_as_the_commonest_address_and_the_csv_feeds_the_harmonizer(flows, tmp_path):
    frames = brute_force() + [(T0 + 20, tcp("192.0.2.9", HOST, 8000, 80, SYN), 54)]
    write(tmp_path, frames)
    out = tmp_path / "out" / "flows.csv"
    rows, summary = flows.run(tmp_path, out=out, log=lambda *_: None)
    assert summary["host"] == HOST and len(rows) == 2
    header = out.read_text().splitlines()[0].split(",")
    assert header[:len(flows.FEATURES)] == flows.FEATURES and header[len(flows.FEATURES):len(flows.FEATURES) + 3] == \
        ["dst_port", "label", "category"]
    sys.path.insert(0, str(ROOT / "ml" / "evaluation"))
    spec = importlib.util.spec_from_file_location("harmonize", ROOT / "ml" / "evaluation" / "harmonize.py")
    harmonize = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harmonize)
    meta = harmonize.harmonize("flows", str(out), tmp_path / "h.npz", with_port=True, log=lambda *_: None)
    X, y, _, _ = harmonize.load(tmp_path / "h.npz")
    assert meta["rows"] == 2 and y.tolist() == [1, 1] and meta["raw_labels"] == {"unsolicited inbound": 2}
    assert X[0].tolist()[:3] == pytest.approx([1.0, 5, 3]) and X[:, -1].tolist() == [22.0, 80.0]


# ---------------------------------------------------------------- the visits
def test_a_visit_logs_where_it_came_from_and_what_it_got(visits):
    class Resp:
        status = 200

        def read(self, n):
            return b"<h1>Internal portal</h1>"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class IpResp(Resp):
        def read(self, n=None):
            return b"203.0.113.5\n"

    def opener(req, timeout):
        return IpResp() if req == visits.CHECK_IP else Resp()

    assert visits.public_ip(opener) == "203.0.113.5"
    status, error, ms = visits.visit("http://198.51.100.1/", opener)
    assert status == 200 and error is None and ms >= 0
    line = visits.entry("http://198.51.100.1/", "203.0.113.5", status, error, ms)
    assert line["public_ip"] == "203.0.113.5" and line["status"] == 200 and "error" not in line
    assert line["at"].endswith("Z")


def test_a_refused_visit_is_a_result_not_a_crash(visits):
    def opener(req, timeout):
        raise ConnectionRefusedError("refused")

    status, error, ms = visits.visit("http://198.51.100.1/", opener)
    assert status is None and error.startswith("ConnectionRefusedError") and ms >= 0
    assert "error" in visits.entry("u", None, status, error, ms)


def test_visits_are_irregular_but_never_closer_than_a_minute(visits):
    class Rng:
        def uniform(self, a, b):
            return a

    assert visits.next_wait(20, 10, Rng()) == 10
    assert visits.next_wait(1, 10, Rng()) == 1.0
