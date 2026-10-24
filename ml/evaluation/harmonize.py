"""
Put three flow datasets, and the honeypot's own flows, on one small feature
schema, so that a detector trained on any of them can be tested on the others.

CICIDS2017 and CSE-CIC-IDS-2018 share CICFlowMeter's 83 features, which is why
`cross_dataset.py` could score one with a model trained on the other. UNSW-NB15
was extracted by Argus and Bro and shares none of them by name, and the
honeypot's packet captures (`scripts/pcap_flows.py`) were never near either
tool. What every source can produce is a dozen quantities about a
bidirectional flow — how long it lasted, how many packets and bytes went each
way, how big the packets were, how far apart, and the transport protocol — and
that is the schema here. Everything that cannot be matched across sources is
left out, on purpose: TTL values, TCP window sizes, flag counts, bulk and idle
statistics, each dataset's own derived rates, and the ports unless asked for.

The harmonization is not exact, and the places where it is approximate are
named in `docs/generalization-protocol.md`: byte counts are made comparable by
adding CICFlowMeter's header lengths to its payload totals and taking the
Ethernet framing off Argus's wire totals; times are converted to seconds; the
means and rates are recomputed from the counts rather than copied from each
dataset's own column, so that one definition holds everywhere.

    python ml/evaluation/harmonize.py cic2017 --data ~/Downloads/cicids2017-corrected \
        --out ml/harmonized/cic2017.npz
    python ml/evaluation/harmonize.py cic2018 --data ~/Downloads/CSECICIDS2018_improved.zip \
        --keep-every 30 --out ml/harmonized/cic2018.npz
    python ml/evaluation/harmonize.py unsw --data ~/Downloads/unsw-nb15 --out ml/harmonized/unsw.npz
    python ml/evaluation/harmonize.py flows --data honeypot-flows.csv --out ml/harmonized/honeypot.npz

Each run writes a compressed `.npz` (X as float32, y as 0/1, each row's raw
label as a code) and a `.json` beside it with the provenance: the files read,
the rows kept and dropped, the options, and the raw labels with their counts.
The 2018 release is 63 million flows; `--keep-every 30` keeps every thirtieth
row of every file, in order, which is the same rows every time.
`cross_matrix.py` reads these tables and never the raw data.
"""
import argparse
import csv
import io
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cross_dataset import _Counted, attempted, key, list_csvs, open_csv  # noqa: E402

FEATURES = [
    "duration_s",         # first packet to last packet, seconds
    "fwd_pkts",           # packets from the flow's initiator
    "bwd_pkts",           # packets back to it
    "fwd_bytes",          # IP-layer bytes (headers and payload, no Ethernet framing) each way
    "bwd_bytes",
    "fwd_mean_len",       # fwd_bytes / fwd_pkts; 0 when there were no packets that way
    "bwd_mean_len",
    "fwd_iat_mean_s",     # mean gap between consecutive packets in that direction, seconds
    "bwd_iat_mean_s",
    "pkt_rate",           # packets a second over the flow's duration, floored at one microsecond
    "byte_rate",
    "bwd_fwd_pkt_ratio",  # bwd_pkts / fwd_pkts; a probe with no reply is 0
    "is_tcp",
    "is_udp",
]
PORT_FEATURE = "dst_port"
MIN_DURATION = 1e-6     # a one-packet flow lasts 0 s; the rates divide by this instead
ETHERNET_HEADER = 14    # bytes Argus counts on the wire that CICFlowMeter does not

# Where each source keeps the quantities above, by column name reduced to
# lower-case letters and digits. The CIC spellings cover the corrected
# releases ("Total Fwd Packet"), the original 2017 release ("Total Fwd
# Packets") and the original 2018 release ("Tot Fwd Pkts").
CIC_COLUMNS = {
    "duration": ["flowduration"],
    "fwd_pkts": ["totalfwdpacket", "totalfwdpackets", "totfwdpkts"],
    "bwd_pkts": ["totalbwdpackets", "totalbackwardpackets", "totbwdpkts"],
    "fwd_payload": ["totallengthoffwdpacket", "totallengthoffwdpackets", "totlenfwdpkts"],
    "bwd_payload": ["totallengthofbwdpacket", "totallengthofbwdpackets", "totlenbwdpkts"],
    "fwd_header": ["fwdheaderlength", "fwdheaderlen"],
    "bwd_header": ["bwdheaderlength", "bwdheaderlen"],
    "fwd_iat": ["fwdiatmean"],
    "bwd_iat": ["bwdiatmean"],
    "protocol": ["protocol"],
    "dst_port": ["dstport", "destinationport"],
    "label": ["label"],
}
UNSW_COLUMNS = {
    "duration": ["dur"],
    "fwd_pkts": ["spkts"],
    "bwd_pkts": ["dpkts"],
    "fwd_wire": ["sbytes"],
    "bwd_wire": ["dbytes"],
    "fwd_iat": ["sintpkt", "sinpkt"],
    "bwd_iat": ["dintpkt", "dinpkt"],
    "protocol": ["proto"],
    "dst_port": ["dsport"],
    "label": ["label"],
    "category": ["attackcat"],
}
# The 49 columns of UNSW-NB15_1.csv to _4.csv, which carry no header row, in
# the order of the dataset's NUSW-NB15_features.csv (the file's own spelling
# of its name). The features file is read when it is in the folder; this list
# is the fallback and the check.
UNSW_RAW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl",
    "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin",
    "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "Sjit", "Djit",
    "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports",
    "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "attack_cat", "Label",
]
UNSW_SIDE_FILES = {"nuswnb15features", "unswnb15features", "unswnb15listevents", "unswnb15gtcsv"}
FLOW_COLUMNS = {f: [key(f)] for f in FEATURES + [PORT_FEATURE]}
FLOW_COLUMNS.update({"label": ["label"], "category": ["category", "raw"]})


# ------------------------------------------------------------- the schema
def resolve(header, columns, optional=()):
    """Position of each wanted quantity in a header, by the spellings allowed
    for it. A quantity not found is an error unless it is optional."""
    positions = {key(c): i for i, c in enumerate(header)}
    found, missing = {}, []
    for want, names in columns.items():
        pos = next((positions[n] for n in names if n in positions), None)
        if pos is None:
            if want not in optional:
                missing.append(f"{want} (one of {names})")
            continue
        found[want] = pos
    if missing:
        shown = list(header)[:12]
        raise ValueError("columns not found: " + "; ".join(missing)
                         + f". The header has: {shown}{'...' if len(header) > 12 else ''}")
    return found


def derive(duration_s, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes, fwd_iat_s, bwd_iat_s, protocol):
    """The schema's columns from the quantities every source has, as float32.
    `protocol` is an array of IP protocol numbers (6, 17, other)."""
    duration_s = np.asarray(duration_s, dtype=np.float64)
    fwd_pkts = np.asarray(fwd_pkts, dtype=np.float64)
    bwd_pkts = np.asarray(bwd_pkts, dtype=np.float64)
    fwd_bytes = np.maximum(np.asarray(fwd_bytes, dtype=np.float64), 0.0)
    bwd_bytes = np.maximum(np.asarray(bwd_bytes, dtype=np.float64), 0.0)
    protocol = np.asarray(protocol, dtype=np.float64)
    span = np.maximum(duration_s, MIN_DURATION)
    with np.errstate(divide="ignore", invalid="ignore"):
        fwd_mean = np.where(fwd_pkts > 0, fwd_bytes / np.maximum(fwd_pkts, 1), 0.0)
        bwd_mean = np.where(bwd_pkts > 0, bwd_bytes / np.maximum(bwd_pkts, 1), 0.0)
        ratio = np.where(fwd_pkts > 0, bwd_pkts / np.maximum(fwd_pkts, 1), bwd_pkts)
    X = np.column_stack([
        duration_s, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes, fwd_mean, bwd_mean,
        np.asarray(fwd_iat_s, dtype=np.float64), np.asarray(bwd_iat_s, dtype=np.float64),
        (fwd_pkts + bwd_pkts) / span, (fwd_bytes + bwd_bytes) / span, ratio,
        (protocol == 6).astype(np.float64), (protocol == 17).astype(np.float64),
    ])
    return X.astype(np.float32)


def numeric(series):
    return pd.to_numeric(series, errors="coerce").to_numpy(dtype=np.float64)


def unsw_protocol(series):
    """Argus writes the protocol as a name; the schema wants IP numbers."""
    s = series.astype(str).str.strip().str.lower()
    return np.where(s == "tcp", 6, np.where(s == "udp", 17, 0)).astype(np.float64)


def unsw_port(series):
    """dsport is decimal for most rows, hexadecimal ('0x000b') for a few of
    the non-TCP ones, and '-' where Argus had no port."""
    def one(v):
        s = str(v).strip().lower()
        try:
            return int(s, 16) if s.startswith("0x") else int(float(s))
        except ValueError:
            return np.nan
    return np.array([one(v) for v in series], dtype=np.float64)


def unsw_category(series):
    """attack_cat as written, with the spaces around some values removed:
    blank for normal traffic, and 'Backdoors' is 'Backdoor' spelt a second
    way in the same release."""
    s = series.fillna("").astype(str).str.strip()
    s = s.where(s != "", "Normal").str.replace(r"^Backdoors$", "Backdoor", regex=True)
    return s.to_numpy(dtype=object)


# ----------------------------------------------------------- per-source rows
def cic_rows(chunk, pos, with_port):
    """One CICFlowMeter chunk (raw columns, by position) → X, y, raw label, port."""
    col = lambda name: chunk[pos[name]]  # noqa: E731
    label = col("label").astype(str).str.strip()
    lower = label.str.lower()
    y = (~((lower == "benign") | lower.str.contains("attempted", regex=False))).astype(np.int8).to_numpy()
    X = derive(numeric(col("duration")) / 1e6,
               numeric(col("fwd_pkts")), numeric(col("bwd_pkts")),
               numeric(col("fwd_payload")) + numeric(col("fwd_header")),
               numeric(col("bwd_payload")) + numeric(col("bwd_header")),
               numeric(col("fwd_iat")) / 1e6, numeric(col("bwd_iat")) / 1e6,
               numeric(col("protocol")))
    port = numeric(col("dst_port")) if with_port else None
    return X, y, label.to_numpy(dtype=object), port


def unsw_rows(chunk, pos, with_port, ethernet=ETHERNET_HEADER):
    col = lambda name: chunk[pos[name]]  # noqa: E731
    y = (numeric(col("label")) > 0).astype(np.int8)
    spkts, dpkts = numeric(col("fwd_pkts")), numeric(col("bwd_pkts"))
    X = derive(numeric(col("duration")), spkts, dpkts,
               numeric(col("fwd_wire")) - ethernet * spkts,
               numeric(col("bwd_wire")) - ethernet * dpkts,
               numeric(col("fwd_iat")) / 1e3, numeric(col("bwd_iat")) / 1e3,
               unsw_protocol(col("protocol")))
    port = unsw_port(col("dst_port")) if with_port else None
    return X, y, unsw_category(col("category")), port


def flow_rows(chunk, pos, with_port):
    """A CSV already in the schema (scripts/pcap_flows.py writes one)."""
    col = lambda name: chunk[pos[name]]  # noqa: E731
    label = col("label").astype(str).str.strip().str.lower()
    y = (label != "benign").astype(np.int8).to_numpy()
    X = np.column_stack([numeric(col(f)) for f in FEATURES]).astype(np.float32)
    port = numeric(col("dst_port")) if with_port else None
    return X, y, col("category").astype(str).str.strip().to_numpy(dtype=object), port


SOURCES = {
    "cic2017": ("CICIDS2017", CIC_COLUMNS, cic_rows),
    "cic2018": ("CSE-CIC-IDS-2018", CIC_COLUMNS, cic_rows),
    "unsw": ("UNSW-NB15", UNSW_COLUMNS, unsw_rows),
    "flows": ("flows in the schema", FLOW_COLUMNS, flow_rows),
}


# ------------------------------------------------------------------ reading
def unsw_feature_names(folder):
    """The raw files' column names from NUSW-NB15_features.csv when it is
    there (checked against the built-in list), else the built-in list."""
    path = next((p for p in sorted(Path(folder).rglob("*"))
                 if key(p.stem) in ("nuswnb15features", "unswnb15features")), None)
    if path is None:
        return list(UNSW_RAW_COLUMNS), None
    with open(path, encoding="latin-1", newline="") as fh:
        rows = list(csv.reader(fh))
    header = [key(c) for c in rows[0]]
    name_col = header.index("name") if "name" in header else 1
    names = [r[name_col].strip() for r in rows[1:] if len(r) > name_col and r[name_col].strip()]
    expected = [key(n) for n in UNSW_RAW_COLUMNS]
    if [key(n) for n in names] != expected:
        raise ValueError(f"{path.name} lists {len(names)} columns that differ from the 49 expected; "
                         f"not expected: {[n for n in names if key(n) not in set(expected)]}")
    return names, path.name


def is_unsw_raw(name):
    """UNSW-NB15_1.csv to _4.csv have no header row; the training and testing
    split files do, and lack the ports."""
    return re.fullmatch(r"unswnb15[1-4]", key(Path(name).stem)) is not None


def locate(data):
    """(base, [(name, size)]) for a folder or zip of CSVs, or one CSV file."""
    path = Path(data)
    if path.is_file() and path.suffix.lower() == ".csv":
        return str(path.parent), [(path.name, path.stat().st_size)]
    return str(path), list_csvs(path)


def read_chunks(source, base, name, chunk_rows, columns, optional, unsw_names=None):
    """(header, positions, chunk iterator) for one CSV: only the wanted columns
    are parsed, every one as text. The headerless UNSW raw files get their
    header from the features file."""
    fh = io.BufferedReader(_Counted(open_csv(base, name)), 1 << 20)
    if source == "unsw" and is_unsw_raw(name):
        header = list(unsw_names or UNSW_RAW_COLUMNS)
    else:
        header = [c.strip() for c in next(csv.reader([fh.readline().decode("latin-1")]))]
    pos = resolve(header, columns, optional)
    reader = pd.read_csv(fh, header=None, names=range(len(header)), usecols=sorted(pos.values()),
                         chunksize=chunk_rows, encoding="latin-1", low_memory=False, on_bad_lines="warn", dtype=str)
    return header, pos, reader


class Table:
    """Accumulates harmonized rows and writes the .npz and its .json."""

    def __init__(self, source, with_port):
        self.source, self.with_port = source, with_port
        self.features = FEATURES + ([PORT_FEATURE] if with_port else [])
        self.parts, self.codes = [], {}
        self.rows = self.dropped = self.repeated_headers = 0
        self.files = []

    def add(self, X, y, raw, port, header_text=None):
        if header_text is not None:                 # header lines repeated inside a file
            repeat = raw == header_text
            if repeat.any():
                self.repeated_headers += int(repeat.sum())
                keep = ~repeat
                X, y, raw = X[keep], y[keep], raw[keep]
                port = None if port is None else port[keep]
        if self.with_port:
            X = np.column_stack([X, np.asarray(port, dtype=np.float32)])
        ok = np.isfinite(X).all(axis=1)
        self.dropped += int((~ok).sum())
        self.rows += int(ok.sum())
        uniq, inverse = np.unique(raw[ok].astype(str), return_inverse=True)
        codes = np.array([self.codes.setdefault(u, len(self.codes)) for u in uniq], dtype=np.int16)
        self.parts.append((X[ok], y[ok], codes[inverse] if len(uniq) else np.empty(0, dtype=np.int16)))

    def arrays(self):
        if not self.parts:
            return (np.empty((0, len(self.features)), dtype=np.float32),
                    np.empty(0, dtype=np.int8), np.empty(0, dtype=np.int16))
        return (np.concatenate([p[0] for p in self.parts]), np.concatenate([p[1] for p in self.parts]),
                np.concatenate([p[2] for p in self.parts]))

    def raw_labels(self):
        return [name for name, _ in sorted(self.codes.items(), key=lambda kv: kv[1])]

    def write(self, out, options):
        X, y, codes = self.arrays()
        out = Path(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(out, X=X, y=y, raw=codes)
        counts = np.bincount(codes, minlength=len(self.codes)) if len(codes) else np.zeros(len(self.codes), dtype=int)
        meta = {
            "dataset": SOURCES[self.source][0], "source": self.source, "features": self.features,
            "rows": int(len(y)), "attack": int(y.sum()), "dropped_missing_or_infinite": self.dropped,
            "repeated_headers": self.repeated_headers, "files": self.files,
            "raw_labels": {name: int(counts[i]) for i, name in enumerate(self.raw_labels())},
            "options": options, "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        out.with_suffix(".json").write_text(json.dumps(meta, indent=2) + "\n")
        return meta


def harmonize(source, data, out, with_port=False, keep_every=1, chunk_rows=200_000, ethernet=ETHERNET_HEADER,
              limit_rows=None, log=print):
    """Read every CSV of a source and write the harmonized table; returns its metadata."""
    dataset, columns, rows_of = SOURCES[source]
    base, files = locate(data)
    if source == "unsw":
        files = [(n, s) for n, s in files if key(Path(n).stem) not in UNSW_SIDE_FILES]
    if not files:
        sys.exit(f"no CSV files under {data}")
    unsw_names, features_file = (unsw_feature_names(base) if source == "unsw" else (None, None))
    table = Table(source, with_port)
    started = time.time()
    log(f"{dataset}: {len(files)} file(s), {sum(s for _, s in files) / 1e9:.2f} GB uncompressed"
        + (f", one row in {keep_every}" if keep_every > 1 else ""))
    offset = 0        # so that keep_every counts on across chunks and files
    for name, size in files:
        try:
            header, pos, reader = read_chunks(source, base, name, chunk_rows, columns,
                                              () if with_port else ("dst_port",), unsw_names)
        except ValueError as exc:
            if len(files) == 1:
                raise
            log(f"  {name}: skipped — {exc}")
            continue
        before_rows, file_started, read = table.rows, time.time(), 0
        header_label = header[pos["label"]] if source != "unsw" else None
        for chunk in reader:
            if limit_rows and read >= limit_rows:
                break
            if keep_every > 1:
                take = np.arange(len(chunk)) + offset
                offset = int((offset + len(chunk)) % keep_every)
                chunk = chunk.iloc[np.flatnonzero(take % keep_every == 0)]
            read += len(chunk)
            if not len(chunk):
                continue
            kw = {"ethernet": ethernet} if source == "unsw" else {}
            X, y, raw, port = rows_of(chunk, pos, with_port, **kw)
            table.add(X, y, raw, port, header_text=header_label)
        kept = table.rows - before_rows
        table.files.append({"file": name, "bytes": size, "rows_kept": kept,
                            "seconds": round(time.time() - file_started, 1)})
        log(f"  {name}: {kept:,} rows kept in {time.time() - file_started:.0f} s")
    options = {"with_port": with_port, "keep_every": keep_every, "limit_rows": limit_rows,
               "unsw_ethernet_header_bytes": ethernet if source == "unsw" else None,
               "unsw_features_file": features_file}
    meta = table.write(out, options)
    log(f"wrote {out}: {meta['rows']:,} rows ({meta['attack']:,} attack), {meta['dropped_missing_or_infinite']:,} "
        f"dropped for missing or infinite values, {len(meta['raw_labels'])} raw labels, "
        f"{(time.time() - started) / 60:.1f} min")
    return meta


def load(path):
    """(X, y, raw codes, meta) of a harmonized table."""
    path = Path(path)
    with np.load(path) as z:
        X, y, raw = z["X"], z["y"], z["raw"]
    meta = json.loads(path.with_suffix(".json").read_text())
    return X, y, raw, meta


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("source", choices=sorted(SOURCES))
    parser.add_argument("--data", required=True, help="a folder of CSVs, a zip of them, or one CSV")
    parser.add_argument("--out", required=True, help="the .npz to write; a .json goes beside it")
    parser.add_argument("--with-port", action="store_true",
                        help="add the destination port as a feature (the protocol's secondary run)")
    parser.add_argument("--keep-every", type=int, default=1, help="keep every Nth row (the 2018 release is 63 million)")
    parser.add_argument("--chunk-rows", type=int, default=200_000)
    parser.add_argument("--limit-rows", type=int, help="read only the first N rows of each file (a trial)")
    parser.add_argument("--unsw-ethernet", type=int, default=ETHERNET_HEADER,
                        help="bytes of framing to take off Argus's wire totals per packet; 0 to keep them")
    args = parser.parse_args()
    harmonize(args.source, args.data, args.out, args.with_port, args.keep_every, args.chunk_rows,
              args.unsw_ethernet, args.limit_rows)


if __name__ == "__main__":
    main()
