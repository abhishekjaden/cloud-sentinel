"""
The platform's own detector, at work on the honeypot (ADR 0011).

The capture bucket invokes this function for each capture file the honeypot
uploads. The file's packets become flows by the extractor the offline record
uses — `scripts/pcap_flows.py`, copied into this image unchanged with the
schema's `harmonize.py` and `cross_dataset.py` — one file at a time. Each flow
is scored by the model section 7 of `docs/generalization-protocol.md` trained,
at the threshold section 8's rule chose, and each address on the internet that
began a flow the model flags is reported once a UTC day as a finding of the
platform's own source, which this account's event bus forwards to the audit
account's ingestion.

What a file reports is `verdicts()`, which reads nothing but the file and the
model, so that section 8's D4 can run the same function offline over the same
files and compare. The rest is delivery. A small table keeps each address's
day — the flagged flows it began, the honeypot's ports they reached, when they
were first and last seen, which files reported it — and a file's update to it
is conditional on that file not having been counted already, so a retried
invocation counts nothing twice. Every address a file reports is then sent
with its day's figures as they stand, and the normalizer stores each copy over
the last: one finding per address per day.

Flows the honeypot began are scored and counted, never reported: an address
the honeypot chose to talk to did not come at it. Nor is an address that is
not on the internet — the VPC's own services, the instance's link-local and
loopback ones — whatever began the flow. The operator's visits are not known
here; they are reported like any other source, and section 8 counts them as
false reports.

The model is refused unless its file's SHA-256 is the one section 8's record
holds and XGBoost is the version the threshold was chosen under: a margin from
another model, or from another library, is not the margin the threshold is for.
"""
import hashlib
import ipaddress
import json
import logging
import os
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote_plus

import boto3
import numpy as np
from botocore.exceptions import ClientError

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pcap_flows  # noqa: E402  scripts/pcap_flows.py, unchanged

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SOURCE = "cloudsentinel.detector"
DETAIL_TYPE = "CloudSentinel Detector Finding"
FINDING_TYPE = "CloudSentinel:EC2/HostileFlows"
#: LOW on the normalizer's 0-100 scale: a hostile source reaching a host that
#: holds nothing.
SEVERITY = 20
INBOUND = "unsolicited inbound"

MODEL_PATH = Path(os.environ.get("MODEL_PATH", str(HERE / "platform_detector.ubj")))
MODEL_SHA256 = os.environ.get("MODEL_SHA256", "")
#: The margin section 8's rule chose, written by the stack from
#: ml/models/platform_detector.json as the shortest decimal that is that
#: float32 exactly, so it compares with the model's float32 margins exactly.
THRESHOLD = float(os.environ.get("THRESHOLD_MARGIN", "nan"))
XGBOOST_VERSION = os.environ.get("XGBOOST_VERSION", "")
#: The honeypot's subnet: its own address, the commonest in every file, must
#: be in it.
HOST_NETWORK = os.environ.get("HOST_NETWORK", "")
ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
CAPTURE_PREFIX = os.environ.get("CAPTURE_PREFIX", "captures/")
STATE_TABLE = os.environ.get("STATE_TABLE", "cloudsentinel-detector-state")
#: How long a day's tally outlives its day, for the run's record to be read.
STATE_DAYS = int(os.environ.get("STATE_DAYS", "3"))
SEND_ATTEMPTS = 3

#: Not on the internet: the VPC's own ranges and services, the instance's
#: link-local and loopback addresses, carrier-grade NAT, multicast and
#: broadcast. Section 3 labels a flow an attack because someone on the
#: internet began it; a DHCP server answering the instance's broadcast at boot
#: is not someone.
NOT_THE_INTERNET = [ipaddress.IPv4Network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32")]

_s3 = boto3.client("s3")
_events = boto3.client("events")
_state = boto3.resource("dynamodb").Table(STATE_TABLE)
_model = None


# ------------------------------------------------------------------- the model
def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_model(path=None, expected=None, version=None):
    """The model, refused unless it is the file section 8's record names and
    XGBoost is the version the threshold was chosen under."""
    import xgboost as xgb
    path = Path(path or MODEL_PATH)
    expected = MODEL_SHA256 if expected is None else expected
    version = XGBOOST_VERSION if version is None else version
    if version and xgb.__version__ != version:
        raise RuntimeError(f"XGBoost {xgb.__version__} is not {version}, the version section 8's "
                           "threshold was chosen under")
    digest = sha256(path)
    if digest != expected:
        raise RuntimeError(f"{path.name} has SHA-256 {digest}, not {expected or 'a recorded one'}: "
                           "it is not the model section 8's threshold is for")
    booster = xgb.Booster()
    booster.load_model(str(path))
    return booster


def model():
    global _model
    if _model is None:
        _model = load_model()
    return _model


# ---------------------------------------------------------------- the verdicts
def on_the_internet(address):
    try:
        a = ipaddress.IPv4Address(address)
    except ValueError:
        return False
    return not any(a in net for net in NOT_THE_INTERNET)


def honeypot_address(seen, network=None):
    """The honeypot's own address, which is in every packet it captured: the
    commonest, as the offline extractor decides it, and refused if it is not
    in the honeypot's subnet. Taken wrongly, every flow the honeypot began
    would be counted an attack (the extractor's defect of 25 October)."""
    host = pcap_flows.guess_host(None, seen)
    if network and ipaddress.IPv4Address(host) not in ipaddress.IPv4Network(network):
        raise RuntimeError(f"the commonest address in this file, {host}, is not in the honeypot's subnet "
                           f"{network}: not the honeypot's capture")
    return host


def day_of(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).date().isoformat()


def verdicts(path, booster, threshold, network=None):
    """What one capture file reports, from the file and the model alone.

    ({(day, address): {"flows", "ports", "first", "last"}}, counts): every
    address on the internet that began a flow the model flags, keyed by the
    UTC day the flow began, and the counts the file's log line carries."""
    import xgboost as xgb
    counts = Counter()
    seen = pcap_flows.address_counts([path])
    if not seen:
        return {}, counts
    host = honeypot_address(seen, network)
    found = []
    pcap_flows.assemble(pcap_flows.packets_of([path], counts), found.append)
    if not found:
        return {}, counts
    X = np.array([flow.features() for flow in found], dtype=np.float32)
    finite = np.isfinite(X).all(axis=1)
    counts["dropped non-finite"] = int((~finite).sum())
    margin = np.full(len(found), -np.inf, dtype=np.float32)
    if finite.any():
        margin[finite] = booster.predict(xgb.DMatrix(X[finite]), output_margin=True)
    flagged = margin >= np.float32(threshold)
    reported = {}
    for flow, hit in zip(found, flagged):
        _label, category, remote, host_port = pcap_flows.label(flow, host, [])
        counts[f"{category}: flows"] += 1
        counts[f"{category}: flagged"] += int(hit)
        if not hit or category != INBOUND or not on_the_internet(remote):
            continue
        r = reported.setdefault((day_of(flow.first), remote),
                                {"flows": 0, "ports": set(), "first": flow.first, "last": flow.last})
        r["flows"] += 1
        r["ports"].add(int(host_port))
        r["first"], r["last"] = min(r["first"], flow.first), max(r["last"], flow.last)
    return reported, counts


# ---------------------------------------------------------------- the delivery
def instance_of(key):
    """The instance a capture file came from: the uploader files each under
    the instance's id (honeypot-stack.ts, uploader())."""
    parts = key[len(CAPTURE_PREFIX):].split("/")
    return parts[0] if len(parts) > 1 and parts[0] else "unknown"


def finding_id(day, address, instance):
    """Stable for an address's day: every copy of the finding the day's files
    send has the same identity, and so the same key in the findings table."""
    key = f"detector|{ACCOUNT_ID}|{instance}|{day}|{address}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def tally(day, address, r, file_key, now):
    """Add one file's flagged flows from one address to that address's day,
    once — a file already counted, by an invocation retried after a partial
    run, changes nothing — and return the day's figures as they now stand."""
    key = {"pk": f"{day}#{address}"}
    expires = datetime.fromisoformat(day).replace(tzinfo=timezone.utc) + timedelta(days=1 + STATE_DAYS)
    names = {f"#{n}": n for n in ("day", "address", "flows", "files", "file_keys", "ports", "first_seen",
                                  "last_seen", "first_reported_at", "last_reported_at", "expires_at")}
    try:
        return _state.update_item(
            Key=key,
            UpdateExpression=(
                "ADD #flows :flows, #files :one, #file_keys :file, #ports :ports "
                "SET #day = :day, #address = :address, #expires_at = :expires, #last_seen = :last, "
                "#first_seen = if_not_exists(#first_seen, :first), "
                "#first_reported_at = if_not_exists(#first_reported_at, :now), #last_reported_at = :now"),
            ConditionExpression="attribute_not_exists(#file_keys) OR NOT contains(#file_keys, :key)",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues={
                ":flows": r["flows"], ":one": 1, ":file": {file_key}, ":key": file_key, ":ports": set(r["ports"]),
                ":day": day, ":address": address, ":expires": int(expires.timestamp()),
                ":first": pcap_flows.iso(r["first"]), ":last": pcap_flows.iso(r["last"]), ":now": now},
            ReturnValues="ALL_NEW",
        )["Attributes"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise
        return _state.get_item(Key=key, ConsistentRead=True)["Item"]


def entry(item, file_key, arrived, now):
    day, address, instance = item["day"], item["address"], instance_of(file_key)
    detail = {
        "finding_id": finding_id(day, address, instance),
        "account_id": ACCOUNT_ID,
        "instance_id": instance,
        "type": FINDING_TYPE,
        "severity": SEVERITY,
        "title": f"Hostile flows from {address} to the honeypot",
        "day": day,
        "address": address,
        "flows": int(item["flows"]),
        "ports": sorted(int(p) for p in item["ports"]),
        "files": int(item["files"]),
        "first_seen": item["first_seen"],
        "last_seen": item["last_seen"],
        "first_reported_at": item["first_reported_at"],
        "file": file_key,
        "file_arrived_at": arrived,
        "reported_at": now,
        "model_sha256": MODEL_SHA256,
        "threshold_margin": os.environ.get("THRESHOLD_MARGIN", ""),
    }
    return {"Source": SOURCE, "DetailType": DETAIL_TYPE, "Detail": json.dumps(detail, sort_keys=True)}


def send(entries):
    """Every entry onto this account's bus, ten to a call, the failed ones
    again; raises if any is still refused, so the invocation is retried."""
    pending = list(entries)
    for attempt in range(SEND_ATTEMPTS):
        refused = []
        for i in range(0, len(pending), 10):
            batch = pending[i:i + 10]
            resp = _events.put_events(Entries=batch)
            if resp.get("FailedEntryCount"):
                refused += [e for e, r in zip(batch, resp.get("Entries", [])) if r.get("ErrorCode")]
        if not refused:
            return len(entries)
        pending = refused
        time.sleep(2 ** attempt)  # nosemgrep: python.lang.best-practice.arbitrary-sleep
    raise RuntimeError(f"{len(pending)} of {len(entries)} detector findings could not be sent")


def process(bucket, key, arrived):
    started = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / Path(key).name
        _s3.download_file(bucket, key, str(path))
        reported, counts = verdicts(path, model(), THRESHOLD, HOST_NETWORK or None)
    now = pcap_flows.iso(time.time())
    items = [tally(day, address, r, key, now) for (day, address), r in sorted(reported.items())]
    sent = send([entry(item, key, arrived, now) for item in items]) if items else 0
    line = {"file": key, "arrived_at": arrived, "reported_at": now, "addresses_reported": len(items),
            "findings_sent": sent, "seconds": round(time.time() - started, 3), **counts}
    # One line per file: the run's record of what each file held and reported.
    logger.info("DETECTOR_FILE %s", json.dumps(line, sort_keys=True))
    return line


def handler(event, context):
    done = []
    for record in event.get("Records", []):
        s3 = record.get("s3") or {}
        bucket = (s3.get("bucket") or {}).get("name")
        key = unquote_plus((s3.get("object") or {}).get("key", ""))
        if not bucket or not key.startswith(CAPTURE_PREFIX) or not key.endswith(".pcap"):
            logger.warning("not a capture file, skipped: %s/%s", bucket, key)
            continue
        done.append(process(bucket, key, record.get("eventTime")))
    return {"files": len(done)}
