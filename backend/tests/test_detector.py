"""
Tests for the platform's own detector (ADR 0011).

What a capture file reports has to be what the offline record computes from
the same file: section 8's D4 compares the two address by address, and the
first test here pins it flow by flow — the live path's flags against the
offline path's, from the extractor's CSV through the harmonizer's reader to
the same model. The rest pin what is and is not reported (addresses that
began a flagged flow, on the internet, once a day; never one the honeypot
called), the refusals (another model, another XGBoost, a capture whose
commonest address is not the honeypot's), and the delivery: a file counted
once however often it is retried, one finding identity per address per day,
and every refused event sent again or the invocation failed.
"""
import importlib
import importlib.util
import json
import sys
from pathlib import Path
from unittest import mock

import numpy as np
import pytest
from botocore.exceptions import ClientError

from .test_pcap_flows import ACK, HOST, OPERATOR, REMOTE, RESOLVER, SYN, T0, brute_force, pcap, tcp, udp

xgb = pytest.importorskip("xgboost")
pytest.importorskip("pandas")

ROOT = Path(__file__).resolve().parents[2]
HANDLER_DIR = ROOT / "cdk" / "lambda" / "detector"
NETWORK = "10.99.0.0/24"
DAY = "2025-11-01"                       # T0 is 2025-11-01T12:26:40Z
KEY = "captures/i-0abc1234def567890/capture-20251101T120000Z.pcap"


@pytest.fixture(scope="module")
def det():
    # The image puts pcap_flows.py and the schema beside the handler; here they
    # are found where they live. Loaded under its own name, like the other
    # functions' handlers, so that no test gets another function's "handler".
    for path in (ROOT / "scripts", ROOT / "ml" / "evaluation"):
        sys.path.insert(0, str(path))
    spec = importlib.util.spec_from_file_location("detector_handler", HANDLER_DIR / "handler.py")
    module = importlib.util.module_from_spec(spec)
    with mock.patch("boto3.client"), mock.patch("boto3.resource"):
        spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def ts():
    return importlib.import_module("honeypot_timesplit")


def probe(t, src, sport, dport):
    """A lone SYN answered by an RST: what most scanners leave."""
    return [(t, tcp(src, HOST, sport, dport, SYN), 60), (t + 0.05, tcp(HOST, src, dport, sport, 0x14), 54)]


def capture(tmp_path, name="capture.pcap"):
    """Attacks from two addresses, the operator's visit, the honeypot's own DNS
    query, and a DHCP server's answer from inside the VPC."""
    frames = (brute_force(T0, 51000) + brute_force(T0 + 5, 51001) + probe(T0 + 9, "192.0.2.77", 40000, 3389)
              + probe(T0 + 11, OPERATOR, 41000, 80)
              + [(T0 + 12, udp(HOST, RESOLVER, 53001, 53, 30), 58), (T0 + 12.01, udp(RESOLVER, HOST, 53, 53001, 90), 118)]
              + [(T0 + 13, udp("10.99.0.1", HOST, 67, 68, 300), 328)])
    frames.sort(key=lambda f: f[0])
    path = tmp_path / name
    path.write_bytes(pcap(frames))
    return path


def toy_model(tmp_path, seed=0):
    """A small model with spread-out margins, so that a threshold between them
    flags some flows and not others."""
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(300, 14)).astype(np.float32) * [1, 3, 3, 100, 100, 50, 50, 1, 1, 10, 100, 1, 1, 1]
    y = (X[:, 1] < 0).astype(np.int8)
    booster = xgb.train({"objective": "binary:logistic", "max_depth": 3, "seed": 1, "nthread": 1},
                        xgb.DMatrix(X, label=y), num_boost_round=8)
    path = tmp_path / "model.ubj"
    booster.save_model(str(path))
    return booster, path


# ------------------------------------------------- the same as the offline record
def test_a_file_flags_exactly_the_flows_the_offline_record_flags(det, ts, tmp_path):
    path = capture(tmp_path)
    booster, _ = toy_model(tmp_path)
    flows = importlib.import_module("pcap_flows")
    flows.run(str(path), host=HOST, out=str(tmp_path / "flows.csv"), log=lambda *_: None)
    offline = ts.read_flows(tmp_path / "flows.csv")
    margin = booster.predict(xgb.DMatrix(offline.X), output_margin=True)
    for threshold in (float(np.median(margin)), float(margin.min()), float(np.nextafter(margin.max(), np.inf))):
        expected = {}
        for m, category, remote, began in zip(margin, offline.category, offline.remote, offline.began):
            if m >= np.float32(threshold) and category == "unsolicited inbound" and det.on_the_internet(remote):
                key = (str(began)[:10], remote)
                expected[key] = expected.get(key, 0) + 1
        reported, counts = det.verdicts(path, booster, threshold, NETWORK)
        assert {k: r["flows"] for k, r in reported.items()} == expected
        assert counts["unsolicited inbound: flows"] == int((offline.category == "unsolicited inbound").sum())


# --------------------------------------------------------- what is reported
def test_every_address_that_began_a_flagged_flow_is_reported_once_a_day_and_no_other(det, tmp_path):
    booster, _ = toy_model(tmp_path)
    reported, counts = det.verdicts(capture(tmp_path), booster, float("-inf"), NETWORK)   # every flow flagged
    assert set(reported) == {(DAY, REMOTE), (DAY, "192.0.2.77"), (DAY, OPERATOR)}
    r = reported[(DAY, REMOTE)]
    assert r["flows"] == 2 and r["ports"] == {22} and r["first"] == pytest.approx(T0) and r["last"] > r["first"]
    assert reported[(DAY, "192.0.2.77")]["ports"] == {3389}
    # The honeypot's own DNS query is scored and counted, and its resolver never
    # named; nor is the VPC's DHCP server, which began a flow but is not on the internet.
    assert counts["self-initiated: flows"] == 1 and counts["self-initiated: flagged"] == 1
    assert counts["unsolicited inbound: flows"] == 5 and counts["unsolicited inbound: flagged"] == 5
    assert not any(address in ("10.99.0.2", "10.99.0.1") for _, address in reported)
    nothing, _ = det.verdicts(capture(tmp_path), booster, float("inf"), NETWORK)
    assert nothing == {}


def test_a_capture_whose_commonest_address_is_not_in_the_honeypot_s_subnet_is_refused(det, tmp_path):
    booster, _ = toy_model(tmp_path)
    with pytest.raises(RuntimeError, match="not in the honeypot's subnet"):
        det.verdicts(capture(tmp_path), booster, 0.0, "10.98.0.0/24")


def test_only_the_recorded_model_under_the_recorded_xgboost_is_served(det, tmp_path):
    _, path = toy_model(tmp_path)
    good = det.sha256(path)
    assert det.load_model(path, good, xgb.__version__) is not None
    with pytest.raises(RuntimeError, match="not the model section 8's threshold is for"):
        det.load_model(path, "0" * 64, xgb.__version__)
    with pytest.raises(RuntimeError, match="the version section 8's threshold was chosen under"):
        det.load_model(path, good, "0.0.1")


# ------------------------------------------------------------- delivery
def conditional_failure():
    return ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "counted"}}, "UpdateItem")


def test_a_file_is_counted_into_its_address_s_day_once_however_often_it_is_retried(det, tmp_path):
    state = mock.MagicMock()
    state.update_item.return_value = {"Attributes": {"day": DAY, "address": REMOTE}}
    r = {"flows": 2, "ports": {22}, "first": T0, "last": T0 + 6}
    with mock.patch.object(det, "_state", state):
        assert det.tally(DAY, REMOTE, r, KEY, "now")["address"] == REMOTE
        call = state.update_item.call_args.kwargs
        assert call["Key"] == {"pk": f"{DAY}#{REMOTE}"}
        assert "NOT contains(#file_keys, :key)" in call["ConditionExpression"]
        assert call["ExpressionAttributeValues"][":file"] == {KEY}
        assert call["ExpressionAttributeValues"][":ports"] == {22}
        assert "if_not_exists(#first_reported_at, :now)" in call["UpdateExpression"]
        # Retried after the file was counted: nothing is added, the day is read back.
        state.update_item.side_effect = conditional_failure()
        state.get_item.return_value = {"Item": {"day": DAY, "address": REMOTE, "flows": 2}}
        assert det.tally(DAY, REMOTE, r, KEY, "later")["flows"] == 2
        assert state.get_item.call_args.kwargs == {"Key": {"pk": f"{DAY}#{REMOTE}"}, "ConsistentRead": True}
        state.update_item.side_effect = ClientError({"Error": {"Code": "ProvisionedThroughputExceededException"}},
                                                    "UpdateItem")
        with pytest.raises(ClientError):
            det.tally(DAY, REMOTE, r, KEY, "later")


def test_every_copy_of_an_address_s_day_has_one_identity_and_names_its_file(det):
    item = {"day": DAY, "address": REMOTE, "flows": 3, "ports": {22, 23}, "files": 2, "first_seen": "a",
            "last_seen": "b", "first_reported_at": "c"}
    first = json.loads(det.entry(item, KEY, "2025-11-01T12:30:00Z", "x")["Detail"])
    later = json.loads(det.entry(dict(item, flows=9), KEY.replace("120000Z", "121500Z"), "2025-11-01T12:45:00Z",
                                 "y")["Detail"])
    assert first["finding_id"] == later["finding_id"] and len(first["finding_id"]) == 32
    assert first["instance_id"] == "i-0abc1234def567890"
    assert first["ports"] == [22, 23] and later["flows"] == 9
    assert later["file_arrived_at"] == "2025-11-01T12:45:00Z" and later["first_reported_at"] == "c"
    other_day = json.loads(det.entry(dict(item, day="2025-11-02"), KEY, "t", "z")["Detail"])
    assert other_day["finding_id"] != first["finding_id"]


def test_refused_events_are_sent_again_and_still_refused_ones_fail_the_invocation(det):
    events = mock.MagicMock()
    entries = [{"Detail": str(i)} for i in range(12)]
    events.put_events.side_effect = [
        {"FailedEntryCount": 1, "Entries": [{}] * 9 + [{"ErrorCode": "Throttled"}]},
        {"FailedEntryCount": 0, "Entries": [{}, {}]},
        {"FailedEntryCount": 0, "Entries": [{}]},
    ]
    with mock.patch.object(det, "_events", events), mock.patch.object(det.time, "sleep"):
        assert det.send(entries) == 12
        assert [len(c.kwargs["Entries"]) for c in events.put_events.call_args_list] == [10, 2, 1]
        events.put_events.side_effect = None
        events.put_events.return_value = {"FailedEntryCount": 1, "Entries": [{"ErrorCode": "Throttled"}]}
        with pytest.raises(RuntimeError, match="could not be sent"):
            det.send(entries[:1])


def test_a_capture_file_is_scored_counted_and_reported_and_anything_else_is_skipped(det, tmp_path):
    path = capture(tmp_path)
    booster, _ = toy_model(tmp_path)
    s3, state, events = mock.MagicMock(), mock.MagicMock(), mock.MagicMock()
    s3.download_file.side_effect = lambda bucket, key, dest: Path(dest).write_bytes(path.read_bytes())
    state.update_item.side_effect = lambda **kw: {"Attributes": {
        "day": kw["ExpressionAttributeValues"][":day"], "address": kw["ExpressionAttributeValues"][":address"],
        "flows": kw["ExpressionAttributeValues"][":flows"], "ports": kw["ExpressionAttributeValues"][":ports"],
        "files": 1, "first_seen": "f", "last_seen": "l", "first_reported_at": "r"}}
    events.put_events.return_value = {"FailedEntryCount": 0, "Entries": [{}] * 10}
    record = {"s3": {"bucket": {"name": "b"}, "object": {"key": KEY}}, "eventTime": "2025-11-01T12:31:02.000Z"}
    skipped = {"s3": {"bucket": {"name": "b"}, "object": {"key": "flow-logs/x.log.gz"}}}
    with mock.patch.object(det, "_s3", s3), mock.patch.object(det, "_state", state), \
            mock.patch.object(det, "_events", events), mock.patch.object(det, "model", return_value=booster), \
            mock.patch.object(det, "THRESHOLD", float("-inf")), mock.patch.object(det, "HOST_NETWORK", NETWORK):
        assert det.handler({"Records": [record, skipped]}, None) == {"files": 1}
    assert s3.download_file.call_count == 1
    sent = [json.loads(e["Detail"]) for c in events.put_events.call_args_list for e in c.kwargs["Entries"]]
    assert sorted(d["address"] for d in sent) == sorted([REMOTE, "192.0.2.77", OPERATOR])
    assert {d["file"] for d in sent} == {KEY} and {d["file_arrived_at"] for d in sent} == {record["eventTime"]}
    assert all(e["Source"] == "cloudsentinel.detector" and e["DetailType"] == "CloudSentinel Detector Finding"
               for c in events.put_events.call_args_list for e in c.kwargs["Entries"])
