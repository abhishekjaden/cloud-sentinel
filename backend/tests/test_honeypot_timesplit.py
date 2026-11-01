"""
Tests for the honeypot's time split (docs/generalization-protocol.md, section 7).

The flows exist only on the laptop that downloaded the captures; what is
pinned here is the arithmetic the expectations are judged by — that the cut
puts a flow by the time it began, that rows the harmonizer would drop are
dropped and counted, that "new addresses" means addresses that began no
unsolicited flow before the cut, that the baseline is the best single-feature
rule on the training days and nothing else, and that G7-G10 are read at the
limits the protocol states.
"""
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pytest

pd = pytest.importorskip("pandas")
pytest.importorskip("xgboost")

EVAL = Path(__file__).resolve().parents[2] / "ml" / "evaluation"


def load_module(name):
    sys.path.insert(0, str(EVAL))
    spec = importlib.util.spec_from_file_location(name, EVAL / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def ts():
    return load_module("honeypot_timesplit")


@pytest.fixture(scope="module")
def harmonize():
    return load_module("harmonize")


COLUMNS_AFTER = ["dst_port", "label", "category", "remote", "host_port", "protocol", "first_seen", "last_seen",
                 "packets", "ended_by"]


def flow_rows(harmonize, n, began, attack, category, remotes, rng):
    """Rows in pcap_flows.py's CSV form: attacks short one-way bursts, the
    rest two-way conversations, features computed by the harmonizer's own
    function."""
    fwd = rng.integers(1, 3, n).astype(float) if attack else rng.integers(5, 20, n).astype(float)
    bwd = rng.integers(0, 2, n).astype(float) if attack else rng.integers(5, 20, n).astype(float)
    dur = rng.uniform(0.0, 0.5, n) if attack else rng.uniform(1.0, 30.0, n)
    X = harmonize.derive(dur, fwd, bwd, fwd * 60, bwd * 300, dur / np.maximum(fwd - 1, 1),
                         dur / np.maximum(bwd - 1, 1), np.full(n, 6.0))
    rows = []
    for i in range(n):
        rows.append({**dict(zip(harmonize.FEATURES, X[i].tolist())), "dst_port": 22 if attack else 443,
                     "label": "attack" if attack else "benign", "category": category,
                     "remote": remotes[i % len(remotes)], "host_port": 22, "protocol": 6,
                     "first_seen": began[i], "last_seen": began[i], "packets": int(fwd[i] + bwd[i]),
                     "ended_by": "timeout"})
    return rows


def times(start, hours, n, rng):
    base = np.datetime64(start)
    offsets = np.sort(rng.uniform(0, hours * 3600, n)).astype("timedelta64[s]")
    return [str(base + o) + "Z" for o in offsets]


def write_csv(harmonize, path, rows):
    pd.DataFrame(rows, columns=harmonize.FEATURES + COLUMNS_AFTER).to_csv(path, index=False)


def test_the_cut_places_a_flow_by_when_it_began_and_non_finite_rows_are_dropped(ts, harmonize, tmp_path):
    rng = np.random.default_rng(1)
    rows = flow_rows(harmonize, 3, ["2026-10-29T23:59:59.999999Z", "2026-10-30T00:00:00.000000Z",
                                    "2026-10-31T10:00:00Z"], True, "unsolicited inbound", ["198.51.100.7"], rng)
    rows[2]["label"], rows[2]["category"] = "benign", "self-initiated"
    broken = dict(rows[0], first_seen="2026-10-25T00:00:00Z", fwd_mean_len="")
    write_csv(harmonize, tmp_path / "flows.csv", rows + [broken])
    flows = ts.read_flows(tmp_path / "flows.csv")
    assert flows.dropped == 1 and len(flows) == 3
    train, test = ts.split(flows)
    assert len(train) == 1 and len(test) == 2                     # the cut itself is a test flow
    assert test.y.tolist() == [1, 0] and list(test.category) == ["unsolicited inbound", "self-initiated"]


def test_new_addresses_are_those_that_began_no_unsolicited_flow_before_the_cut(ts):
    test = ts.Flows(np.zeros((5, 14), dtype=np.float32), np.array([1, 1, 1, 0, 0], dtype=np.int8),
                    np.array(["unsolicited inbound"] * 3 + ["self-initiated", "operator"], dtype=object),
                    np.array(["a", "c", "c", "a", "op"], dtype=object),
                    np.array(["2026-10-31T00:00:00"] * 5, dtype="datetime64[us]"))
    flagged = np.array([True, False, True, False, True])
    m = ts.measure(flagged, flagged.astype(float), test, {"a"})
    assert m["inbound"] == {"n": 3, "flagged": 2, "fraction": pytest.approx(2 / 3, abs=1e-6)}
    assert m["inbound_new_addresses"]["n"] == 2 and m["inbound_new_addresses"]["flagged"] == 1
    assert m["inbound_new_addresses"]["addresses"] == 1
    assert m["benign"]["n"] == 2 and m["benign"]["flagged"] == 1
    assert m["by_category"]["operator"] == {"n": 1, "flagged": 1, "fraction": 1.0}


def test_the_baseline_is_the_best_single_feature_rule_on_the_training_days(ts):
    rng = np.random.default_rng(2)
    X = rng.normal(size=(400, 14)).astype(np.float32)
    y = np.array([1] * 200 + [0] * 200, dtype=np.int8)
    X[:, 11] = np.where(y == 1, 0.0, rng.uniform(1, 5, 400))      # bwd_fwd_pkt_ratio: no reply means attack
    rule = ts.best_single_feature(X, y)
    assert rule["feature"] == "bwd_fwd_pkt_ratio" and rule["direction"] == "<=" and rule["threshold"] == 0.0
    assert rule["balanced_accuracy_training"] == 1.0
    flagged, _ = ts.apply_rule(rule, X)
    assert flagged.tolist() == (y == 1).tolist()
    with pytest.raises(ValueError, match="both classes"):
        ts.best_single_feature(X, np.ones(400, dtype=np.int8))


def figures(inbound, new, benign, operator):
    return {"inbound": {"fraction": inbound}, "inbound_new_addresses": {"fraction": new},
            "benign": {"fraction": benign}, "by_category": {"operator": {"n": 10, "fraction": operator}}}


def test_the_expectations_are_read_at_the_protocols_limits(ts):
    at_limits = ts.expectations({"H": figures(0.93, 0.93, 0.01, 0.10), "P+H": figures(0.94, 0.9, 0.0, 0.0),
                                 "B": figures(0.5, 0.5, 0.0, 0.0)})
    assert all(at_limits[g]["met"] for g in ("G7", "G8", "G9", "G10"))
    assert at_limits["baseline_at_G7_and_G9_levels"] is False
    past = ts.expectations({"H": figures(0.9299, 0.95, 0.005, 0.11), "P+H": figures(0.9411, 0.9, 0.0, 0.0),
                            "B": figures(0.99, 0.99, 0.001, 0.0)})
    assert not past["G7"]["met"] and past["G8"]["met"] and not past["G9"]["met"] and not past["G10"]["met"]
    assert past["baseline_at_G7_and_G9_levels"] is True
    nothing = ts.expectations({"H": figures(0.95, None, 0.0, 0.0), "B": figures(0.5, 0.5, 0.0, 0.0)})
    assert not nothing["G8"]["met"] and "G10" not in nothing        # nothing to count meets nothing


def test_the_run_fits_three_models_and_records_what_it_ran_under(ts, harmonize, tmp_path):
    rng = np.random.default_rng(3)
    rows = (flow_rows(harmonize, 240, times("2026-10-24T15:00:00", 200, 240, rng), True, "unsolicited inbound",
                      [f"203.0.113.{i}" for i in range(30)], rng)
            + flow_rows(harmonize, 300, times("2026-10-24T15:00:00", 200, 300, rng), False, "self-initiated",
                        ["52.216.0.1"], rng)
            + flow_rows(harmonize, 20, times("2026-10-24T15:00:00", 200, 20, rng), False, "operator",
                        ["192.0.2.50"], rng))
    write_csv(harmonize, tmp_path / "flows.csv", rows)
    public_X = harmonize.derive(np.r_[rng.uniform(0, 0.5, 100), rng.uniform(1, 30, 100)],
                                np.r_[rng.integers(1, 3, 100), rng.integers(5, 20, 100)].astype(float),
                                np.r_[rng.integers(0, 2, 100), rng.integers(5, 20, 100)].astype(float),
                                np.full(200, 600.0), np.full(200, 900.0), np.full(200, 0.1), np.full(200, 0.1),
                                np.full(200, 6.0))
    np.savez_compressed(tmp_path / "pub.npz", X=public_X, y=np.r_[np.ones(100), np.zeros(100)].astype(np.int8),
                        raw=np.zeros(200, dtype=np.int16))
    (tmp_path / "pub.json").write_text(json.dumps({"dataset": "public", "source": "flows",
                                                   "features": harmonize.FEATURES, "raw_labels": {"x": 200}}))
    flows = ts.read_flows(tmp_path / "flows.csv")
    params = dict(ts.PARAMS, n_estimators=5, max_depth=3)
    result = ts.run(flows, ts.read_public([tmp_path / "pub.npz"]), params, tmp_path / "out" / "ts.json",
                    log=lambda *_: None)
    assert set(result["models"]) == {"H", "P+H", "B"}
    assert {"G7", "G8", "G9", "G10", "baseline_at_G7_and_G9_levels"} <= set(result["expectations"])
    assert result["versions"]["xgboost"] and result["versions"]["numpy"]
    assert result["training"]["flows"] + result["test"]["flows"] == 560 and result["cut"] == ts.CUT
    assert result["models"]["H"]["inbound"]["fraction"] > 0.9       # a separable toy, not a claim
    saved = json.loads((tmp_path / "out" / "ts.json").read_text())
    assert saved["complete"]
    written = (tmp_path / "out" / "ts.json").read_text()
    assert "203.0.113." not in written and "192.0.2.50" not in written    # counts only, never an address
    lines = []
    ts.report(saved, log=lines.append)
    text = "\n".join(lines)
    assert "| G7 |" in text and "| G10 |" in text and "B: " in text


def test_a_public_table_with_the_port_is_refused(ts, harmonize, tmp_path):
    np.savez_compressed(tmp_path / "p.npz", X=np.zeros((2, 15), dtype=np.float32), y=np.array([0, 1], dtype=np.int8),
                        raw=np.zeros(2, dtype=np.int16))
    (tmp_path / "p.json").write_text(json.dumps({"dataset": "p", "features": harmonize.FEATURES + ["dst_port"]}))
    with pytest.raises(SystemExit, match="without the port"):
        ts.read_public([tmp_path / "p.npz"])
