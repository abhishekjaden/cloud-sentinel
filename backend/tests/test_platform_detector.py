"""
Tests for putting section 7's H to work (docs/generalization-protocol.md,
section 8).

The flows exist only on the laptop that downloaded the captures; what is
pinned here is the rule's arithmetic and the order of its refusals — that the
threshold is the lowest at which no more than the limit is flagged, ties
falling below it; that the stricter of the two limits decides; that a model
which does not reproduce section 7's record is not put to work and writes no
model; that a rule which cannot be met writes no model either; and that what
is written holds counts, a hash and versions, never an address.
"""
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pytest

from .test_honeypot_timesplit import flow_rows, times, write_csv

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
def pdet():
    return load_module("platform_detector")


@pytest.fixture(scope="module")
def ts():
    return load_module("honeypot_timesplit")


@pytest.fixture(scope="module")
def harmonize():
    return load_module("harmonize")


def test_the_lowest_threshold_flags_no_more_than_the_limit_and_ties_fall_below_it(pdet):
    m = np.array([0.0, 5.0, 4.0, 1.0, 4.0, 3.0], dtype=np.float32)
    t = pdet.lowest_threshold(m, 2 / 6)                 # two of six may be flagged
    assert (m >= t).sum() == 1                          # the tie at 4.0 cannot be split, so both fall below
    assert (m >= np.float32(4.0)).sum() == 3            # and the threshold one step lower flags three
    assert t == float(np.nextafter(np.float32(4.0), np.float32(np.inf)))
    t = pdet.lowest_threshold(m, 0.5)                   # three may be flagged: just above 3.0
    assert (m >= t).sum() == 3 and t > 3.0
    assert (m >= pdet.lowest_threshold(m, 0.0)).sum() == 0
    assert pdet.lowest_threshold(m, 1.0) == float("-inf")


def flows_for(ts, margins_by_category):
    """Test days whose margins are given per category, for the rule alone."""
    category, margin = [], []
    for name, values in margins_by_category.items():
        category += [name] * len(values)
        margin += list(values)
    n = len(category)
    y = np.array([1 if c == ts.INBOUND else 0 for c in category], dtype=np.int8)
    remote = np.array([f"r{i}" for i in range(n)], dtype=object)
    test = ts.Flows(np.zeros((n, 14), dtype=np.float32), y, np.array(category, dtype=object), remote,
                    np.array(["2026-10-31T00:00:00"] * n, dtype="datetime64[us]"))
    return test, np.array(margin, dtype=np.float32)


def test_the_stricter_limit_decides_and_the_rule_reads_recall_at_the_threshold(pdet, ts):
    benign = list(np.linspace(-9, -1, 400)) + [2.0]       # 1 of 401 high: within 0.5%
    operator = [-5.0] * 18 + [3.0, 3.5]                   # 2 of 20 high: 5% allows one, so just above 3.0
    inbound = [6.0] * 97 + [2.9] * 3                      # three fall below the operator's limit
    test, margin = flows_for(ts, {ts.SELF: benign, ts.OPERATOR: operator, ts.INBOUND: inbound})
    threshold, figures, met = pdet.decide(test, margin, set())
    assert threshold["from_operator_limit"] > threshold["from_benign_limit"]
    assert threshold["margin"] == threshold["from_operator_limit"]
    assert figures["by_category"][ts.OPERATOR]["flagged"] == 1
    assert figures["inbound"]["flagged"] == 97 and met            # 97% of inbound: above the 95% floor
    inbound = [6.0] * 94 + [2.9] * 6
    test, margin = flows_for(ts, {ts.SELF: benign, ts.OPERATOR: operator, ts.INBOUND: inbound})
    _, figures, met = pdet.decide(test, margin, set())
    assert figures["inbound"]["fraction"] == pytest.approx(0.94) and not met


def separable_run(ts, harmonize, tmp_path):
    """Section 7 run on a separable toy, so that there is a record to reproduce:
    every attacking address sends one flow, so the test days' attackers are
    all new, as the rule needs some to be."""
    rng = np.random.default_rng(7)
    attackers = [f"198.51.100.{i}" for i in range(120)] + [f"203.0.113.{i}" for i in range(120)]
    rows = (flow_rows(harmonize, 240, times("2026-10-24T15:00:00", 200, 240, rng), True, ts.INBOUND,
                      attackers, rng)
            + flow_rows(harmonize, 400, times("2026-10-24T15:00:00", 200, 400, rng), False, ts.SELF,
                        ["52.216.0.1"], rng)
            + flow_rows(harmonize, 40, times("2026-10-24T15:00:00", 200, 40, rng), False, ts.OPERATOR,
                        ["192.0.2.50"], rng))
    write_csv(harmonize, tmp_path / "flows.csv", rows)
    flows = ts.read_flows(tmp_path / "flows.csv")
    params = dict(ts.PARAMS, n_estimators=5, max_depth=3)
    recorded = ts.run(flows, [], params, tmp_path / "timesplit.json", log=lambda *_: None)
    return flows, recorded


def test_h_is_put_to_work_only_as_section_7_recorded_it(pdet, ts, harmonize, tmp_path):
    flows, recorded = separable_run(ts, harmonize, tmp_path)
    recorded["models"]["H"]["benign"]["flagged"] += 1               # a record the model does not match
    with pytest.raises(SystemExit, match="does not reproduce"):
        pdet.run(flows, recorded, tmp_path / "m.ubj", tmp_path / "pd.json", log=lambda *_: None)
    saved = json.loads((tmp_path / "pd.json").read_text())
    assert saved["reproduction"]["reproduced"] is False and saved["complete"] is False
    assert saved["reproduction"]["checks"]["benign"]["recorded"] != saved["reproduction"]["checks"]["benign"]["now"]
    assert "threshold" not in saved and not (tmp_path / "m.ubj").exists()


def test_the_rule_writes_the_model_its_hash_and_counts_never_an_address(pdet, ts, harmonize, tmp_path):
    flows, recorded = separable_run(ts, harmonize, tmp_path)
    result = pdet.run(flows, recorded, tmp_path / "out" / "m.ubj", tmp_path / "out" / "pd.json",
                      log=lambda *_: None)
    assert result["reproduction"]["reproduced"] and result["rule_met"] and result["complete"]
    assert result["params"] == recorded["params"] and result["cut"] == recorded["cut"]
    model = tmp_path / "out" / "m.ubj"
    assert result["model"]["sha256"] == pdet.sha256(model) and result["model"]["trees"] == 5
    assert result["versions"]["xgboost"] and result["recorded_versions"] == recorded["versions"]
    written = (tmp_path / "out" / "pd.json").read_text()
    for address in ("198.51.100.", "203.0.113.", "192.0.2.50", "52.216."):
        assert address not in written
    import xgboost as xgb
    served = xgb.Booster()
    served.load_model(str(model))                                  # what the deployment will load
    train, test = ts.split(flows, recorded["cut"])
    margin = served.predict(xgb.DMatrix(test.X), output_margin=True)
    assert int((margin >= result["threshold"]["margin"]).sum()) == (
        result["at_threshold"]["inbound"]["flagged"] + result["at_threshold"]["benign"]["flagged"])
    lines = []
    pdet.report(json.loads(written), log=lines.append)
    assert any("Rule met" in line for line in lines)


def test_a_rule_that_cannot_be_met_writes_no_model(pdet, ts, harmonize, tmp_path, monkeypatch):
    flows, recorded = separable_run(ts, harmonize, tmp_path)
    monkeypatch.setattr(pdet, "RECALL_FLOOR", 1.01)               # a floor nothing can reach
    result = pdet.run(flows, recorded, tmp_path / "m.ubj", tmp_path / "pd.json", log=lambda *_: None)
    assert result["reproduction"]["reproduced"] and not result["rule_met"]
    assert "model" not in result and not (tmp_path / "m.ubj").exists()
    lines = []
    pdet.report(result, log=lines.append)
    assert any("NOT MET" in line for line in lines)
