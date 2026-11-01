"""
Train the detector on the honeypot's first days and test it on its last ones,
so that a figure says what the platform's own traffic can teach a detector
about the traffic that reaches the platform next.

`docs/generalization-protocol.md`, section 7, fixes everything here before the
run: the cut (flows that began before 30 October 2026 00:00 UTC train, the
rest test), the three models, the served settings and threshold, and the four
expectations G7-G10 with what each outcome will be taken to mean.

- **H** is trained on the training days alone, on the fourteen features of
  the harmonized schema (no port);
- **P+H** on the three public tables and the training days together;
- **B** is a baseline, not a model: the one feature and threshold that best
  separate the training days' attack and benign flows (balanced accuracy,
  either direction), applied to the test days unchanged. What it does, a
  model can claim no credit for.

Every figure is on the test days, at a probability of 0.5 as the served route
decides: the fraction of unsolicited inbound flows flagged; the same for flows
from addresses that began no unsolicited flow in the training days (attackers
the model has not met); the fraction of benign flows flagged, with the
operator's visits apart; and AUC, which needs no threshold.

    python ml/evaluation/honeypot_timesplit.py --flows ml/harmonized/honeypot-flows.csv \\
        --public ml/harmonized/cic2017.npz ml/harmonized/cic2018.npz ml/harmonized/unsw.npz \\
        --out ml/models/honeypot_timesplit.json

    # the tables again from a saved result
    python ml/evaluation/honeypot_timesplit.py --report ml/models/honeypot_timesplit.json

The flows are `scripts/pcap_flows.py`'s CSV, read the way `harmonize.py`
reads it, so that a row the harmonizer drops (a feature that is not a finite
number) is dropped here too, and counted. The CSV holds addresses and is not
committed; the result holds counts and fractions only.
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cross_matrix import PARAMS, auc, fit, score, versions  # noqa: E402
from harmonize import FEATURES, load, numeric  # noqa: E402

CUT = "2026-10-30T00:00:00Z"          # fixed in the protocol, section 7, before the run
RECALL_TARGET = 0.93                  # G7 and G8
BENIGN_LIMIT = 0.01                   # G9: the test days' benign flows
OPERATOR_LIMIT = 0.10                 # G9: the operator's visits among them
PUBLIC_GAIN_LIMIT = 0.01              # G10: P+H's recall over H's, in absolute terms
INBOUND, SELF, OPERATOR = "unsolicited inbound", "self-initiated", "operator"


class Flows:
    """The honeypot's flows: features, labels, and what the record is read by."""

    def __init__(self, X, y, category, remote, began, dropped=0):
        self.X, self.y, self.category, self.remote, self.began = X, y, category, remote, began
        self.dropped = dropped

    def __len__(self):
        return len(self.y)

    def take(self, mask):
        return Flows(self.X[mask], self.y[mask], self.category[mask], self.remote[mask], self.began[mask])


def read_flows(path):
    """`pcap_flows.py`'s CSV → Flows, the features read as `harmonize.py`'s
    `flows` source reads them, rows with a non-finite feature dropped."""
    import pandas as pd
    columns = FEATURES + ["label", "category", "remote", "first_seen"]
    frame = pd.read_csv(path, usecols=columns, dtype=str, keep_default_na=False)
    X = np.column_stack([numeric(frame[f]) for f in FEATURES]).astype(np.float32)
    ok = np.isfinite(X).all(axis=1)
    y = (frame["label"].str.strip().str.lower() != "benign").to_numpy().astype(np.int8)
    category = frame["category"].str.strip().to_numpy(dtype=object)
    remote = frame["remote"].str.strip().to_numpy(dtype=object)
    began = pd.to_datetime(frame["first_seen"].str.strip(), utc=True, format="ISO8601")
    began = began.dt.tz_localize(None).to_numpy().astype("datetime64[us]")     # UTC, without the zone
    return Flows(X[ok], y[ok], category[ok], remote[ok], began[ok], dropped=int((~ok).sum()))


def split(flows, cut=CUT):
    """(training, test): by the time each flow began, the cut itself in test."""
    at = np.datetime64(cut.replace("Z", ""), "us")
    before = flows.began < at
    return flows.take(before), flows.take(~before)


# ------------------------------------------------------------------ baseline
def best_single_feature(X, y, names=FEATURES):
    """The one feature and threshold with the highest balanced accuracy on
    (X, y), flagging values at or above the threshold or at or below it.
    Ties go to the earlier feature, then the lower threshold."""
    y = np.asarray(y).astype(bool)
    pos, neg = int(y.sum()), int((~y).sum())
    if pos == 0 or neg == 0:
        raise ValueError("the baseline needs both classes in the training days")
    best = None
    for j, name in enumerate(names):
        v = np.asarray(X[:, j], dtype=np.float64)
        order = np.argsort(v, kind="mergesort")
        sv, sy = v[order], y[order]
        cum_pos = np.concatenate([[0], np.cumsum(sy)])          # positives among the first k sorted
        cum_neg = np.concatenate([[0], np.cumsum(~sy)])
        starts = np.concatenate([[0], np.flatnonzero(np.diff(sv)) + 1])   # first index of each value
        ends = np.concatenate([starts[1:], [len(sv)]])                    # one past its last index
        # flag v >= value: everything from the value's first index on
        tp = pos - cum_pos[starts]
        fp = neg - cum_neg[starts]
        ba_ge = (tp / pos + (1 - fp / neg)) / 2
        # flag v <= value: everything up to the value's last index
        tp = cum_pos[ends]
        fp = cum_neg[ends]
        ba_le = (tp / pos + (1 - fp / neg)) / 2
        for direction, ba in ((">=", ba_ge), ("<=", ba_le)):
            k = int(np.argmax(ba))
            candidate = (float(ba[k]), j, direction, float(sv[starts[k]]))
            if best is None or candidate[0] > best[0] + 1e-12:
                best = candidate
    ba, j, direction, threshold = best
    return {"feature": names[j], "index": j, "direction": direction, "threshold": threshold,
            "balanced_accuracy_training": round(ba, 6)}


def apply_rule(rule, X):
    """(flagged, a score for AUC) of a single-feature rule."""
    v = np.asarray(X[:, rule["index"]], dtype=np.float64)
    if rule["direction"] == ">=":
        return v >= rule["threshold"], v
    return v <= rule["threshold"], -v


# ------------------------------------------------------------------ measures
def measure(flagged, scores, test, train_attackers):
    """Every figure section 7 reads, for one model on the test days."""
    flagged = np.asarray(flagged, dtype=bool)
    attack = test.y == 1
    new = attack & np.fromiter((r not in train_attackers for r in test.remote), dtype=bool, count=len(test))

    def frac(mask):
        n = int(mask.sum())
        return {"n": n, "flagged": int((flagged & mask).sum()),
                "fraction": round(float((flagged & mask).sum()) / n, 6) if n else None}

    out = {"auc": round(auc(scores, test.y), 6),
           "inbound": frac(attack),
           "inbound_new_addresses": {**frac(new), "addresses": int(len(set(test.remote[new])))},
           "benign": frac(~attack)}
    out["by_category"] = {c: frac(test.category == c) for c in sorted(set(test.category))}
    return out


def operator_fraction(m):
    op = m["by_category"].get(OPERATOR)
    return op["fraction"] if op and op["n"] else 0.0


def at_least(value, target):
    return value is not None and value >= target - 1e-12


def at_most(value, limit):
    return value is not None and value <= limit + 1e-12


def expectations(models):
    """G7-G10 read from the measured figures, as section 7 states them. A
    figure with nothing to count (no such flows in the test days) meets
    nothing."""
    h = models["H"]
    out = {
        "G7": {"value": h["inbound"]["fraction"], "met": at_least(h["inbound"]["fraction"], RECALL_TARGET)},
        "G8": {"value": h["inbound_new_addresses"]["fraction"],
               "met": at_least(h["inbound_new_addresses"]["fraction"], RECALL_TARGET)},
        "G9": {"value": h["benign"]["fraction"], "operator": operator_fraction(h),
               "met": at_most(h["benign"]["fraction"], BENIGN_LIMIT)
               and at_most(operator_fraction(h), OPERATOR_LIMIT)},
    }
    if "P+H" in models:
        gain = models["P+H"]["inbound"]["fraction"] - h["inbound"]["fraction"]
        out["G10"] = {"value": round(gain, 6), "met": at_most(gain, PUBLIC_GAIN_LIMIT)}
    b = models["B"]
    out["baseline_at_G7_and_G9_levels"] = bool(
        at_least(b["inbound"]["fraction"], RECALL_TARGET) and at_most(b["benign"]["fraction"], BENIGN_LIMIT)
        and at_most(operator_fraction(b), OPERATOR_LIMIT))
    return out


# ----------------------------------------------------------------------- run
def read_public(paths):
    """[(X, y, name)] of harmonized public tables, refused unless they are on
    the fourteen features without the port, as section 7 fixes."""
    public = []
    for path in paths:
        X, y, _, meta = load(path)
        if meta["features"] != FEATURES:
            sys.exit(f"{path} has features {meta['features']}; section 7 uses the fourteen without the port")
        public.append((X, y, meta["dataset"]))
    return public


def describe(part):
    if not len(part):
        return {"flows": 0}
    return {"flows": int(len(part)), "attack": int(part.y.sum()),
            "first_began": str(part.began.min()) + "Z", "last_began": str(part.began.max()) + "Z",
            "by_category": {c: int((part.category == c).sum()) for c in sorted(set(part.category))}}


def run(flows, public, params, out, cut=CUT, log=print):
    train, test = split(flows, cut)
    if not len(train) or not len(test) or train.y.min() == train.y.max():
        sys.exit("the cut leaves a side empty or the training days with one class; nothing is run")
    train_attackers = set(train.remote[train.y == 1])
    result = {"cut": cut, "params": params, "versions": versions(), "features": FEATURES,
              "dropped_non_finite": flows.dropped, "training": describe(train), "test": describe(test),
              "training_attack_addresses": len(train_attackers), "models": {},
              "started": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    log(f"training: {len(train):,} flows before {cut}; test: {len(test):,} flows from it on")

    started = time.time()
    model = fit(train.X, train.y, params)
    margin = score(model, test.X)
    result["models"]["H"] = {**measure(margin >= 0, margin, test, train_attackers),
                             "trained_on": "the training days", "fit_seconds": round(time.time() - started, 1)}

    if public:
        started = time.time()
        X = np.concatenate([p[0] for p in public] + [train.X])
        y = np.concatenate([p[1] for p in public] + [train.y])
        model = fit(X, y, params)
        margin = score(model, test.X)
        result["models"]["P+H"] = {**measure(margin >= 0, margin, test, train_attackers),
                                   "trained_on": " + ".join([p[2] for p in public] + ["the training days"]),
                                   "fit_seconds": round(time.time() - started, 1)}

    rule = best_single_feature(train.X, train.y)
    flagged, scores = apply_rule(rule, test.X)
    result["models"]["B"] = {**measure(flagged, scores, test, train_attackers), "rule": rule}

    result["expectations"] = expectations(result["models"])
    result["complete"] = True
    result["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=1) + "\n")
    return result


def report(result, log=print):
    pct = lambda f: "—" if f is None else f"{100 * f:.2f}%"  # noqa: E731
    tr, te = result["training"], result["test"]
    log(f"Cut {result['cut']}: training {tr['flows']:,} flows ({tr['attack']:,} attack, {tr['first_began']} → "
        f"{tr['last_began']}), test {te['flows']:,} ({te['attack']:,} attack, {te['first_began']} → "
        f"{te['last_began']}); {result['dropped_non_finite']} dropped for a non-finite feature.\n")
    log("| model | AUC | inbound flagged | from new addresses | benign flagged | operator's visits flagged |")
    log("|---|---|---|---|---|---|")
    for name, m in result["models"].items():
        label = name if name != "B" else (f"B: {m['rule']['feature']} {m['rule']['direction']} "
                                          f"{m['rule']['threshold']:g}")
        op = m["by_category"].get(OPERATOR, {"n": 0, "flagged": 0, "fraction": None})
        new = m["inbound_new_addresses"]
        log(f"| {label} | {m['auc']:.3f} | {pct(m['inbound']['fraction'])} of {m['inbound']['n']:,} | "
            f"{pct(new['fraction'])} of {new['n']:,} ({new['addresses']:,} addresses) | "
            f"{pct(m['benign']['fraction'])} of {m['benign']['n']:,} | {op['flagged']} of {op['n']:,} |")
    e = result["expectations"]
    log("\n| | Expectation (section 7) | Result | |\n|---|---|---|---|")
    log(f"| G7 | H flags at least 93% of inbound | {pct(e['G7']['value'])} | {'Met' if e['G7']['met'] else 'Not met'} |")
    log(f"| G8 | ... of inbound from new addresses | {pct(e['G8']['value'])} | {'Met' if e['G8']['met'] else 'Not met'} |")
    log(f"| G9 | at most 1% of benign, at most 10% of the operator's visits | {pct(e['G9']['value'])}; "
        f"{pct(e['G9']['operator'])} | {'Met' if e['G9']['met'] else 'Not met'} |")
    if "G10" in e:
        log(f"| G10 | P+H at most one point above H | {100 * e['G10']['value']:+.2f} points | "
            f"{'Met' if e['G10']['met'] else 'Not met'} |")
    log(f"\nBaseline B at G7's and G9's levels: {'yes — the task is easy on this honeypot' if e['baseline_at_G7_and_G9_levels'] else 'no'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--flows", help="scripts/pcap_flows.py's CSV")
    parser.add_argument("--public", nargs="*", default=[], help="harmonized public tables for P+H (no port)")
    parser.add_argument("--cut", default=CUT, help="the protocol's cut; another value is a different experiment")
    parser.add_argument("--out", default="ml/models/honeypot_timesplit.json")
    parser.add_argument("--estimators", type=int, help="trees per model (a trial; the default is the served 300)")
    parser.add_argument("--report", help="print the tables from a saved result, without data")
    args = parser.parse_args()
    if args.report:
        report(json.loads(Path(args.report).read_text()))
        return
    if not args.flows:
        parser.error("--flows is needed")
    params = dict(PARAMS, n_estimators=args.estimators) if args.estimators else dict(PARAMS)
    started = time.time()
    flows = read_flows(args.flows)
    result = run(flows, read_public(args.public), params, args.out, cut=args.cut)
    print()
    report(result)
    print(f"\nwrote {args.out} ({(time.time() - started) / 60:.1f} min)")


if __name__ == "__main__":
    main()
