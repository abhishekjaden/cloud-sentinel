"""
Train the binary detector on each harmonized dataset and test it on every
other one, so that one table says how much of what it learns is the attacks
and how much is the network it learned them on.

The tables come from `harmonize.py`; this script never reads the raw data.
With three datasets it fits ten models — for each dataset, one on a stratified
70% of it, tested on the other 30% (the diagonal: what the schema can do on
the network it was trained on); one on all of it, tested on each other dataset
whole (the off-diagonal: the cross-dataset figure); one on the other two
together, tested on it (leave-one-dataset-out); and one on all three, which
scores any `--extra` table, such as the honeypot's flows, that is never
trained on. The settings are the served models' (`train.py`); only the
features differ. The expectations the figures are read against were written
before the first run, in `docs/generalization-protocol.md`.

    python ml/evaluation/cross_matrix.py --data ml/harmonized/cic2017.npz ml/harmonized/cic2018.npz \
        ml/harmonized/unsw.npz --out ml/models/harmonized_matrix.json

    # a quick trial on a tenth of every table, with thirty trees
    python ml/evaluation/cross_matrix.py --data ... --sample 0.1 --estimators 30 --out /tmp/trial.json

    # the honeypot's flows, scored by every model and trained on by none
    python ml/evaluation/cross_matrix.py --data ... --extra ml/harmonized/honeypot.npz --out ...

    # the tables again from a saved result
    python ml/evaluation/cross_matrix.py --report ml/models/harmonized_matrix.json

The result is written after every cell, so an interrupted run keeps what it
measured; every cell carries each raw label's count and flagged fraction, so
the per-family tables can be printed again without the data.
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harmonize import load  # noqa: E402

SEED = 42
PARAMS = dict(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8)
TEST_FRACTION = 0.3


# ------------------------------------------------------------------ metrics
def auc(scores, y):
    """Area under the ROC curve from scores and 0/1 labels, exactly, with
    tied scores counted half (the Mann–Whitney form)."""
    scores, y = np.asarray(scores, dtype=np.float64), np.asarray(y)
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    if pos == 0 or neg == 0:
        return float("nan")
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores), dtype=np.float64)
    sorted_scores = scores[order]
    # average rank within each run of equal scores
    boundaries = np.flatnonzero(np.diff(sorted_scores)) + 1
    starts = np.concatenate([[0], boundaries])
    ends = np.concatenate([boundaries, [len(scores)]])
    for s, e in zip(starts, ends):
        ranks[order[s:e]] = (s + e + 1) / 2.0        # ranks are 1-based: mean of s+1 .. e
    return float((ranks[y == 1].sum() - pos * (pos + 1) / 2.0) / (pos * neg))


def metrics(margin, y):
    """AUC, and precision, recall, F1 and the false-positive rate at a
    probability of 0.5 (a log-odds margin of zero), as the served route decides."""
    y = np.asarray(y)
    flagged = np.asarray(margin) >= 0
    tp = int((flagged & (y == 1)).sum())
    fp = int((flagged & (y == 0)).sum())
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(pos, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    return {"n": int(len(y)), "attack": pos, "auc": round(auc(margin, y), 6), "f1": round(f1, 4),
            "precision": round(precision, 4), "recall": round(recall, 4),
            "false_positive_rate": round(fp / max(neg, 1), 6), "flagged": int(flagged.sum())}


def per_raw(margin, y, raw, names):
    """Each raw label's count and flagged fraction in a scored table."""
    flagged = np.asarray(margin) >= 0
    out = {}
    for code, name in enumerate(names):
        m = raw == code
        n = int(m.sum())
        if n:
            out[name] = {"n": n, "attack": bool(y[m][0]), "flagged_as_attack": round(float(flagged[m].sum()) / n, 4)}
    return out


# ------------------------------------------------------------------- fitting
def split(y, fraction=TEST_FRACTION, seed=SEED):
    """Stratified train/test indices: the same fraction of each class."""
    rng = np.random.default_rng(seed)
    train, test = [], []
    for cls in (0, 1):
        idx = np.flatnonzero(y == cls)
        rng.shuffle(idx)
        cut = int(round(len(idx) * (1 - fraction)))
        train.append(idx[:cut])
        test.append(idx[cut:])
    return np.sort(np.concatenate(train)), np.sort(np.concatenate(test))


def subsample(n, fraction, seed=SEED):
    rng = np.random.default_rng(seed)
    return np.sort(rng.choice(n, size=max(1, int(n * fraction)), replace=False))


def fit(X, y, params=PARAMS, threads=0):
    """The served models' settings through XGBoost's own API, which needs no
    scikit-learn: the sklearn wrapper's n_estimators is the number of rounds
    and its learning_rate is eta."""
    import xgboost as xgb
    y = np.asarray(y)
    spw = float((y == 0).sum()) / max(int((y == 1).sum()), 1)
    settings = {"objective": "binary:logistic", "eval_metric": "auc", "tree_method": "hist",
                "max_depth": params["max_depth"], "eta": params["learning_rate"],
                "subsample": params["subsample"], "colsample_bytree": params["colsample_bytree"],
                "scale_pos_weight": spw, "seed": SEED, "nthread": threads, "verbosity": 0}
    return xgb.train(settings, xgb.DMatrix(X, label=y), num_boost_round=params["n_estimators"])


def score(model, X):
    import xgboost as xgb
    return model.predict(xgb.DMatrix(X), output_margin=True)


class Dataset:
    def __init__(self, path, sample=None):
        self.X, self.y, self.raw, self.meta = load(path)
        self.name = self.meta["dataset"]
        self.key = self.meta["source"]
        self.features = self.meta["features"]
        self.raw_names = list(self.meta["raw_labels"])
        if sample and sample < 1:
            keep = subsample(len(self.y), sample)
            self.X, self.y, self.raw = self.X[keep], self.y[keep], self.raw[keep]
        self.train_idx, self.test_idx = split(self.y)

    def summary(self):
        return {"dataset": self.name, "rows": int(len(self.y)), "attack": int(self.y.sum()),
                "raw_labels": len(self.raw_names)}


def cell(kind, train_names, test, model, X, y, raw, fit_seconds):
    started = time.time()
    margin = score(model, X)
    out = {"kind": kind, "train": train_names, "test": test.name, **metrics(margin, y),
           "per_raw_label": per_raw(margin, y, raw, test.raw_names),
           "fit_seconds": round(fit_seconds, 1), "score_seconds": round(time.time() - started, 1)}
    return out


def run(datasets, extras, params, out, loo=True, log=print):
    """All the cells, written to `out` as each is finished."""
    features = datasets[0].features
    for d in datasets[1:] + extras:
        if d.features != features:
            sys.exit(f"{d.name} has features {d.features}; the first table has {features}. "
                     "Every table must be harmonized the same way (the same --with-port).")
    result = {"features": features, "params": params, "test_fraction": TEST_FRACTION, "seed": SEED,
              "datasets": [d.summary() for d in datasets], "extras": [d.summary() for d in extras],
              "cells": [], "complete": False, "started": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)

    def record(c):
        result["cells"].append(c)
        out.write_text(json.dumps(result, indent=1))
        log(f"  {c['kind']:<14} {' + '.join(c['train']):<40} → {c['test']:<18} AUC {c['auc']:.4f}  "
            f"F1 {c['f1']:.4f}  recall {c['recall']:.4f}  FPR {c['false_positive_rate']:.4f}  "
            f"(fit {c['fit_seconds']:.0f} s)")

    full_models = {}
    for d in datasets:
        log(f"{d.name}: {len(d.y):,} rows, {int(d.y.sum()):,} attack")
        started = time.time()
        within = fit(d.X[d.train_idx], d.y[d.train_idx], params)
        record(cell("within", [d.name], d, within, d.X[d.test_idx], d.y[d.test_idx], d.raw[d.test_idx],
                    time.time() - started))
        started = time.time()
        full_models[d.name] = fit(d.X, d.y, params)
        fit_seconds = time.time() - started
        for other in datasets:
            if other is not d:
                record(cell("cross", [d.name], other, full_models[d.name], other.X, other.y, other.raw, fit_seconds))
        for extra in extras:
            record(cell("extra", [d.name], extra, full_models[d.name], extra.X, extra.y, extra.raw, fit_seconds))
    if loo and len(datasets) > 2:
        for held in datasets:
            others = [d for d in datasets if d is not held]
            started = time.time()
            model = fit(np.concatenate([d.X for d in others]), np.concatenate([d.y for d in others]), params)
            record(cell("leave_one_out", [d.name for d in others], held, model, held.X, held.y, held.raw,
                        time.time() - started))
    if extras:
        started = time.time()
        model = fit(np.concatenate([d.X for d in datasets]), np.concatenate([d.y for d in datasets]), params)
        for extra in extras:
            record(cell("extra", [d.name for d in datasets], extra, model, extra.X, extra.y, extra.raw,
                        time.time() - started))
    result["complete"] = True
    result["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    out.write_text(json.dumps(result, indent=1))
    return result


# -------------------------------------------------------------------- report
def report(result, verbose=False, log=print):
    names = [d["dataset"] for d in result["datasets"]]
    cells = {(tuple(c["train"]), c["test"], c["kind"]): c for c in result["cells"]}
    width = max(len(n) for n in names + ["trained on ↓ / tested on →"]) + 2
    log(("" if result.get("complete") else f"INCOMPLETE: {len(result['cells'])} cells so far\n")
        + f"Harmonized schema, {len(result['features'])} features; AUC with F1 in brackets, "
        f"diagonal on a held-out {result['test_fraction']:.0%} of the same dataset:\n")
    log("| " + "trained on ↓ / tested on →".ljust(width) + " | " + " | ".join(n.ljust(22) for n in names) + " |")
    log("|" + "-" * (width + 2) + "|" + "|".join("-" * 24 for _ in names) + "|")
    for a in names:
        row = []
        for b in names:
            c = cells.get(((a,), b, "within" if a == b else "cross"))
            row.append(f"{c['auc']:.3f} ({c['f1']:.3f})".ljust(22) if c else "—".ljust(22))
        log("| " + a.ljust(width) + " | " + " | ".join(row) + " |")
    loo = [c for c in result["cells"] if c["kind"] == "leave_one_out"]
    if loo:
        row = []
        for b in names:
            c = next((c for c in loo if c["test"] == b), None)
            row.append(f"{c['auc']:.3f} ({c['f1']:.3f})".ljust(22) if c else "—".ljust(22))
        log("| " + "the other two".ljust(width) + " | " + " | ".join(row) + " |")
    extras = [c for c in result["cells"] if c["kind"] == "extra"]
    if extras:
        log("\nTables scored but never trained on:\n\n| trained on | tested on | flows | attack | AUC | recall | FPR |\n|---|---|---|---|---|---|---|")
        for c in extras:
            log(f"| {' + '.join(c['train'])} | {c['test']} | {c['n']:,} | {c['attack']:,} | {c['auc']:.3f} | "
                f"{c['recall']:.3f} | {c['false_positive_rate']:.4f} |")
    shown = [c for c in result["cells"] if c["kind"] in ("cross", "leave_one_out", "extra")] if verbose else \
            [c for c in result["cells"] if c["kind"] in ("leave_one_out", "extra")]
    for c in shown:
        log(f"\n{' + '.join(c['train'])} → {c['test']}, by the test set's own labels:\n\n"
            "| label | counted as | flows | flagged as attack |\n|---|---|---|---|")
        for name, s in sorted(c["per_raw_label"].items(), key=lambda kv: -kv[1]["n"]):
            log(f"| {name} | {'attack' if s['attack'] else 'benign'} | {s['n']:,} | {s['flagged_as_attack']:.4f} |")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data", nargs="+", help="harmonized .npz tables, two or more")
    parser.add_argument("--extra", nargs="*", default=[], help="tables to score with every model and train on with none")
    parser.add_argument("--out", default="ml/models/harmonized_matrix.json")
    parser.add_argument("--sample", type=float, help="use this fraction of every table (a trial)")
    parser.add_argument("--estimators", type=int, help="trees per model (a trial; the default is the served 300)")
    parser.add_argument("--no-loo", action="store_true", help="skip the leave-one-dataset-out models")
    parser.add_argument("--report", help="print the tables from a saved result, without data")
    parser.add_argument("--verbose", action="store_true", help="per-label tables for every cross cell too")
    args = parser.parse_args()
    if args.report:
        report(json.loads(Path(args.report).read_text()), args.verbose)
        return
    if not args.data or len(args.data) < 2:
        parser.error("--data needs at least two harmonized tables")
    params = dict(PARAMS, n_estimators=args.estimators) if args.estimators else dict(PARAMS)
    started = time.time()
    datasets = [Dataset(p, args.sample) for p in args.data]
    extras = [Dataset(p, None) for p in args.extra]
    result = run(datasets, extras, params, args.out, loo=not args.no_loo)
    print()
    report(result)
    print(f"\nwrote {args.out} ({(time.time() - started) / 60:.1f} min)")


if __name__ == "__main__":
    main()
