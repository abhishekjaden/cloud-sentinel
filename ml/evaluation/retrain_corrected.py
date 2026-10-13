"""
Retrain CloudSentinel's intrusion-detection models on the corrected CICIDS2017
(Engelen, Rimmer and Joosen, IEEE SPW 2021) and compare them with the served
models, which were trained on the original release.

The served models stay as they are: this is a measurement, not a release. It
uses the served models' family labels, split and XGBoost settings
(ml/processing/preprocessing.py, ml/training/train.py), so a difference in the
results comes from the data, not the method.

    # 1. What is in the download: files, rows, columns, labels. No training.
    python ml/evaluation/retrain_corrected.py --data PATH --inspect

    # 2. A quick end-to-end check on 10% of the rows (a few minutes)
    python ml/evaluation/retrain_corrected.py --data PATH --sample 0.1

    # 3. The comparison: the served split and settings on the corrected data
    python ml/evaluation/retrain_corrected.py --data PATH --out ml/models/corrected_metrics.json

    # 4. Generalisation: train on the other days, test on Friday, whose DDoS
    #    and botnet traffic occur on no other day
    python ml/evaluation/retrain_corrected.py --data PATH --holdout-day friday \
        --out ml/models/holdout_metrics.json

PATH is the folder holding the corrected CSVs (searched recursively).
"""
import argparse
import json
import re
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

SEED = 42
PARAMS = dict(n_estimators=300, max_depth=8, learning_rate=0.1,
              subsample=0.8, colsample_bytree=0.8)
FAMILIES = ["BENIGN", "Bot", "BruteForce", "DDoS", "DoS", "Infiltration", "PortScan", "WebAttack"]

# Identifiers, not behaviour: the served pipeline drops these so a model cannot
# key on who or when. Source port is dropped too; the original release's
# feature set had none, and an ephemeral port says nothing about the flow.
IDENTIFIERS = {"id", "flowid", "srcip", "sourceip", "dstip", "destinationip",
               "srcport", "sourceport", "timestamp", "attemptedcategory", "label"}


def key(name):
    """A column name reduced to letters and digits, lower case: 'Flow ID' and
    'flow_id' are the same column."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def family(raw, infiltration_portscan):
    """A label as one of the served models' eight families, or None if unknown.
    Attempted flows are dealt with before this is called."""
    s = re.sub(r"\s+", " ", str(raw)).strip().lower()
    if s == "benign":
        return "BENIGN"
    if s.startswith(("dos hulk", "dos goldeneye", "dos slowloris", "dos slowhttptest", "heartbleed")):
        return "DoS"
    if s == "ddos" or s.startswith("ddos"):
        return "DDoS"
    if s in ("portscan", "port scan"):
        return "PortScan"
    if s.startswith("infiltration") and "portscan" in s.replace(" ", ""):
        return "PortScan" if infiltration_portscan == "portscan" else "Infiltration"
    if s.startswith("infiltration"):
        return "Infiltration"
    if s.startswith(("ftp-patator", "ssh-patator")):
        return "BruteForce"
    if s.startswith("web attack"):
        return "WebAttack"
    if s in ("bot", "botnet") or s.startswith("botnet") or s.startswith("bot "):
        return "Bot"
    return None


def attempted(raw):
    return "attempted" in str(raw).lower()


def find_csvs(data):
    paths = sorted(p for p in Path(data).rglob("*") if p.suffix.lower() == ".csv")
    if not paths:
        sys.exit(f"No CSV files under {data}. Point --data at the folder you unzipped.")
    return paths


def columns_of(path):
    head = pd.read_csv(path, nrows=0, encoding="latin-1")
    return [c.strip() for c in head.columns]


def label_column(cols):
    for c in cols:
        if key(c) == "label":
            return c
    return None


def inspect(paths, args):
    total = 0
    union = {}
    labels = {}
    for p in paths:
        cols = columns_of(p)
        lab = label_column(cols)
        for c in cols:
            union.setdefault(key(c), c)
        if lab is None:
            print(f"  {p.name}: NO LABEL COLUMN ({len(cols)} columns) - skipped")
            continue
        counts = pd.read_csv(p, usecols=lambda c, lab=lab: c.strip() == lab, encoding="latin-1",
                             low_memory=False).iloc[:, 0].astype(str).str.strip().value_counts()
        rows = int(counts.sum())
        total += rows
        print(f"  {p.name}: {rows:,} rows, {len(cols)} columns")
        for name, n in counts.items():
            labels[name] = labels.get(name, 0) + int(n)
    print(f"\n{len(paths)} files, {total:,} rows")
    features = [c for k, c in union.items() if k not in IDENTIFIERS]
    print(f"{len(features)} candidate feature columns (identifiers removed): " + ", ".join(features))
    print("\nLabels, and the family each becomes:")
    unknown = []
    for name, n in sorted(labels.items(), key=lambda kv: -kv[1]):
        if attempted(name):
            fate = "BENIGN (attempted)" if args.attempted == "benign" else "dropped (attempted)"
        else:
            fate = family(name, args.infiltration_portscan) or "UNKNOWN"
            if fate == "UNKNOWN":
                unknown.append(name)
        print(f"  {name!r:45} {n:>10,}  -> {fate}")
    if unknown:
        print(f"\n{len(unknown)} label(s) map to no family; send this output to Claude before training.")
    print(f"\nRough memory for the full load: {total * len(features) * 4 / 1e9:.1f} GB as float32.")


def load(paths, args):
    frames = []
    for p in paths:
        cols = columns_of(p)
        lab = label_column(cols)
        if lab is None:
            print(f"  {p.name}: no label column, skipped")
            continue
        df = pd.read_csv(p, encoding="latin-1", low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        if args.sample < 1.0:
            df = df.sample(frac=args.sample, random_state=SEED)
        raw = df[lab].astype(str).str.strip()
        is_attempted = raw.map(attempted)
        if args.attempted == "drop":
            df, raw, is_attempted = df[~is_attempted], raw[~is_attempted], is_attempted[~is_attempted]
        fam = raw.map(lambda s: family(s, args.infiltration_portscan))
        fam = fam.where(~is_attempted, "BENIGN")
        unknown = sorted(set(raw[fam.isna()]))
        if unknown:
            sys.exit(f"{p.name}: labels with no family: {unknown}. Run --inspect and send Claude the output.")
        features = [c for c in df.columns if key(c) not in IDENTIFIERS]
        X = df[features].apply(pd.to_numeric, errors="coerce")
        # A column that is mostly not numbers is not a feature; left in, its
        # blanks would take every row with them when NaN rows are dropped.
        blank = X.isna().mean()
        if (blank > 0.5).any():
            print(f"  {p.name}: not numeric, left out: {', '.join(blank[blank > 0.5].index)}")
            X = X.loc[:, blank <= 0.5]
        X = X.astype("float32")
        X.columns = [key(c) for c in X.columns]
        part = X.assign(_family=fam.values, _attempted=is_attempted.values, _file=p.stem.lower())
        frames.append(part)
        print(f"  {p.name}: {len(part):,} rows, {len(features)} features")
    data = pd.concat(frames, ignore_index=True, join="inner")
    before = len(data)
    data = data.replace([np.inf, -np.inf], np.nan).dropna()
    print(f"loaded {len(data):,} rows; dropped {before - len(data):,} with NaN or infinite values "
          f"(as the served pipeline does)")
    return data


def split(frame, size):
    """A stratified split when every family has at least two rows to share
    out, as in the served pipeline; a plain random one otherwise (only ever
    with --sample, where a rare family can shrink to a single row)."""
    from sklearn.model_selection import train_test_split
    counts = frame["_family"].value_counts()
    stratify = frame["_family"] if counts.min() >= 2 else None
    if stratify is None:
        print(f"  (not stratified: {', '.join(counts[counts < 2].index)} has a single row)")
    return train_test_split(frame, test_size=size, random_state=SEED, stratify=stratify)


def xy(frame):
    X = frame.drop(columns=["_family", "_attempted", "_file"])
    return X, frame["_family"].values


def train_binary(X_tr, y_tr, X_val, y_val):
    import xgboost as xgb
    spw = float((y_tr == 0).sum()) / max(int((y_tr == 1).sum()), 1)
    model = xgb.XGBClassifier(**PARAMS, scale_pos_weight=spw, objective="binary:logistic",
                              eval_metric="auc", tree_method="hist", n_jobs=-1, random_state=SEED)
    model.fit(X_tr, y_tr, eval_set=[(X_val, y_val)], verbose=False)
    return model, spw


def train_multiclass(X_tr, y_tr_raw, X_val, y_val_raw):
    import xgboost as xgb
    from sklearn.preprocessing import LabelEncoder
    le = LabelEncoder().fit(y_tr_raw)
    y_tr, y_val = le.transform(y_tr_raw), le.transform(y_val_raw)
    classes, counts = np.unique(y_tr, return_counts=True)
    freq = dict(zip(classes, counts))
    weights = np.array([len(y_tr) / (len(classes) * freq[c]) for c in y_tr])
    model = xgb.XGBClassifier(**PARAMS, objective="multi:softprob", num_class=len(classes),
                              eval_metric="mlogloss", tree_method="hist", n_jobs=-1,
                              random_state=SEED)
    model.fit(X_tr, y_tr, sample_weight=weights, eval_set=[(X_val, y_val)], verbose=False)
    return model, le


def binary_metrics(y, proba):
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
    pred = (proba >= 0.5).astype(int)
    benign = y == 0
    return {
        "auc": round(float(roc_auc_score(y, proba)), 6) if len(set(y)) > 1 else None,
        "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "false_positive_rate": round(float(pred[benign].mean()), 6) if benign.any() else None,
        "n_test": int(len(y)), "n_attack": int((y == 1).sum()), "n_benign": int(benign.sum()),
    }


def multiclass_metrics(y_raw, pred_raw):
    from sklearn.metrics import classification_report, confusion_matrix
    labels = [c for c in FAMILIES if c in set(y_raw) | set(pred_raw)]
    report = classification_report(y_raw, pred_raw, labels=labels, output_dict=True, zero_division=0)
    return {
        "macro_f1": round(report["macro avg"]["f1-score"], 4),
        "weighted_f1": round(report["weighted avg"]["f1-score"], 4),
        "accuracy": round(float(np.mean(np.asarray(y_raw) == np.asarray(pred_raw))), 4),
        "per_class": {c: {"precision": round(report[c]["precision"], 4),
                          "recall": round(report[c]["recall"], 4),
                          "f1": round(report[c]["f1-score"], 4),
                          "support": int(report[c]["support"])} for c in labels},
        "confusion": {"labels": labels,
                      "matrix": confusion_matrix(y_raw, pred_raw, labels=labels).tolist()},
    }


def compare(baseline_path, result):
    """Markdown tables: the served models on the original data, against the
    same method on the corrected data."""
    try:
        base = json.loads(Path(baseline_path).read_text())
    except (OSError, ValueError):
        print(f"\n(no baseline at {baseline_path}; comparison skipped)")
        return
    b, c = base.get("binary", {}), result["binary"]
    print("\n| Binary | original (served) | corrected | change |\n|---|---|---|---|")
    for m in ("auc", "f1", "precision", "recall"):
        if isinstance(b.get(m), (int, float)) and isinstance(c.get(m), (int, float)):
            digits = 6 if m == "auc" else 4
            print(f"| {m} | {b[m]:.{digits}f} | {c[m]:.{digits}f} | {c[m] - b[m]:+.{digits}f} |")
    bm, cm = base.get("multiclass", {}), result.get("multiclass")
    if not cm:
        return
    print("\n| Multiclass | original (served) | corrected | change |\n|---|---|---|---|")
    for m in ("macro_f1", "weighted_f1", "accuracy"):
        if m in bm:
            print(f"| {m} | {bm[m]:.4f} | {cm[m]:.4f} | {cm[m] - bm[m]:+.4f} |")
    print("\n| Class | F1 original (n) | F1 corrected (n) | change |\n|---|---|---|---|")
    for cls in FAMILIES:
        o, n = bm.get("per_class", {}).get(cls), cm["per_class"].get(cls)
        if o and n:
            print(f"| {cls} | {o['f1']:.3f} ({o['support']:,}) | {n['f1']:.3f} ({n['support']:,}) "
                  f"| {n['f1'] - o['f1']:+.3f} |")
        elif n:
            print(f"| {cls} | - | {n['f1']:.3f} ({n['support']:,}) | |")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data", required=True, help="folder with the corrected CICIDS2017 CSVs")
    parser.add_argument("--inspect", action="store_true", help="describe the files and stop")
    parser.add_argument("--attempted", choices=["benign", "drop"], default="benign",
                        help="attempted attacks carried no attack traffic: count them as "
                             "benign (default) or leave them out")
    parser.add_argument("--infiltration-portscan", choices=["portscan", "infiltration"],
                        default="portscan", help="family for the infiltrated host's port scan")
    parser.add_argument("--holdout-day", help="test on the files whose name contains this "
                        "(e.g. friday); train on the rest. Binary only")
    parser.add_argument("--sample", type=float, default=1.0, help="fraction of rows, for a quick run")
    parser.add_argument("--n-estimators", type=int, default=PARAMS["n_estimators"])
    parser.add_argument("--baseline", default=str(Path(__file__).resolve().parent / "models" / "test_metrics.json"),
                        help="the served models' test metrics (ml/models/test_metrics.json)")
    parser.add_argument("--out", default="corrected_metrics.json")
    args = parser.parse_args()
    PARAMS["n_estimators"] = args.n_estimators

    paths = find_csvs(args.data)
    if args.inspect:
        inspect(paths, args)
        return

    started = time.time()
    data = load(paths, args)
    result = {"dataset": "CICIDS2017, corrected (Engelen, Rimmer and Joosen, 2021)",
              "attempted": args.attempted, "infiltration_portscan": args.infiltration_portscan,
              "sample": args.sample, "params": PARAMS, "rows": int(len(data)),
              "features": int(data.shape[1] - 3)}

    if args.holdout_day:
        day = args.holdout_day.lower()
        held = data["_file"].str.contains(day)
        if not held.any() or held.all():
            sys.exit(f"--holdout-day {day!r} matches {'no' if not held.any() else 'every'} file")
        rest, test = data[~held], data[held]
        train, val = split(rest, 0.15)
        X_tr, f_tr = xy(train)
        X_val, f_val = xy(val)
        X_te, f_te = xy(test)
        y_tr, y_val, y_te = ((f != "BENIGN").astype(int) for f in (f_tr, f_val, f_te))
        print(f"training on {len(train):,} rows, testing on {len(test):,} rows held out by day...")
        model, spw = train_binary(X_tr, y_tr, X_val, y_val)
        proba = model.predict_proba(X_te)[:, 1]
        result["split"] = f"held-out day: {day}"
        result["binary"] = binary_metrics(y_te, proba)
        result["binary"]["scale_pos_weight"] = round(spw, 3)
        detected = {}
        for fam_name in sorted(set(f_te)):
            mask = f_te == fam_name
            rate = float((proba[mask] >= 0.5).mean())
            detected[fam_name] = {"n": int(mask.sum()),
                                  "flagged_as_attack": round(rate, 4),
                                  "seen_in_training": bool((f_tr == fam_name).any())}
        result["by_family_on_held_out_day"] = detected
        print(json.dumps(result["binary"], indent=2))
        print("\n| Family on the held-out day | n | flagged as attack | seen in training |\n|---|---|---|---|")
        for fam_name, d in detected.items():
            print(f"| {fam_name} | {d['n']:,} | {d['flagged_as_attack']:.4f} | {d['seen_in_training']} |")
    else:
        train, temp = split(data, 0.30)
        val, test = split(temp, 0.50)
        X_tr, f_tr = xy(train)
        X_val, f_val = xy(val)
        X_te, f_te = xy(test)
        y_tr, y_val, y_te = ((f != "BENIGN").astype(int) for f in (f_tr, f_val, f_te))
        print(f"split: train {len(train):,}, val {len(val):,}, test {len(test):,}")
        print("training binary model...")
        model, spw = train_binary(X_tr, y_tr, X_val, y_val)
        result["split"] = "stratified 70/15/15, seed 42 (as served)"
        result["binary"] = binary_metrics(y_te, model.predict_proba(X_te)[:, 1])
        result["binary"]["scale_pos_weight"] = round(spw, 3)
        print(json.dumps(result["binary"], indent=2))
        print("training multiclass model...")
        mmodel, le = train_multiclass(X_tr, f_tr, X_val, f_val)
        pred = le.inverse_transform(mmodel.predict(X_te))
        result["multiclass"] = multiclass_metrics(f_te, pred)
        print(f"macro F1 {result['multiclass']['macro_f1']}, accuracy {result['multiclass']['accuracy']}")
        compare(args.baseline, result)

    result["minutes"] = round((time.time() - started) / 60, 1)
    Path(args.out).write_text(json.dumps(result, indent=2))
    print(f"\nwrote {args.out} ({result['minutes']} min)")


if __name__ == "__main__":
    main()
