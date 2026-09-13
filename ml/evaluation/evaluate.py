"""
Evaluation on the held-out CICIDS2017 test split.

The validation set steered training decisions, so its numbers are optimistic by
construction. This script scores the test split, which no training or tuning
decision has seen, and is the only source of the figures reported in the
project write-up.

Every result is printed with its support count. On this dataset that is not a
formality: two classes have fewer than 400 test samples and one has single
digits, where an F1 score carries almost no information on its own.
"""
import argparse
import json
import os

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    f1_score, precision_score, recall_score,
)

LABEL_COLS = ["label_binary", "label_multiclass"]


def load_test(path):
    df = pd.read_csv(path)
    drop = [c for c in df.columns
            if c.lower() in ("flow id", "source ip", "destination ip",
                             "timestamp", "src ip", "dst ip")]
    if drop:
        df = df.drop(columns=drop)
    y_bin = df["label_binary"].astype(int).values
    y_mul = df["label_multiclass"].astype(str).values
    X = df.drop(columns=LABEL_COLS).select_dtypes(include=[np.number])
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    return X, y_bin, y_mul


def evaluate_binary(model_path, X, y):
    model = xgb.XGBClassifier()
    model.load_model(model_path)
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= 0.5).astype(int)
    return {
        "auc": float(roc_auc_score(y, proba)),
        "f1": round(float(f1_score(y, pred)), 4),
        "precision": round(float(precision_score(y, pred)), 4),
        "recall": round(float(recall_score(y, pred)), 4),
        "n_test": int(len(y)),
        "n_attack": int(y.sum()),
        "n_benign": int((y == 0).sum()),
    }


def evaluate_multiclass(model_path, classes_path, X, y_raw):
    model = xgb.XGBClassifier()
    model.load_model(model_path)
    classes = json.load(open(classes_path))
    idx = {c: i for i, c in enumerate(classes)}

    unseen = sorted(set(y_raw) - set(classes))
    mask = np.array([c in idx for c in y_raw])
    y = np.array([idx[c] for c in y_raw[mask]])
    pred = model.predict(X[mask])

    report = classification_report(
        y, pred, labels=list(range(len(classes))), target_names=classes,
        output_dict=True, zero_division=0,
    )
    cm = confusion_matrix(y, pred, labels=list(range(len(classes))))

    return {
        "macro_f1": round(report["macro avg"]["f1-score"], 4),
        "weighted_f1": round(report["weighted avg"]["f1-score"], 4),
        "accuracy": round(report["accuracy"], 4),
        "classes": classes,
        "unseen_labels_in_test": unseen,
        "per_class": {
            c: {
                "precision": round(report[c]["precision"], 4),
                "recall": round(report[c]["recall"], 4),
                "f1": round(report[c]["f1-score"], 4),
                "support": int(report[c]["support"]),
            }
            for c in classes
        },
        "confusion_matrix": cm.tolist(),
    }


def print_report(binary, multi):
    print("\n" + "=" * 64)
    print("BINARY  (BENIGN vs ATTACK)")
    print("=" * 64)
    print(f"  samples      {binary['n_test']:,}  "
          f"({binary['n_benign']:,} benign / {binary['n_attack']:,} attack)")
    print(f"  AUC          {binary['auc']:.6f}")
    print(f"  F1           {binary['f1']:.4f}")
    print(f"  precision    {binary['precision']:.4f}")
    print(f"  recall       {binary['recall']:.4f}")

    print("\n" + "=" * 64)
    print("MULTICLASS  (attack family)")
    print("=" * 64)
    print(f"  macro F1     {multi['macro_f1']:.4f}   "
          "<- the honest headline: every class weighted equally")
    print(f"  weighted F1  {multi['weighted_f1']:.4f}   "
          "<- dominated by BENIGN, which is 80% of the data")
    print(f"  accuracy     {multi['accuracy']:.4f}   "
          "<- near-meaningless at this imbalance")

    print(f"\n  {'class':<14}{'precision':>10}{'recall':>9}{'f1':>8}{'support':>10}")
    print("  " + "-" * 51)
    for c, m in sorted(multi["per_class"].items(), key=lambda kv: -kv[1]["support"]):
        flag = "  <- too few to be meaningful" if m["support"] < 50 else ""
        print(f"  {c:<14}{m['precision']:>10.3f}{m['recall']:>9.3f}"
              f"{m['f1']:>8.3f}{m['support']:>10,}{flag}")

    print("\n  Confusion matrix (rows = actual, columns = predicted)")
    classes = multi["classes"]
    print("  " + " " * 14 + "".join(f"{c[:8]:>9}" for c in classes))
    for i, row in enumerate(multi["confusion_matrix"]):
        print(f"  {classes[i]:<14}" + "".join(f"{v:>9,}" for v in row))

    if multi["unseen_labels_in_test"]:
        print(f"\n  Labels in test but not in the model: "
              f"{multi['unseen_labels_in_test']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", default="ml/data/test.csv")
    ap.add_argument("--models", default="ml/models")
    ap.add_argument("--out", default="ml/models/test_metrics.json")
    args = ap.parse_args()

    print(f"loading {args.test} ...")
    X, y_bin, y_mul = load_test(args.test)
    print(f"  {X.shape[0]:,} rows, {X.shape[1]} features")

    binary = evaluate_binary(os.path.join(args.models, "binary_model.json"), X, y_bin)
    multi = evaluate_multiclass(
        os.path.join(args.models, "multiclass_model.json"),
        os.path.join(args.models, "label_classes.json"),
        X, y_mul,
    )
    print_report(binary, multi)

    out = {
        "split": "held-out test",
        "dataset": "CICIDS2017",
        "binary": binary,
        "multiclass": multi,
        "caveat": (
            "Near-perfect separation on most classes is a documented property of "
            "CICIDS2017 rather than evidence of real-world detection accuracy. "
            "Engelen, Rimmer and Joosen (IEEE S&P Workshops, 2021) identify "
            "labelling errors and feature-generation artefacts in this dataset. "
            "Classes with fewer than 50 test samples are reported for "
            "completeness; their scores are not statistically meaningful."
        ),
    }
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nwritten to {args.out}")


if __name__ == "__main__":
    main()
