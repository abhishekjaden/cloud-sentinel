"""
XGBoost training for CloudSentinel intrusion detection.

Trains TWO models from the CICIDS2017 feature splits:
  - binary:     BENIGN vs ATTACK   (scale_pos_weight for imbalance)
  - multiclass: 8 attack families  (sample weights for rare classes)

Written to SageMaker training-container conventions so the SAME script
runs as a managed training job (production path) or in-notebook (interim):
  - data channels under /opt/ml/input/data/<channel>/
  - model + metrics written to /opt/ml/model/
  - hyperparameters via CLI args (so HPO can sweep them)
"""
import argparse
import json
import os

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    roc_auc_score, f1_score, precision_score, recall_score,
    classification_report, confusion_matrix,
)
from sklearn.preprocessing import LabelEncoder

LABEL_COLS = ["label_binary", "label_multiclass"]


def _load(channel_dir, name):
    path = os.path.join(channel_dir, name)
    df = pd.read_csv(path)
    # Drop any non-numeric leakage columns if present (flow id, ip, timestamp)
    drop = [c for c in df.columns
            if c.lower() in ("flow id", "source ip", "destination ip",
                             "timestamp", "src ip", "dst ip")]
    if drop:
        df = df.drop(columns=drop)
    return df


def _split_xy(df):
    y_bin = df["label_binary"].astype(int).values
    y_multi_raw = df["label_multiclass"].astype(str).values
    X = df.drop(columns=LABEL_COLS)
    # keep only numeric feature columns
    X = X.select_dtypes(include=[np.number])
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    return X, y_bin, y_multi_raw


def train_binary(X_tr, y_tr, X_val, y_val, params):
    """Binary BENIGN(0) vs ATTACK(1) with imbalance handling."""
    n_neg = int((y_tr == 0).sum())
    n_pos = int((y_tr == 1).sum())
    spw = n_neg / max(n_pos, 1)  # scale_pos_weight

    model = xgb.XGBClassifier(
        n_estimators=params["n_estimators"],
        max_depth=params["max_depth"],
        learning_rate=params["learning_rate"],
        subsample=params["subsample"],
        colsample_bytree=params["colsample_bytree"],
        scale_pos_weight=spw,
        objective="binary:logistic",
        eval_metric="auc",
        tree_method="hist",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_tr, y_tr, eval_set=[(X_val, y_val)], verbose=False)

    proba = model.predict_proba(X_val)[:, 1]
    pred = (proba >= 0.5).astype(int)
    metrics = {
        "scale_pos_weight": round(spw, 3),
        "auc": round(roc_auc_score(y_val, proba), 4),
        "f1": round(f1_score(y_val, pred), 4),
        "precision": round(precision_score(y_val, pred), 4),
        "recall": round(recall_score(y_val, pred), 4),
    }
    return model, metrics


def train_multiclass(X_tr, y_tr_raw, X_val, y_val_raw, params):
    """8-class attack-family classifier with per-class sample weights."""
    le = LabelEncoder()
    y_tr = le.fit_transform(y_tr_raw)
    y_val = le.transform(y_val_raw)

    # inverse-frequency sample weights (critical for rare classes e.g. Infiltration)
    classes, counts = np.unique(y_tr, return_counts=True)
    freq = dict(zip(classes, counts))
    total = len(y_tr)
    weights = np.array([total / (len(classes) * freq[c]) for c in y_tr])

    model = xgb.XGBClassifier(
        n_estimators=params["n_estimators"],
        max_depth=params["max_depth"],
        learning_rate=params["learning_rate"],
        subsample=params["subsample"],
        colsample_bytree=params["colsample_bytree"],
        objective="multi:softprob",
        num_class=len(classes),
        eval_metric="mlogloss",
        tree_method="hist",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_tr, y_tr, sample_weight=weights,
              eval_set=[(X_val, y_val)], verbose=False)

    pred = model.predict(X_val)
    report = classification_report(
        y_val, pred, target_names=le.classes_, output_dict=True, zero_division=0
    )
    metrics = {
        "macro_f1": round(report["macro avg"]["f1-score"], 4),
        "weighted_f1": round(report["weighted avg"]["f1-score"], 4),
        "accuracy": round(report["accuracy"], 4),
        "per_class": {
            cls: {
                "precision": round(report[cls]["precision"], 4),
                "recall": round(report[cls]["recall"], 4),
                "f1": round(report[cls]["f1-score"], 4),
                "support": int(report[cls]["support"]),
            }
            for cls in le.classes_
        },
    }
    return model, metrics, le


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", default=os.environ.get("SM_CHANNEL_TRAIN", "/opt/ml/input/data/train"))
    parser.add_argument("--model-dir", default=os.environ.get("SM_MODEL_DIR", "/opt/ml/model"))
    parser.add_argument("--n-estimators", type=int, default=300)
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=0.1)
    parser.add_argument("--subsample", type=float, default=0.8)
    parser.add_argument("--colsample-bytree", type=float, default=0.8)
    args = parser.parse_args()
    params = {
        "n_estimators": args.n_estimators,
        "max_depth": args.max_depth,
        "learning_rate": args.learning_rate,
        "subsample": args.subsample,
        "colsample_bytree": args.colsample_bytree,
    }
    print("loading train/val...")
    train_df = _load(args.train, "train.csv")
    val_df = _load(args.train, "val.csv")
    X_tr, ybin_tr, ymul_tr = _split_xy(train_df)
    X_val, ybin_val, ymul_val = _split_xy(val_df)
    print(f"  train {X_tr.shape}  val {X_val.shape}  features={X_tr.shape[1]}")
    print("training binary model...")
    bin_model, bin_metrics = train_binary(X_tr, ybin_tr, X_val, ybin_val, params)
    print("  binary:", json.dumps(bin_metrics))
    print("training multiclass model...")
    mul_model, mul_metrics, le = train_multiclass(X_tr, ymul_tr, X_val, ymul_val, params)
    print("  multiclass macro_f1:", mul_metrics["macro_f1"], "accuracy:", mul_metrics["accuracy"])
    for cls, m in mul_metrics["per_class"].items():
        print(f"    {cls:14s} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} n={m['support']}")
    os.makedirs(args.model_dir, exist_ok=True)
    bin_model.save_model(os.path.join(args.model_dir, "binary_model.json"))
    mul_model.save_model(os.path.join(args.model_dir, "multiclass_model.json"))
    with open(os.path.join(args.model_dir, "label_classes.json"), "w") as f:
        json.dump(list(le.classes_), f)
    with open(os.path.join(args.model_dir, "metrics.json"), "w") as f:
        json.dump({"binary": bin_metrics, "multiclass": mul_metrics}, f, indent=2)
    print("saved models + metrics to", args.model_dir)


if __name__ == "__main__":
    main()
