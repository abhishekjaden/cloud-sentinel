"""
Full-data binary training via CHUNKED load (memory-safe for t3.medium).

Reads train.csv in row-chunks, converts each to float32, and assembles a
single xgb.DMatrix incrementally — never holding the full DataFrame plus a
model copy at once. Trains binary (alerting path) on ALL 1.98M rows.
Multiclass deferred to the managed job. Same train_binary hyperparameters.
"""
import os, sys, gc, json
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import roc_auc_score, f1_score, precision_score, recall_score

sys.path.insert(0, os.path.dirname(__file__))
from train import LABEL_COLS

DATA = os.path.expanduser("~/cloud-sentinel/data")
OUT = os.path.expanduser("~/cloud-sentinel/models")
os.makedirs(OUT, exist_ok=True)
CHUNK = 200_000
DROP = ("flow id","source ip","destination ip","timestamp","src ip","dst ip")


def load_chunked(path):
    """Load X (float32) + y_binary by concatenating float32 chunks."""
    X_parts, y_parts, cols = [], [], None
    for chunk in pd.read_csv(path, chunksize=CHUNK, low_memory=False):
        drop = [c for c in chunk.columns if c.lower() in DROP]
        if drop:
            chunk = chunk.drop(columns=drop)
        y_parts.append(chunk["label_binary"].astype(np.int8).values)
        Xc = chunk.drop(columns=LABEL_COLS).select_dtypes(include=[np.number])
        Xc = Xc.replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)
        if cols is None:
            cols = list(Xc.columns)
        X_parts.append(Xc.values)
        del chunk, Xc; gc.collect()
    X = np.concatenate(X_parts, axis=0); del X_parts; gc.collect()
    y = np.concatenate(y_parts, axis=0); del y_parts; gc.collect()
    return X, y, cols


if __name__ == "__main__":
    print("loading train (chunked float32)...")
    X_tr, y_tr, cols = load_chunked(os.path.join(DATA, "train.csv"))
    print(f"  train X {X_tr.shape}  pos={int(y_tr.sum())} neg={int((y_tr==0).sum())}")
    print("loading val (chunked float32)...")
    X_val, y_val, _ = load_chunked(os.path.join(DATA, "val.csv"))
    print(f"  val X {X_val.shape}")

    spw = (y_tr == 0).sum() / max((y_tr == 1).sum(), 1)
    dtrain = xgb.DMatrix(X_tr, label=y_tr, feature_names=cols)
    del X_tr, y_tr; gc.collect()
    dval = xgb.DMatrix(X_val, label=y_val, feature_names=cols)

    params = {
        "objective": "binary:logistic", "eval_metric": "auc",
        "max_depth": 8, "eta": 0.1, "subsample": 0.8,
        "colsample_bytree": 0.8, "tree_method": "hist",
        "scale_pos_weight": float(spw), "nthread": -1,
    }
    print(f"training binary (scale_pos_weight={spw:.3f})...")
    booster = xgb.train(params, dtrain, num_boost_round=300,
                        evals=[(dval, "val")], verbose_eval=50)

    proba = booster.predict(dval)
    pred = (proba >= 0.5).astype(int)
    metrics = {
        "scale_pos_weight": round(float(spw), 3),
        "auc": round(float(roc_auc_score(y_val, proba)), 4),
        "f1": round(float(f1_score(y_val, pred)), 4),
        "precision": round(float(precision_score(y_val, pred)), 4),
        "recall": round(float(recall_score(y_val, pred)), 4),
        "n_train": int(dtrain.num_row()),
        "note": "full-data binary, chunked in-notebook interim; managed job = production",
    }
    print("binary metrics:", json.dumps(metrics))
    booster.save_model(os.path.join(OUT, "binary_model.json"))
    with open(os.path.join(OUT, "binary_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    print("saved to", OUT)
