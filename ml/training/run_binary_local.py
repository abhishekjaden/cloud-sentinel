"""
Interim: train ONLY the binary model on full data, memory-frugally (t3.medium).

Loads with float32 to halve the DataFrame footprint, trains binary (the
alerting-path model) on the full 1.98M rows, saves artifacts. The multiclass
model is deferred to the managed training job (run_training.py) which has the
memory for it. Reuses train_binary() from train.py — identical logic.
"""
import os, sys, json, gc
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
from train import train_binary, LABEL_COLS

DATA = os.path.expanduser("~/cloud-sentinel/data")
OUT = os.path.expanduser("~/cloud-sentinel/models")
os.makedirs(OUT, exist_ok=True)


def load_x_ybin(path):
    df = pd.read_csv(path, low_memory=False)
    drop = [c for c in df.columns if c.lower() in
            ("flow id","source ip","destination ip","timestamp","src ip","dst ip")]
    if drop:
        df = df.drop(columns=drop)
    y = df["label_binary"].astype(np.int8).values
    X = df.drop(columns=LABEL_COLS).select_dtypes(include=[np.number])
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)
    del df; gc.collect()
    return X, y


if __name__ == "__main__":
    params = {"n_estimators": 300, "max_depth": 8, "learning_rate": 0.1,
              "subsample": 0.8, "colsample_bytree": 0.8}
    print("loading train (float32)...")
    X_tr, y_tr = load_x_ybin(os.path.join(DATA, "train.csv"))
    print(f"  train {X_tr.shape}")
    print("loading val (float32)...")
    X_val, y_val = load_x_ybin(os.path.join(DATA, "val.csv"))
    print(f"  val {X_val.shape}")
    print("training binary model...")
    model, metrics = train_binary(X_tr, y_tr, X_val, y_val, params)
    print("  binary metrics:", json.dumps(metrics))
    del X_tr, y_tr; gc.collect()
    model.save_model(os.path.join(OUT, "binary_model.json"))
    with open(os.path.join(OUT, "binary_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    print("saved binary model + metrics to", OUT)
