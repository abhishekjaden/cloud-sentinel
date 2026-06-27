"""
In-notebook CICIDS2017 preprocessing (memory-safe for ml.t3.medium).

Interim runner: produces the SAME train/val/test splits as the managed
SageMaker Processing job (run_processing.py), but processes file-by-file
to fit in ~1.6GB RAM. Reuses the exact clean() logic from preprocessing.py.

The managed Processing job remains the production path; this unblocks
training while new-account quota for processing instances is pending.
"""
import os
import sys
import boto3
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(__file__))
from preprocessing import clean  # identical cleaning logic

BUCKET = "cloudsentinel-ml-743181156000"
RAW_PREFIX = "raw/cicids2017/"
FEATURES_PREFIX = "features/"
WORK = "/tmp/cicids-work"
os.makedirs(WORK, exist_ok=True)

s3 = boto3.client("s3")


def list_raw_keys():
    resp = s3.list_objects_v2(Bucket=BUCKET, Prefix=RAW_PREFIX)
    return [o["Key"] for o in resp.get("Contents", []) if o["Key"].endswith(".csv")]


def process():
    keys = list_raw_keys()
    if not keys:
        raise FileNotFoundError(f"no CSVs under s3://{BUCKET}/{RAW_PREFIX}")
    print(f"found {len(keys)} raw CSVs")

    train_path = os.path.join(WORK, "train.csv")
    val_path = os.path.join(WORK, "val.csv")
    test_path = os.path.join(WORK, "test.csv")
    for p in (train_path, val_path, test_path):
        if os.path.exists(p):
            os.remove(p)

    header_written = {"train": False, "val": False, "test": False}
    totals = {"train": 0, "val": 0, "test": 0}
    label_counts = {}

    for key in keys:
        fname = os.path.basename(key)
        local = os.path.join(WORK, fname)
        s3.download_file(BUCKET, key, local)
        df = pd.read_csv(local, encoding="latin-1", low_memory=False)
        cleaned, dropped = clean(df)
        os.remove(local)

        for lbl, n in cleaned["label_multiclass"].value_counts().items():
            label_counts[lbl] = label_counts.get(lbl, 0) + int(n)

        strat = cleaned["label_multiclass"]
        vc = strat.value_counts()
        can_strat = (vc >= 2).all() and len(vc) > 1
        tr, tmp = train_test_split(
            cleaned, test_size=0.30, random_state=42,
            stratify=strat if can_strat else None,
        )
        s2 = tmp["label_multiclass"]
        vc2 = s2.value_counts()
        can_strat2 = (vc2 >= 2).all() and len(vc2) > 1
        va, te = train_test_split(
            tmp, test_size=0.50, random_state=42,
            stratify=s2 if can_strat2 else None,
        )

        for name, part, path in [
            ("train", tr, train_path), ("val", va, val_path), ("test", te, test_path)
        ]:
            part.to_csv(path, mode="a", header=not header_written[name], index=False)
            header_written[name] = True
            totals[name] += len(part)

        print(f"  {fname}: {len(cleaned)} rows (dropped {dropped}) -> "
              f"train+{len(tr)} val+{len(va)} test+{len(te)}")
        del df, cleaned, tr, tmp, va, te

    print(f"\nsplit totals: {totals}")
    print(f"label distribution (multiclass): {label_counts}")
    return train_path, val_path, test_path


def upload(train_path, val_path, test_path):
    for path in (train_path, val_path, test_path):
        name = os.path.basename(path)
        key = f"{FEATURES_PREFIX}{name}"
        s3.upload_file(path, BUCKET, key)
        size_mb = os.path.getsize(path) / 1e6
        print(f"  uploaded s3://{BUCKET}/{key} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    tr, va, te = process()
    print("\nuploading splits to S3...")
    upload(tr, va, te)
    print("\nDONE — splits in s3://%s/%s" % (BUCKET, FEATURES_PREFIX))
