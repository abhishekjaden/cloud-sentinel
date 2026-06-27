"""
CICIDS2017 preprocessing for CloudSentinel intrusion detection.

Runs as a SageMaker Processing job. Reads the 8 raw CICIDS2017 CSVs,
cleans known data-quality issues, derives binary + multiclass labels,
and writes stratified train/val/test splits.

Known CICIDS2017 issues handled:
  - leading whitespace in column names
  - Inf values in Flow Bytes/s and Flow Packets/s (division by zero)
  - NaN rows (small fraction, dropped)
  - inconsistent / non-UTF8 attack label strings
  - severe class imbalance (handled at TRAIN time, not here)
"""
import argparse
import glob
import os
import numpy as np
import pandas as pd

# Raw label string -> clean attack family
LABEL_MAP = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "Heartbleed": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Bot": "Bot",
    "Infiltration": "Infiltration",
}


def _normalize_label(raw):
    """Map a raw label string to a clean family, tolerating encoding junk."""
    if not isinstance(raw, str):
        return "BENIGN"
    s = raw.strip()
    # Fix the non-UTF8 'Web Attack <byte> X' artifacts -> 'Web Attack - X'
    if s.startswith("Web Attack"):
        if "Brute" in s:
            return "WebAttack"
        if "XSS" in s:
            return "WebAttack"
        if "Sql" in s or "SQL" in s:
            return "WebAttack"
        return "WebAttack"
    return LABEL_MAP.get(s, s)


def clean(df):
    """Clean one raw CICIDS2017 dataframe in place-ish, return cleaned copy."""
    # 1. Strip leading/trailing whitespace from column names
    df.columns = [c.strip() for c in df.columns]

    # 2. The label column is named 'Label'
    if "Label" not in df.columns:
        raise ValueError(f"no Label column; got {list(df.columns)[:3]}...")

    # 3. Replace Inf -> NaN across numeric columns
    df = df.replace([np.inf, -np.inf], np.nan)

    # 4. Drop rows with any NaN (small fraction in flow-rate columns)
    before = len(df)
    df = df.dropna()
    dropped = before - len(df)

    # 5. Normalize labels -> family, then derive binary
    df["label_multiclass"] = df["Label"].map(_normalize_label)
    df["label_binary"] = (df["label_multiclass"] != "BENIGN").astype(int)
    df = df.drop(columns=["Label"])

    return df, dropped


def main(input_dir, output_dir):
    from sklearn.model_selection import train_test_split

    csv_paths = sorted(glob.glob(os.path.join(input_dir, "*.csv")))
    if not csv_paths:
        raise FileNotFoundError(f"no CSVs found in {input_dir}")
    print(f"found {len(csv_paths)} CSV files")

    frames, total_dropped = [], 0
    for p in csv_paths:
        # latin-1 tolerates the non-UTF8 bytes in the WebAttacks file
        df = pd.read_csv(p, encoding="latin-1", low_memory=False)
        cleaned, dropped = clean(df)
        total_dropped += dropped
        frames.append(cleaned)
        print(f"  {os.path.basename(p)}: {len(cleaned)} rows (dropped {dropped})")

    data = pd.concat(frames, ignore_index=True)
    print(f"combined: {len(data)} rows, dropped {total_dropped} NaN/Inf rows total")

    # Stratify on multiclass so rare attack families stay represented in all splits
    strat = data["label_multiclass"]
    train, temp = train_test_split(
        data, test_size=0.30, random_state=42, stratify=strat
    )
    val, test = train_test_split(
        temp, test_size=0.50, random_state=42, stratify=temp["label_multiclass"]
    )
    print(f"split: train={len(train)} val={len(val)} test={len(test)}")

    os.makedirs(output_dir, exist_ok=True)
    for name, part in [("train", train), ("val", val), ("test", test)]:
        out = os.path.join(output_dir, f"{name}.csv")
        part.to_csv(out, index=False)
        print(f"  wrote {out}")

    # Label distribution report (for the writeup / sanity)
    print("\nmulticlass distribution (full):")
    print(data["label_multiclass"].value_counts())
    print("\nbinary distribution (full):")
    print(data["label_binary"].value_counts())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", default="/opt/ml/processing/input")
    parser.add_argument("--output-dir", default="/opt/ml/processing/output")
    args = parser.parse_args()
    main(args.input_dir, args.output_dir)
