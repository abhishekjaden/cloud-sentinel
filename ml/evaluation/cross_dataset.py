"""
Cross-dataset test: train CloudSentinel's binary detector on all five days of
the corrected CICIDS2017 and score the corrected CSE-CIC-IDS-2018, which Liu,
Engelen et al. extracted with the same fixed flow tool, so the columns match.

Quick trial, reading only the first 100,000 rows of each 2018 file. It also
saves the trained model, so the full run loads it instead of training again,
and it prints how long the full run will take:

    python ml/evaluation/cross_dataset.py --train ~/Downloads/cicids2017-corrected \
        --test ~/Downloads/CSECICIDS2018_improved.zip \
        --model ml/models/cross_model.ubj --limit-rows 100000 \
        --out ml/models/cross_trial.json

Full run: the same command without --limit-rows, with
--out ml/models/cross_dataset_2018.json.

The 2018 data is streamed from the zip in chunks; it is never unzipped to disk
or held in memory whole. For every raw label the result keeps a count, how
many flows were flagged as attack and a histogram of the scores, so the tables
can be printed again, with another label mapping if need be, without reading
the data:

    python ml/evaluation/cross_dataset.py --report ml/models/cross_dataset_2018.json

The result is saved after every file, so an interrupted run still reports
what it scored. Training settings, family labels, the treatment of attempted
attacks and the dropping of rows with missing or infinite values are those of
retrain_corrected.py and the served models.
"""
import argparse
import csv
import io
import json
import os
import re
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

SEED = 42
PARAMS = dict(n_estimators=300, max_depth=8, learning_rate=0.1,
              subsample=0.8, colsample_bytree=0.8)
LO, HI, BINS = -30.0, 30.0, 6000      # histogram of log-odds scores, 0.01 wide
IDENTIFIERS = {"id", "flowid", "srcip", "sourceip", "dstip", "destinationip",
               "srcport", "sourceport", "timestamp", "attemptedcategory", "label"}


def key(name):
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def attempted(raw):
    return "attempted" in str(raw).lower()


def family(raw, infiltration_portscan="portscan"):
    """Both releases' label spellings, as the served models' eight families."""
    s = re.sub(r"\s+", " ", str(raw)).strip().lower()
    if s == "benign":
        return "BENIGN"
    if s.startswith("ddos"):
        return "DDoS"
    if s.startswith(("dos", "heartbleed")):
        return "DoS"
    if s.startswith(("infiltration", "infilteration")):
        if "portscan" in s.replace(" ", ""):
            return "PortScan" if infiltration_portscan == "portscan" else "Infiltration"
        return "Infiltration"
    if s.replace(" ", "") == "portscan":
        return "PortScan"
    if s.startswith("web attack") or "sql" in s or "xss" in s or ("brute force" in s and "web" in s):
        return "WebAttack"
    if s.startswith(("ftp", "ssh")):
        return "BruteForce"
    if s.startswith("bot"):
        return "Bot"
    return None


def describe(raw, infiltration_portscan="portscan"):
    if attempted(raw):
        return "BENIGN (attempted)"
    return family(raw, infiltration_portscan) or "no family"


# ------------------------------------------------------------------ training
def load_training(folder):
    frames = []
    for p in sorted(x for x in Path(folder).rglob("*") if x.suffix.lower() == ".csv"):
        df = pd.read_csv(p, encoding="latin-1", low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        lab = next((c for c in df.columns if key(c) == "label"), None)
        if lab is None:
            print(f"  {p.name}: no label column, skipped")
            continue
        raw = df[lab].astype(str).str.strip()
        fam = raw.map(family)
        fam = fam.where(~raw.str.lower().str.contains("attempted", regex=False), "BENIGN")
        if fam.isna().any():
            sys.exit(f"{p.name}: labels with no family: {sorted(set(raw[fam.isna()]))}")
        X = df[[c for c in df.columns if key(c) not in IDENTIFIERS]].apply(pd.to_numeric, errors="coerce")
        X = X.loc[:, X.isna().mean() <= 0.5].astype("float32")
        X.columns = [key(c) for c in X.columns]
        if X.columns.duplicated().any():
            sys.exit(f"{p.name}: two columns have the same name once spaces and case are ignored")
        frames.append(X.assign(_y=(fam != "BENIGN").astype(int).to_numpy()))
        print(f"  {p.name}: {len(X):,} rows")
    if not frames:
        sys.exit(f"no labelled CSV files under {folder}")
    data = pd.concat(frames, ignore_index=True, join="inner")
    before = len(data)
    data = data.replace([np.inf, -np.inf], np.nan).dropna()
    print(f"  dropped {before - len(data):,} rows with missing or infinite values")
    return data.drop(columns=["_y"]), data["_y"].to_numpy()


def get_model(train_dir, model_path):
    """Trains on the 2017 data, or loads the model an earlier run saved."""
    import xgboost as xgb
    if model_path and Path(model_path).exists():
        model = xgb.XGBClassifier()
        model.load_model(model_path)
        info = json.loads(model.get_booster().attr("cross_dataset") or "{}")
        features = list(model.get_booster().feature_names)
        print(f"loaded the model trained earlier from {model_path} ({len(features)} features)")
        return model, features, info
    if not train_dir:
        sys.exit("--train is needed: there is no saved model to load")
    started = time.time()
    print("training on CICIDS2017 (corrected), all five days...")
    X, y = load_training(train_dir)
    spw = float((y == 0).sum()) / max(int((y == 1).sum()), 1)
    model = xgb.XGBClassifier(**PARAMS, scale_pos_weight=spw, objective="binary:logistic",
                              eval_metric="auc", tree_method="hist", n_jobs=-1, random_state=SEED)
    model.fit(X, y, verbose=False)
    info = {"rows": len(X), "attack": int(y.sum()), "features": X.shape[1],
            "scale_pos_weight": round(spw, 3), "minutes": round((time.time() - started) / 60, 1)}
    print(f"  {info['rows']:,} rows, {info['features']} features, {info['attack']:,} attack; "
          f"trained in {info['minutes']} min")
    if model_path:
        model.get_booster().set_attr(cross_dataset=json.dumps(info))
        Path(model_path).parent.mkdir(parents=True, exist_ok=True)
        model.save_model(model_path)
        print(f"  saved the model to {model_path}; runs with the same --model load it")
    return model, list(X.columns), info


# ------------------------------------------------------------- test files
class _Counted(io.RawIOBase):
    """Counts the uncompressed bytes read, for progress and time estimates."""

    def __init__(self, raw):
        super().__init__()
        self.raw, self.count = raw, 0

    def readable(self):
        return True

    def readinto(self, buf):
        data = self.raw.read(len(buf))
        buf[:len(data)] = data
        self.count += len(data)
        return len(data)

    def close(self):
        if not self.closed:
            self.raw.close()
        super().close()


class _Unzip:
    """Streams a member through `unzip -p`, for compression Python lacks (Deflate64)."""

    def __init__(self, archive, member):
        self.proc = subprocess.Popen(["unzip", "-p", str(archive), member],
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def read(self, n=-1):
        return self.proc.stdout.read(n)

    def close(self):
        self.proc.stdout.close()
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()


def list_csvs(test):
    """(name, uncompressed bytes) of every CSV in the zip or folder."""
    def wanted(name):       # CSVs, but not the resource-fork copies macOS adds to archives
        return name.lower().endswith(".csv") and "__MACOSX" not in name and not Path(name).name.startswith("._")

    path = Path(test)
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as zf:
            return [(i.filename, i.file_size) for i in sorted(zf.infolist(), key=lambda i: i.filename)
                    if wanted(i.filename)]
    return [(p.relative_to(path).as_posix(), p.stat().st_size)
            for p in sorted(path.rglob("*")) if wanted(p.relative_to(path).as_posix())]


def open_csv(test, name):
    path = Path(test)
    if path.suffix.lower() != ".zip":
        return open(path / name, "rb")
    with zipfile.ZipFile(path) as zf:
        try:
            return zf.open(name)        # stays readable after the archive object closes
        except NotImplementedError:
            pass
    print(f"  {name}: Python cannot decompress this file, so it is read through unzip")
    return _Unzip(path, name)


# ------------------------------------------------------------------ scoring
def score_file(model, features, test, name, size, chunk_rows, limit_rows):
    """Per-raw-label counts and score histograms for one CSV."""
    stats, rows, skipped_headers = {}, 0, 0
    started = last = time.time()
    counted = _Counted(open_csv(test, name))
    with io.BufferedReader(counted, 1 << 20) as fh:
        header = [c.strip() for c in next(csv.reader([fh.readline().decode("latin-1")]))]
        positions = {key(c): i for i, c in enumerate(header)}
        lab = positions.get("label")
        if lab is None:
            print(f"  {name}: no label column, skipped")
            return None
        idx = [positions.get(f) for f in features]
        missing = [f for f, i in zip(features, idx) if i is None]
        present = [j for j, i in enumerate(idx) if i is not None]
        used = sorted({lab, *(i for i in idx if i is not None)})
        with pd.read_csv(fh, header=None, usecols=used, chunksize=chunk_rows, nrows=limit_rows,
                         encoding="latin-1", low_memory=False, on_bad_lines="warn") as reader:
            for chunk in reader:
                labels = chunk[lab].astype(str).str.strip().to_numpy(dtype=object)
                X = np.full((len(chunk), len(features)), np.nan, dtype=np.float32)
                for j in present:
                    X[:, j] = pd.to_numeric(chunk[idx[j]], errors="coerce").to_numpy(dtype=np.float64)
                repeat = labels == header[lab]          # header lines repeated inside the file
                if repeat.any():
                    skipped_headers += int(repeat.sum())
                    labels, X = labels[~repeat], X[~repeat]
                rows += len(labels)
                ok = np.isfinite(X[:, present]).all(axis=1)
                margin = (model.predict(pd.DataFrame(X[ok], columns=features), output_margin=True)
                          if ok.any() else np.empty(0))
                bins = np.clip(np.floor((margin - LO) / (HI - LO) * BINS), 0, BINS - 1).astype(np.int64)
                flagged = margin >= 0                   # probability >= 0.5
                scored_labels = labels[ok]
                for raw in pd.unique(labels):
                    m = scored_labels == raw
                    s = stats.setdefault(raw, {"n": 0, "flagged": 0, "dropped": 0,
                                               "hist": np.zeros(BINS, dtype=np.int64)})
                    n = int(m.sum())
                    s["dropped"] += int((labels == raw).sum()) - n
                    s["n"] += n
                    s["flagged"] += int(flagged[m].sum())
                    s["hist"] += np.bincount(bins[m], minlength=BINS)
                if time.time() - last >= 120:
                    last = time.time()
                    print(f"    {name}: {rows:,} rows so far, {counted.count / max(size, 1):.0%} of the file",
                          flush=True)
    return {"stats": stats, "rows": rows, "bytes_read": counted.count, "missing": missing,
            "repeated_headers": skipped_headers, "seconds": time.time() - started}


_WORKER = {}


def _score_job(job):
    """Runs in a worker process: loads the saved model once, then scores one file."""
    model_path, threads, features, test, name, size, chunk_rows, limit_rows = job
    if "model" not in _WORKER:
        import xgboost as xgb
        model = xgb.XGBClassifier()
        model.load_model(model_path)
        model.set_params(n_jobs=threads)
        _WORKER["model"] = model
    return name, size, score_file(_WORKER["model"], features, test, name, size, chunk_rows, limit_rows)


def scored_files(model, features, args, files):
    """(name, size, result) for each file, from one process or several."""
    if args.workers <= 1:
        for name, size in files:
            yield name, size, score_file(model, features, args.test, name, size, args.chunk_rows, args.limit_rows)
        return
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor, as_completed
    threads = max(1, (os.cpu_count() or 2) // args.workers)
    jobs = [(args.model, threads, features, args.test, name, size, args.chunk_rows, args.limit_rows)
            for name, size in sorted(files, key=lambda f: -f[1])]    # largest first
    with ProcessPoolExecutor(args.workers, mp_context=multiprocessing.get_context("spawn")) as pool:
        for future in as_completed([pool.submit(_score_job, job) for job in jobs]):
            yield future.result()


def makespan(sizes, workers, rate):
    """Minutes to score files of these sizes, largest first, each on the least busy worker."""
    loads = [0.0] * workers
    for size in sorted(sizes, reverse=True):
        loads[loads.index(min(loads))] += size / rate
    return max(loads) / 60


def merge(total, part):
    for raw, s in part.items():
        t = total.setdefault(raw, {"n": 0, "flagged": 0, "dropped": 0, "hist": np.zeros(BINS, dtype=np.int64)})
        for k in ("n", "flagged", "dropped"):
            t[k] += s[k]
        t["hist"] += s["hist"]


def as_json(stats):
    out = {}
    for raw, s in stats.items():
        nz = np.flatnonzero(s["hist"])
        out[raw] = {"n": s["n"], "flagged": s["flagged"], "dropped": s["dropped"],
                    "hist": {"bins": nz.tolist(), "counts": s["hist"][nz].tolist()}}
    return out


def histogram(s):
    h = np.zeros(BINS, dtype=np.int64)
    h[np.asarray(s["hist"]["bins"], dtype=np.int64)] = s["hist"]["counts"]
    return h


# ------------------------------------------------------------------- report
def report(result, infiltration_portscan="portscan", attempted_as="benign"):
    stats = result["labels"]
    fams, unmapped = {}, {}
    pos_hist = np.zeros(BINS, dtype=np.int64)
    neg_hist = np.zeros(BINS, dtype=np.int64)
    for raw, s in stats.items():
        if attempted(raw):
            if attempted_as == "drop":
                continue
            fam = "BENIGN"
        else:
            fam = family(raw, infiltration_portscan)
        if fam is None:
            unmapped[raw] = s["n"]
            continue
        f = fams.setdefault(fam, {"n": 0, "flagged": 0})
        f["n"] += s["n"]
        f["flagged"] += s["flagged"]
        if fam == "BENIGN":
            neg_hist += histogram(s)
        else:
            pos_hist += histogram(s)
    # AUC from the two score histograms: P(attack scores above benign), ties count half
    below = np.cumsum(neg_hist) - neg_hist
    auc = float((pos_hist * (below + 0.5 * neg_hist)).sum() / max(pos_hist.sum() * neg_hist.sum(), 1))
    tp = sum(f["flagged"] for k, f in fams.items() if k != "BENIGN")
    pos = sum(f["n"] for k, f in fams.items() if k != "BENIGN")
    fp = fams.get("BENIGN", {}).get("flagged", 0)
    neg = fams.get("BENIGN", {}).get("n", 0)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(pos, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    files = result.get("files", [])
    scope = "" if result.get("complete") else f" (INCOMPLETE: {len(files)} files so far)"
    if result.get("limit_rows"):
        scope += f" (trial: first {result['limit_rows']:,} rows of each file)"
    print(f"\nTrained on CICIDS2017 (corrected), tested on CSE-CIC-IDS-2018 (corrected){scope}: "
          f"{pos + neg:,} flows scored, {pos:,} attack")
    print(f"AUC {auc:.4f}  F1 {f1:.4f}  precision {precision:.4f}  recall {recall:.4f}  "
          f"false-positive rate {fp / max(neg, 1):.6f} ({fp:,} of {neg:,} benign flagged)")
    print("\n| Family | flows | flagged as attack |\n|---|---|---|")
    for fam in sorted(fams, key=lambda k: (k != "BENIGN", k)):
        f = fams[fam]
        print(f"| {fam} | {f['n']:,} | {f['flagged'] / max(f['n'], 1):.4f} |")
    print("\n| Raw label | counted as | flows | flagged as attack |\n|---|---|---|---|")
    for raw, s in sorted(stats.items(), key=lambda kv: -kv[1]["n"]):
        print(f"| {raw} | {describe(raw, infiltration_portscan)} | {s['n']:,} | "
              f"{s['flagged'] / max(s['n'], 1):.4f} |")
    dropped = {raw: s["dropped"] for raw, s in stats.items() if s.get("dropped")}
    if dropped:
        print(f"\nNot scored, missing or infinite values (as the served pipeline drops them): {dropped}")
    if result.get("missing_in_test"):
        print(f"Features absent from the 2018 files, scored as missing values: {result['missing_in_test']}")
    if unmapped:
        print(f"\nLabels with no family, left out of the figures above: {unmapped}")
    return {"auc": round(auc, 6), "f1": round(f1, 4), "precision": round(precision, 4),
            "recall": round(recall, 4), "false_positive_rate": round(fp / max(neg, 1), 6),
            "flows": pos + neg, "attack": pos,
            "families": {k: {"n": v["n"], "flagged_as_attack": round(v["flagged"] / max(v["n"], 1), 4)}
                         for k, v in fams.items()}, "unmapped": unmapped}


# --------------------------------------------------------------------- main
def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--train", help="folder with the corrected CICIDS2017 CSVs")
    parser.add_argument("--test", help="the corrected CSE-CIC-IDS-2018 zip, or a folder of its CSVs")
    parser.add_argument("--model", help="saves the trained model here; if the file exists it is loaded instead")
    parser.add_argument("--out", default="cross_dataset_2018.json")
    parser.add_argument("--chunk-rows", type=int, default=200_000)
    parser.add_argument("--workers", type=int, default=1,
                        help="files scored at once, each in its own process (about 1 GB of memory each)")
    parser.add_argument("--limit-rows", type=int, help="read only the first N rows of each file (a quick trial)")
    parser.add_argument("--report", help="print the tables again from a saved result, without reading data")
    parser.add_argument("--infiltration-portscan", choices=["portscan", "infiltration"], default="portscan")
    parser.add_argument("--attempted", choices=["benign", "drop"], default="benign")
    args = parser.parse_args()

    if args.report:
        report(json.loads(Path(args.report).read_text()), args.infiltration_portscan, args.attempted)
        return
    if not args.test:
        parser.error("--test is needed (or --report)")

    started = time.time()
    files = list_csvs(args.test)
    if not files:
        sys.exit(f"no CSV files in {args.test}")
    total = sum(size for _, size in files)
    out = Path(args.out)
    if args.workers > 1 and not args.model:
        args.model = str(out.with_name(out.stem + "_model.ubj"))     # the workers load it from here
    model, features, info = get_model(args.train, args.model)

    print(f"scoring CSE-CIC-IDS-2018 (corrected): {len(files)} files, {total / 1e9:.1f} GB uncompressed, "
          f"{args.workers} at a time", flush=True)
    scoring_started = time.time()
    out.parent.mkdir(parents=True, exist_ok=True)
    stats, per_file, missing = {}, [], set()
    result = {"train": "CICIDS2017 corrected, all five days", "test": "CSE-CIC-IDS-2018 corrected",
              "params": PARAMS, "training": info, "features": features, "limit_rows": args.limit_rows,
              "score_histogram": {"log_odds_from": LO, "to": HI, "bins": BINS}}
    done = 0
    for name, size, part in scored_files(model, features, args, files):
        if part is None:
            continue
        done += size
        merge(stats, part["stats"])
        per_file.append({"file": name, "rows": part["rows"], "seconds": round(part["seconds"], 1),
                         "bytes": size, "bytes_read": part["bytes_read"],
                         "repeated_headers": part["repeated_headers"]})
        elapsed = time.time() - scoring_started
        line = f"  {name}: {part['rows']:,} rows in {part['seconds']:.0f} s; {len(per_file)} of {len(files)} files done"
        if not args.limit_rows and done < total:
            line += f", about {(total - done) * elapsed / done / 60:.0f} min left"
        print(line, flush=True)
        if part["missing"] and not set(part["missing"]) <= missing:
            print(f"    features not in this file, scored as missing values: {part['missing']}")
        missing.update(part["missing"])
        result.update(files=per_file, missing_in_test=sorted(missing), labels=as_json(stats), complete=False)
        out.write_text(json.dumps(result))      # saved after every file

    result["complete"] = True
    result["summary"] = report(result, args.infiltration_portscan, args.attempted)
    result["minutes"] = round((time.time() - started) / 60, 1)
    if args.limit_rows and per_file:
        read = sum(f["bytes_read"] for f in per_file)
        rate = read / max(sum(f["seconds"] for f in per_file), 1e-9)     # bytes a second, one worker
        sizes = [size for _, size in files]
        options = [w for w in (1, 2, 3, 4) if w <= max(1, (os.cpu_count() or 1) // 2) or w == 1]
        result["estimate"] = {"flows": int(sum(f["rows"] for f in per_file) * total / max(read, 1)),
                              "minutes_by_workers": {w: round(makespan(sizes, w, rate)) for w in options}}
        by = ", ".join(f"{m} min with --workers {w}" for w, m in result["estimate"]["minutes_by_workers"].items())
        print(f"\nThe full run would score about {result['estimate']['flows'] / 1e6:.1f} million flows: roughly "
              f"{by}. This computer has {os.cpu_count()} logical CPUs; each worker needs about 1 GB of memory.")
    out.write_text(json.dumps(result))
    print(f"\nwrote {out} ({result['minutes']} min)")


if __name__ == "__main__":
    main()
