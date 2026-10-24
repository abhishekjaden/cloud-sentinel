"""
Tests for the harmonized schema and the cross-dataset matrix.

The datasets themselves only exist on a laptop with the downloads; what is
pinned here is the mapping — that each source's columns reach the schema with
the right units and definitions, that rows the served pipeline would drop are
dropped and counted, that the raw labels survive as written — and that the
matrix fits and scores the cells it says it does, with an AUC computed
exactly.
"""
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pytest

pd = pytest.importorskip("pandas")
pytest.importorskip("xgboost")

EVAL = Path(__file__).resolve().parents[2] / "ml" / "evaluation"


def load_module(name):
    sys.path.insert(0, str(EVAL))
    spec = importlib.util.spec_from_file_location(name, EVAL / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def harmonize():
    return load_module("harmonize")


@pytest.fixture(scope="module")
def matrix():
    return load_module("cross_matrix")


CIC_HEADER = ("id,Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,Total Fwd Packet,"
              "Total Bwd packets,Total Length of Fwd Packet,Total Length of Bwd Packet,Fwd IAT Mean,Bwd IAT Mean,"
              "Fwd Header Length,Bwd Header Length,Label,Attempted Category")


def cic_row(i, dst_port=22, proto=6, dur_us=2_000_000, fwd=4, bwd=2, fwd_len=100, bwd_len=50,
            fwd_iat=500_000.0, bwd_iat=250_000.0, fwd_hdr=80, bwd_hdr=40, label="BENIGN", attempted=-1):
    return (f"{i},10.0.0.1-10.0.0.2-{40000 + i}-{dst_port}-{proto},10.0.0.1,{40000 + i},10.0.0.2,{dst_port},"
            f"{proto},01/07/2017 09:00:0{i % 10},{dur_us},{fwd},{bwd},{fwd_len},{bwd_len},{fwd_iat},{bwd_iat},"
            f"{fwd_hdr},{bwd_hdr},{label},{attempted}")


def write_cic(folder):
    rows = [CIC_HEADER,
            cic_row(1),                                                   # benign TCP
            cic_row(2, proto=17, label="DoS Hulk", fwd_iat=0.0, bwd=0, bwd_len=0, bwd_iat=0.0, bwd_hdr=0),
            cic_row(3, label="FTP-BruteForce - Attempted"),               # attempted: counted benign
            CIC_HEADER,                                                   # a header repeated inside the file
            cic_row(4, label="SSH-BruteForce", fwd_iat="Infinity"),      # dropped: not finite
            cic_row(5, label="PortScan", dur_us=0, fwd=1, bwd=0, fwd_len=0, bwd_len=0, fwd_iat=0.0, bwd_iat=0.0,
                    fwd_hdr=40, bwd_hdr=0)]                               # one-packet probe
    (folder / "Monday.csv").write_text("\n".join(rows) + "\n", encoding="latin-1")


def test_cic_rows_reach_the_schema_in_seconds_and_ip_bytes(harmonize, tmp_path):
    write_cic(tmp_path)
    meta = harmonize.harmonize("cic2017", str(tmp_path), tmp_path / "out" / "cic.npz", log=lambda *_: None)
    X, y, raw, meta2 = harmonize.load(tmp_path / "out" / "cic.npz")
    assert meta2 == meta
    assert meta["rows"] == 4 and meta["dropped_missing_or_infinite"] == 1 and meta["repeated_headers"] == 1
    assert meta["raw_labels"] == {"BENIGN": 1, "DoS Hulk": 1, "FTP-BruteForce - Attempted": 1, "PortScan": 1}
    assert y.tolist() == [0, 1, 0, 1]                        # attempted attacks count as benign
    f = {name: i for i, name in enumerate(harmonize.FEATURES)}
    first = X[0]
    assert first[f["duration_s"]] == pytest.approx(2.0)      # microseconds → seconds
    assert first[f["fwd_bytes"]] == 180 and first[f["bwd_bytes"]] == 90      # payload + header
    assert first[f["fwd_mean_len"]] == 45 and first[f["bwd_mean_len"]] == 45
    assert first[f["fwd_iat_mean_s"]] == pytest.approx(0.5)
    assert first[f["pkt_rate"]] == pytest.approx(3.0) and first[f["byte_rate"]] == pytest.approx(135.0)
    assert first[f["bwd_fwd_pkt_ratio"]] == pytest.approx(0.5)
    assert (first[f["is_tcp"]], first[f["is_udp"]]) == (1, 0)
    udp = X[1]
    assert (udp[f["is_tcp"]], udp[f["is_udp"]]) == (0, 1) and udp[f["bwd_fwd_pkt_ratio"]] == 0
    probe = X[3]                                              # one packet: rates use the floor, not infinity
    assert probe[f["duration_s"]] == 0 and probe[f["pkt_rate"]] == pytest.approx(1e6)
    assert np.isfinite(X).all()


def test_the_port_is_a_feature_only_when_asked(harmonize, tmp_path):
    write_cic(tmp_path)
    meta = harmonize.harmonize("cic2017", str(tmp_path), tmp_path / "p.npz", with_port=True, log=lambda *_: None)
    X, _, _, _ = harmonize.load(tmp_path / "p.npz")
    assert meta["features"][-1] == "dst_port" and X.shape[1] == len(harmonize.FEATURES) + 1
    assert set(X[:, -1].tolist()) == {22.0}


def test_keep_every_counts_across_chunks_and_files(harmonize, tmp_path):
    rows = [CIC_HEADER] + [cic_row(i) for i in range(1, 11)]
    (tmp_path / "a.csv").write_text("\n".join(rows) + "\n")
    (tmp_path / "b.csv").write_text("\n".join(rows) + "\n")
    meta = harmonize.harmonize("cic2017", str(tmp_path), tmp_path / "k.npz", keep_every=3, chunk_rows=4,
                               log=lambda *_: None)
    assert meta["rows"] == 7                                  # rows 0,3,6,9 of the first file, 2,5,8 of the second


UNSW_FEATURES = "No.,Name,Type ,Description\n" + "\n".join(
    f"{i + 1},{name},x,-" for i, name in enumerate([
        "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss",
        "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz",
        "dmeansz", "trans_depth", "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt",
        "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
        "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
        "ct_dst_src_ltm", "attack_cat", "Label"])) + "\n"


def unsw_raw_row(dsport="22", proto="tcp", dur=1.5, sbytes=1000, dbytes=400, spkts=10, dpkts=5,
                 sintpkt=150.0, dintpkt=300.0, attack_cat="", label=0):
    cols = ["59.166.0.0", "1390", "149.171.126.6", dsport, proto, "FIN", str(dur), str(sbytes), str(dbytes), "31",
            "29", "0", "0", "-", "1000", "400", str(spkts), str(dpkts), "255", "255", "1", "2", "100", "80", "0",
            "0", "0.1", "0.2", "1421927414", "1421927415", str(sintpkt), str(dintpkt), "0", "0", "0", "0", "0", "",
            "0", "", "1", "1", "1", "1", "1", "1", "1", attack_cat, str(label)]
    assert len(cols) == 49
    return ",".join(cols)


def test_unsw_raw_files_get_their_header_from_the_features_file(harmonize, tmp_path):
    (tmp_path / "NUSW-NB15_features.csv").write_text(UNSW_FEATURES, encoding="latin-1")
    (tmp_path / "UNSW-NB15_1.csv").write_text("\n".join([
        unsw_raw_row(),                                                       # normal
        unsw_raw_row(dsport="0x000b", proto="udp", attack_cat=" Fuzzers ", label=1),
        unsw_raw_row(attack_cat="Backdoors", label=1),
        unsw_raw_row(attack_cat="Backdoor", label=1),
        unsw_raw_row(dsport="-", proto="arp", attack_cat="Reconnaissance", label=1),
    ]) + "\n")
    meta = harmonize.harmonize("unsw", str(tmp_path), tmp_path / "u.npz", with_port=True, log=lambda *_: None)
    X, y, raw, _ = harmonize.load(tmp_path / "u.npz")
    assert meta["options"]["unsw_features_file"] == "NUSW-NB15_features.csv"
    assert meta["files"] == [{"file": "UNSW-NB15_1.csv", "bytes": meta["files"][0]["bytes"], "rows_kept": 4,
                              "seconds": meta["files"][0]["seconds"]}]
    assert meta["dropped_missing_or_infinite"] == 1                          # the row with no port
    assert meta["raw_labels"] == {"Backdoor": 2, "Fuzzers": 1, "Normal": 1}  # two spellings, one category; spaces gone
    assert y.tolist() == [0, 1, 1, 1]
    f = {name: i for i, name in enumerate(meta["features"])}
    first = X[0]
    assert first[f["duration_s"]] == pytest.approx(1.5)
    assert first[f["fwd_bytes"]] == 1000 - 14 * 10 and first[f["bwd_bytes"]] == 400 - 14 * 5   # framing taken off
    assert first[f["fwd_iat_mean_s"]] == pytest.approx(0.150)                # milliseconds → seconds
    assert (first[f["is_tcp"]], first[f["is_udp"]]) == (1, 0) and first[f["dst_port"]] == 22
    assert X[1][f["dst_port"]] == 11 and (X[1][f["is_tcp"]], X[1][f["is_udp"]]) == (0, 1)   # hexadecimal port


def test_unsw_split_files_have_a_header_and_no_ports(harmonize, tmp_path):
    header = "id,dur,proto,service,state,spkts,dpkts,sbytes,dbytes,rate,sinpkt,dinpkt,attack_cat,label"
    rows = [header, "1,0.5,tcp,ssh,FIN,4,2,300,120,10,100,200,Normal,0", "2,0.1,udp,dns,CON,1,1,70,90,20,0,0,Generic,1"]
    (tmp_path / "UNSW_NB15_training-set.csv").write_text("\n".join(rows) + "\n")
    meta = harmonize.harmonize("unsw", str(tmp_path), tmp_path / "s.npz", ethernet=0, log=lambda *_: None)
    X, y, _, _ = harmonize.load(tmp_path / "s.npz")
    assert meta["rows"] == 2 and y.tolist() == [0, 1] and meta["options"]["unsw_features_file"] is None
    assert X[0][3] == 300                                                   # ethernet 0: wire bytes kept
    with pytest.raises(ValueError, match="dst_port"):
        harmonize.harmonize("unsw", str(tmp_path), tmp_path / "s2.npz", with_port=True, log=lambda *_: None)


def test_a_features_file_with_other_columns_is_refused(harmonize, tmp_path):
    (tmp_path / "NUSW-NB15_features.csv").write_text(UNSW_FEATURES.replace("Sintpkt", "Sinterval"))
    (tmp_path / "UNSW-NB15_1.csv").write_text(unsw_raw_row() + "\n")
    with pytest.raises(ValueError, match="differ from the 49 expected"):
        harmonize.harmonize("unsw", str(tmp_path), tmp_path / "x.npz", log=lambda *_: None)


def test_flows_already_in_the_schema_are_read_as_they_are(harmonize, tmp_path):
    header = ",".join(harmonize.FEATURES + ["dst_port", "label", "category"])
    row = ",".join(["3.0", "5", "4", "500", "400", "100", "100", "0.7", "0.9", "3", "300", "0.8", "1", "0"])
    (tmp_path / "flows.csv").write_text("\n".join([header, row + ",22,attack,unsolicited inbound",
                                                   row + ",80,benign,operator"]) + "\n")
    meta = harmonize.harmonize("flows", str(tmp_path / "flows.csv"), tmp_path / "f.npz", log=lambda *_: None)
    X, y, raw, _ = harmonize.load(tmp_path / "f.npz")
    assert meta["rows"] == 2 and y.tolist() == [1, 0]
    assert meta["raw_labels"] == {"operator": 1, "unsolicited inbound": 1}
    assert X[0].tolist() == pytest.approx([3.0, 5, 4, 500, 400, 100, 100, 0.7, 0.9, 3, 300, 0.8, 1, 0])


def test_a_missing_column_names_what_was_wanted(harmonize, tmp_path):
    (tmp_path / "odd.csv").write_text("Flow Duration,Label\n1,BENIGN\n")
    with pytest.raises(ValueError, match="fwd_pkts"):
        harmonize.harmonize("cic2017", str(tmp_path), tmp_path / "o.npz", log=lambda *_: None)


def test_derive_handles_empty_directions_without_dividing_by_zero(harmonize):
    X = harmonize.derive([0.0], [1], [0], [40], [0], [0.0], [0.0], [6])
    row = dict(zip(harmonize.FEATURES, X[0].tolist()))
    assert row["fwd_mean_len"] == 40 and row["bwd_mean_len"] == 0 and row["bwd_fwd_pkt_ratio"] == 0
    assert row["pkt_rate"] == pytest.approx(1e6) and row["byte_rate"] == pytest.approx(4e7)
    assert np.isfinite(X).all()


# --------------------------------------------------------------- the matrix
def test_auc_is_the_exact_rank_statistic_with_ties_counted_half(matrix):
    scores = np.array([0.1, 0.4, 0.4, 0.8, 0.9])
    y = np.array([0, 0, 1, 1, 0])
    # pairs (pos, neg): (0.4,0.1)=1 (0.4,0.4)=0.5 (0.4,0.9)=0 (0.8,0.1)=1 (0.8,0.4)=1 (0.8,0.9)=0 → 3.5 of 6
    assert matrix.auc(scores, y) == pytest.approx(3.5 / 6)
    assert matrix.auc(np.array([1, 2, 3]), np.array([0, 0, 1])) == 1.0
    assert np.isnan(matrix.auc(np.array([1, 2]), np.array([1, 1])))


def test_split_is_stratified_and_reproducible(matrix):
    y = np.array([0] * 90 + [1] * 10)
    train, test = matrix.split(y)
    train2, test2 = matrix.split(y)
    assert train.tolist() == train2.tolist() and test.tolist() == test2.tolist()
    assert len(test) == 30 and int(y[test].sum()) == 3 and int(y[train].sum()) == 7
    assert not set(train) & set(test)


def synthetic_table(harmonize, path, shift, n=600, seed=0):
    """A separable toy dataset on the schema: attacks are short one-way bursts."""
    rng = np.random.default_rng(seed)
    y = np.array([0] * (n // 2) + [1] * (n // 2), dtype=np.int8)
    fwd = np.where(y == 1, rng.integers(20, 60, n), rng.integers(2, 10, n)).astype(float)
    bwd = np.where(y == 1, rng.integers(0, 2, n), rng.integers(2, 10, n)).astype(float)
    dur = np.where(y == 1, rng.uniform(0.01, 0.2, n), rng.uniform(1, 30, n)) + shift
    X = harmonize.derive(dur, fwd, bwd, fwd * 60 + shift, bwd * 400, dur / np.maximum(fwd - 1, 1),
                         dur / np.maximum(bwd - 1, 1), np.full(n, 6))
    raw = np.where(y == 1, 1, 0).astype(np.int16)
    np.savez_compressed(path, X=X, y=y, raw=raw)
    Path(path).with_suffix(".json").write_text(json.dumps({
        "dataset": Path(path).stem, "source": "flows", "features": harmonize.FEATURES,
        "raw_labels": {"Normal": int((y == 0).sum()), "Burst": int((y == 1).sum())}}))


def test_the_matrix_fits_every_cell_and_keeps_each_label_apart(harmonize, matrix, tmp_path):
    for name, shift in (("alpha", 0.0), ("beta", 0.5), ("gamma", 1.0), ("hp", 0.2)):
        synthetic_table(harmonize, tmp_path / f"{name}.npz", shift)
    datasets = [matrix.Dataset(tmp_path / f"{n}.npz") for n in ("alpha", "beta", "gamma")]
    extras = [matrix.Dataset(tmp_path / "hp.npz")]
    params = dict(matrix.PARAMS, n_estimators=10, max_depth=3)
    result = matrix.run(datasets, extras, params, tmp_path / "m" / "matrix.json", log=lambda *_: None)
    kinds = [c["kind"] for c in result["cells"]]
    assert kinds.count("within") == 3 and kinds.count("cross") == 6 and kinds.count("leave_one_out") == 3
    assert kinds.count("extra") == 4                      # each full model, then all three together
    assert result["complete"] and json.loads((tmp_path / "m" / "matrix.json").read_text())["complete"]
    within = [c for c in result["cells"] if c["kind"] == "within"]
    assert all(c["auc"] > 0.95 and c["n"] == 180 and c["attack"] == 90 for c in within)
    last = result["cells"][-1]
    assert last["train"] == ["alpha", "beta", "gamma"] and last["test"] == "hp"
    assert set(last["per_raw_label"]) == {"Normal", "Burst"}
    assert last["per_raw_label"]["Burst"]["attack"] is True and last["per_raw_label"]["Normal"]["attack"] is False
    lines = []
    matrix.report(result, log=lines.append)
    text = "\n".join(lines)
    assert "trained on ↓ / tested on →" in text and "the other two" in text and "never trained on" in text


def test_tables_harmonized_differently_are_refused(harmonize, matrix, tmp_path):
    synthetic_table(harmonize, tmp_path / "a.npz", 0.0)
    synthetic_table(harmonize, tmp_path / "b.npz", 0.0)
    b = matrix.Dataset(tmp_path / "b.npz")
    b.features = harmonize.FEATURES + ["dst_port"]
    with pytest.raises(SystemExit, match="harmonized the same way"):
        matrix.run([matrix.Dataset(tmp_path / "a.npz"), b], [], dict(matrix.PARAMS, n_estimators=2),
                   tmp_path / "x.json", log=lambda *_: None)
