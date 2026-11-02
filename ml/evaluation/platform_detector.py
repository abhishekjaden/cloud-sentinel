"""
Put section 7's H to work: train it again, check that it is the model section
7 recorded, and choose its threshold by the rule section 8 fixed before the
threshold was computed.

`docs/generalization-protocol.md`, section 8, fixes the rule. Section 7's test
days are spent as a test — their verdicts stand as recorded — and from here
they are the days a threshold is chosen on: the lowest threshold at which H
flags at most 0.5% of their benign flows and at most 5% of the operator's
visits among them, half of G9's limits. The rule fails if at that threshold H
flags less than 95% of those days' unsolicited inbound flows, or of those from
addresses new to the training days; the detector is then not put to work at
these limits, and the record says so.

    python ml/evaluation/platform_detector.py --flows ml/harmonized/honeypot-flows.csv

    # the tables again from the saved record
    python ml/evaluation/platform_detector.py --report ml/models/platform_detector.json

H is trained again on section 7's training days at section 7's settings and
must reproduce section 7's record exactly — every count flagged on the test
days at a probability of 0.5, and the AUC to six places — or no threshold is
chosen and nothing is written but the record of the mismatch. The model goes
to `ml/models/platform_detector.ubj`, which git ignores: the deployment
carries it, and the function that serves it refuses a file whose SHA-256 is
not the one recorded here. The record — that hash, the threshold, the figures
it was chosen on and the library versions — goes to
`ml/models/platform_detector.json`. Counts and fractions only: the CSV holds
addresses and is not committed.
"""
import argparse
import hashlib
import json
import math
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cross_matrix import fit, score, versions  # noqa: E402
from harmonize import FEATURES  # noqa: E402
from honeypot_timesplit import OPERATOR, at_least, measure, read_flows, split  # noqa: E402

BENIGN_LIMIT = 0.005        # half of G9's 1%, on section 7's test days
OPERATOR_LIMIT = 0.05       # half of G9's 10%
RECALL_FLOOR = 0.95         # at the chosen threshold, on the same days: the rule fails below it
RECORDED = "ml/models/honeypot_timesplit.json"
MODEL_OUT = "ml/models/platform_detector.ubj"
OUT = "ml/models/platform_detector.json"


# ------------------------------------------------------------------ the rule
def lowest_threshold(margins, limit):
    """The lowest threshold t at which at most `limit` (a fraction) of the
    margins are flagged, a margin being flagged when it is at least t.

    That is the float32 just above the (k+1)-th highest margin, k being the
    number the limit allows: every margin tied with it falls below t too, and
    any lower t would flag k+1 or more. Margins are XGBoost's, float32, and
    the threshold is one of them so that a serving copy of the model compares
    exactly as this does. Minus infinity if the limit allows every margin."""
    m = np.sort(np.asarray(margins, dtype=np.float32))[::-1]
    allowed = int(math.floor(limit * len(m) + 1e-9))
    if allowed >= len(m):
        return float("-inf")
    return float(np.nextafter(m[allowed], np.float32(np.inf), dtype=np.float32))


def decide(test, margin, train_attackers):
    """Section 8's rule on the days it names: the threshold, the figures at
    it, and whether the rule is met."""
    benign = test.y == 0
    operator = test.category == OPERATOR
    from_benign = lowest_threshold(margin[benign], BENIGN_LIMIT)
    from_operator = lowest_threshold(margin[operator], OPERATOR_LIMIT) if operator.any() else float("-inf")
    t = max(from_benign, from_operator)
    figures = measure(margin >= t, margin, test, train_attackers)
    met = (at_least(figures["inbound"]["fraction"], RECALL_FLOOR)
           and at_least(figures["inbound_new_addresses"]["fraction"], RECALL_FLOOR))
    threshold = {"margin": t, "probability": probability(t),
                 "from_benign_limit": from_benign, "from_operator_limit": from_operator}
    return threshold, figures, bool(met)


def probability(margin):
    if margin == float("-inf"):
        return 0.0
    return round(1.0 / (1.0 + math.exp(-margin)), 9)


# ------------------------------------------------------------- reproduction
def reproduction(recorded, now):
    """Every count section 7 recorded for H, beside the same count now, and
    the AUC. The model is section 7's only if every one is equal."""
    checks = {}
    for key in ("inbound", "inbound_new_addresses", "benign"):
        checks[key] = {"recorded": [recorded[key]["n"], recorded[key]["flagged"]],
                       "now": [now[key]["n"], now[key]["flagged"]]}
    for category in sorted(set(recorded["by_category"]) | set(now["by_category"])):
        rec, cur = recorded["by_category"].get(category, {}), now["by_category"].get(category, {})
        checks[f"category: {category}"] = {"recorded": [rec.get("n"), rec.get("flagged")],
                                           "now": [cur.get("n"), cur.get("flagged")]}
    checks["auc"] = {"recorded": recorded["auc"], "now": now["auc"]}
    return all(c["recorded"] == c["now"] for c in checks.values()), checks


# ----------------------------------------------------------------------- run
def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write(out, result):
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=1) + "\n")


def run(flows, recorded, model_out, out, log=print):
    """Train H again, check it against section 7's record, apply the rule,
    and write the model only if both hold."""
    h = recorded["models"]["H"]
    params = recorded["params"]
    train, test = split(flows, recorded["cut"])
    if not len(train) or not len(test) or train.y.min() == train.y.max():
        sys.exit("the cut leaves a side empty or the training days with one class; nothing is run")
    train_attackers = set(train.remote[train.y == 1])
    result = {"protocol_section": 8, "cut": recorded["cut"], "params": params, "features": FEATURES,
              "versions": versions(), "recorded_versions": recorded.get("versions"),
              "dropped_non_finite": flows.dropped,
              "rule": {"benign_at_most": BENIGN_LIMIT, "operator_at_most": OPERATOR_LIMIT,
                       "recall_at_least": RECALL_FLOOR, "chosen_on": "section 7's test days"},
              "started": datetime.now(timezone.utc).isoformat(timespec="seconds")}

    started = time.time()
    model = fit(train.X, train.y, params)
    margin = score(model, test.X)
    log(f"H trained again on {len(train):,} flows in {time.time() - started:.1f} s")

    reproduced, checks = reproduction(h, measure(margin >= 0, margin, test, train_attackers))
    result["reproduction"] = {"reproduced": reproduced, "checks": checks}
    if not reproduced:
        result.update(complete=False, finished=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        write(out, result)
        sys.exit(f"H does not reproduce section 7's record; no threshold is chosen. The checks are in {out}.")

    threshold, figures, met = decide(test, margin, train_attackers)
    result.update(threshold=threshold, at_threshold=figures, rule_met=met)
    if met:
        model_out = Path(model_out)
        model_out.parent.mkdir(parents=True, exist_ok=True)
        model.save_model(str(model_out))
        result["model"] = {"file": model_out.name, "sha256": sha256(model_out),
                           "bytes": model_out.stat().st_size, "trees": model.num_boosted_rounds()}
    result.update(complete=True, finished=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    write(out, result)
    return result


def report(result, log=print):
    pct = lambda f: "—" if f is None else f"{100 * f:.2f}%"  # noqa: E731
    r = result["reproduction"]
    log(f"Reproduction of section 7's H: {'exact' if r['reproduced'] else 'NOT EXACT'}")
    for name, check in r["checks"].items():
        if check["recorded"] != check["now"]:
            log(f"  {name}: recorded {check['recorded']}, now {check['now']}")
    if not r["reproduced"]:
        return
    t, f, rule = result["threshold"], result["at_threshold"], result["rule"]
    op = f["by_category"].get(OPERATOR, {"n": 0, "flagged": 0, "fraction": None})
    log(f"\nThreshold: probability {t['probability']:.6f} (margin {t['margin']:.6f}); "
        f"the benign limit asks {t['from_benign_limit']:.6f}, the operator's {t['from_operator_limit']:.6f}")
    log("\n| On section 7's test days, at the threshold | Figure | Rule |\n|---|---|---|")
    log(f"| benign flagged | {f['benign']['flagged']:,} of {f['benign']['n']:,}, {pct(f['benign']['fraction'])} "
        f"| at most {pct(rule['benign_at_most'])} |")
    log(f"| operator's visits flagged | {op['flagged']} of {op['n']} | at most {pct(rule['operator_at_most'])} |")
    log(f"| unsolicited inbound flagged | {f['inbound']['flagged']:,} of {f['inbound']['n']:,}, "
        f"{pct(f['inbound']['fraction'])} | at least {pct(rule['recall_at_least'])} |")
    new = f["inbound_new_addresses"]
    log(f"| from new addresses | {new['flagged']:,} of {new['n']:,}, {pct(new['fraction'])} "
        f"| at least {pct(rule['recall_at_least'])} |")
    log(f"\nRule {'met' if result['rule_met'] else 'NOT MET: the detector is not put to work at these limits'}.")
    if "model" in result:
        m = result["model"]
        log(f"Model: {m['file']}, {m['trees']} trees, {m['bytes']:,} bytes, SHA-256 {m['sha256']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--flows", help="scripts/pcap_flows.py's CSV of the third run")
    parser.add_argument("--recorded", default=RECORDED, help="section 7's result, which H must reproduce")
    parser.add_argument("--model-out", default=MODEL_OUT)
    parser.add_argument("--out", default=OUT)
    parser.add_argument("--report", help="print the tables from a saved record, without data")
    args = parser.parse_args()
    if args.report:
        report(json.loads(Path(args.report).read_text()))
        return
    if not args.flows:
        parser.error("--flows is needed")
    recorded = json.loads(Path(args.recorded).read_text())
    result = run(read_flows(args.flows), recorded, args.model_out, args.out)
    print()
    report(result)
    print(f"\nwrote {args.out}" + (f" and {args.model_out}" if "model" in result else ""))


if __name__ == "__main__":
    main()
