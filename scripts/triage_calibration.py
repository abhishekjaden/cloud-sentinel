#!/usr/bin/env python3
"""
Read what the triage model's confidence is worth, and compare models, from
the records eval_triage.py --out writes.

A triage note carries a confidence beside its severity. The protocol has so
far measured only whether the severity fell inside its band; this reads the
record for two more things. Calibration: when the model says "high", is it
right more often than when it says "medium" or "low"? If not, the field
carries no information and an analyst should not read it as doubt. And
consistency: asked the same incident three times at temperature zero, does it
give one severity or several? The same record answers what a model costs per
note, from the tokens Bedrock reports, and how long it takes.

Given two records of the same case file under different models, the tables are
printed side by side, and every case where the two disagree on pass or fail is
listed with both models' reasons — the comparison ADR 0005 assumed rather than
measured.

    python scripts/triage_calibration.py docs/triage-runs/2026-10-25-independent-haiku.json
    python scripts/triage_calibration.py docs/triage-runs/2026-10-25-independent-haiku.json \\
        docs/triage-runs/2026-10-25-independent-sonnet.json --json docs/triage-runs/2026-10-25-comparison.json

Cost uses list prices per million tokens; --price MODEL_SUBSTRING IN OUT
overrides the built-in table, and the record's invoice is the figure to quote.
"""
import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

CONFIDENCES = ("high", "medium", "low")
SEVERITIES = ("critical", "high", "medium", "low", "informational")
# Dollars per million tokens, input and output, at the list prices published
# when this was written (October 2026). A model not matched here has no cost
# line unless --price names it.
LIST_PRICES = {"haiku-4-5": (1.00, 5.00), "sonnet-4-5": (3.00, 15.00), "opus-4-1": (15.00, 75.00)}


def load(path):
    record = json.loads(Path(path).read_text(encoding="utf-8"))
    for key in ("model", "prompt_version", "case_file", "results"):
        if key not in record:
            sys.exit(f"{path}: not a record eval_triage.py --out wrote (no {key})")
    return record


def rate(ok, n):
    return ok / n if n else float("nan")


def by_field(results, field, levels):
    """Answers and passes for each value of a note field, in the field's order."""
    counts = {level: [0, 0] for level in levels}
    for r in results:
        note = r.get("note")
        if not note:
            continue
        level = note.get(field)
        if level in counts:
            counts[level][1] += 1
            counts[level][0] += r["passed"]
    return {level: {"answers": n, "passed": ok, "pass_rate": round(rate(ok, n), 4) if n else None}
            for level, (ok, n) in counts.items()}


def consistency(results):
    """Per case: the severities given across its runs; how many cases gave one."""
    per_case = defaultdict(list)
    for r in results:
        per_case[r["case"]].append(r["note"]["assessed_severity"] if r.get("note") else "rejected")
    cases = {name: dict(Counter(levels)) for name, levels in per_case.items()}
    unanimous = sum(1 for levels in per_case.values() if len(set(levels)) == 1)
    return {"cases": len(per_case), "unanimous": unanimous, "runs_per_case": max((len(v) for v in per_case.values()), default=0),
            "split": {name: levels for name, levels in cases.items() if len(levels) > 1}}


def flags(results):
    """How often each flag was right, against the expectation."""
    out = {}
    for flag in ("likely_test_data", "injection_suspected"):
        n = ok = 0
        for r in results:
            if r.get("note") is None or flag not in r.get("expect", {}):
                continue
            n += 1
            ok += r["note"][flag] == r["expect"][flag]
        out[flag] = {"checked": n, "correct": ok, "rate": round(rate(ok, n), 4) if n else None}
    return out


def price_for(model, prices):
    for key, (pin, pout) in prices.items():
        if key in model:
            return pin, pout
    return None


def cost(results, model, prices):
    tokens_in = [r["usage"]["input_tokens"] for r in results if r.get("usage", {}).get("input_tokens") is not None]
    tokens_out = [r["usage"]["output_tokens"] for r in results if r.get("usage", {}).get("output_tokens") is not None]
    latency = [r["latency_ms"] for r in results if r.get("latency_ms") is not None]
    out = {"answers_with_usage": len(tokens_in),
           "input_tokens_mean": round(statistics.fmean(tokens_in)) if tokens_in else None,
           "output_tokens_mean": round(statistics.fmean(tokens_out)) if tokens_out else None,
           "latency_ms_median": round(statistics.median(latency)) if latency else None,
           "latency_ms_p95": round(sorted(latency)[max(0, int(len(latency) * 0.95) - 1)]) if latency else None}
    p = price_for(model, prices)
    if p and tokens_in and tokens_out:
        per_note = (sum(tokens_in) * p[0] + sum(tokens_out) * p[1]) / 1e6 / len(tokens_in)
        out.update({"price_per_million_tokens": {"input": p[0], "output": p[1]},
                    "usd_per_note": round(per_note, 6), "usd_per_1000_notes": round(per_note * 1000, 3)})
    return out


def summarize(record, prices):
    results = record["results"]
    return {
        "model": record["model"], "prompt_version": record["prompt_version"], "case_file": record["case_file"],
        "case_file_sha256": record.get("case_file_sha256"), "started": record.get("started"),
        "passed": sum(r["passed"] for r in results), "total": len(results),
        "rejected": sum(1 for r in results if r.get("note") is None),
        "by_source": record.get("by_source", {}),
        "by_confidence": by_field(results, "confidence", CONFIDENCES),
        "by_severity": by_field(results, "assessed_severity", SEVERITIES),
        "flags": flags(results),
        "consistency": consistency(results),
        "cost": cost(results, record["model"], prices),
    }


def disagreements(a, b):
    """Cases where the two records' runs differ in pass or fail, with both
    sides' severities and the reasons of the failing side."""
    def by_case(record):
        out = defaultdict(list)
        for r in record["results"]:
            out[r["case"]].append(r)
        return out
    ra, rb = by_case(a), by_case(b)
    rows = []
    for case in sorted(set(ra) | set(rb)):
        pa = [r["passed"] for r in ra.get(case, [])]
        pb = [r["passed"] for r in rb.get(case, [])]
        if sum(pa) == len(pa) and sum(pb) == len(pb):
            continue
        if sum(pa) == sum(pb) and len(pa) == len(pb):
            continue
        rows.append({
            "case": case, "source": (ra.get(case) or rb.get(case))[0].get("source"),
            "a": {"passed": sum(pa), "runs": len(pa),
                  "severities": [r["note"]["assessed_severity"] if r.get("note") else "rejected" for r in ra.get(case, [])],
                  "reasons": next((r["note"]["reasons"] for r in ra.get(case, []) if not r["passed"] and r.get("note")), [])},
            "b": {"passed": sum(pb), "runs": len(pb),
                  "severities": [r["note"]["assessed_severity"] if r.get("note") else "rejected" for r in rb.get(case, [])],
                  "reasons": next((r["note"]["reasons"] for r in rb.get(case, []) if not r["passed"] and r.get("note")), [])},
        })
    return rows


def pct(x):
    return "—" if x is None else f"{x:.0%}"


def render(summaries, pairs, log=print):
    names = [s["model"].split(".")[-1] if "." in s["model"] else s["model"] for s in summaries]
    width = max(len(n) for n in names) + 2

    def row(label, cells):
        log(f"| {label:<34} | " + " | ".join(str(c).ljust(width) for c in cells) + " |")

    log(f"Case file {summaries[0]['case_file']}, prompt {', '.join(sorted({s['prompt_version'] for s in summaries}))}\n")
    log("| " + " " * 34 + " | " + " | ".join(n.ljust(width) for n in names) + " |")
    log("|" + "-" * 36 + "|" + "|".join("-" * (width + 2) for _ in names) + "|")
    row("passed / total", [f"{s['passed']}/{s['total']}" for s in summaries])
    row("rejected answers", [s["rejected"] for s in summaries])
    for source in sorted({k for s in summaries for k in s["by_source"]}):
        row(f"  {source}", [f"{s['by_source'][source]['passed']}/{s['by_source'][source]['total']}"
                            if source in s["by_source"] else "—" for s in summaries])
    for level in CONFIDENCES:
        row(f"pass rate at confidence {level}", [f"{pct(s['by_confidence'][level]['pass_rate'])} (n={s['by_confidence'][level]['answers']})"
                                                for s in summaries])
    for level in SEVERITIES:
        if any(s["by_severity"][level]["answers"] for s in summaries):
            row(f"pass rate at severity {level}", [f"{pct(s['by_severity'][level]['pass_rate'])} (n={s['by_severity'][level]['answers']})"
                                                  for s in summaries])
    for flag in ("likely_test_data", "injection_suspected"):
        row(f"{flag} correct", [f"{s['flags'][flag]['correct']}/{s['flags'][flag]['checked']}" for s in summaries])
    row("cases unanimous across runs", [f"{s['consistency']['unanimous']}/{s['consistency']['cases']}" for s in summaries])
    row("input / output tokens, mean", [f"{s['cost']['input_tokens_mean']} / {s['cost']['output_tokens_mean']}" for s in summaries])
    row("latency ms, median / p95", [f"{s['cost']['latency_ms_median']} / {s['cost']['latency_ms_p95']}" for s in summaries])
    row("USD per 1,000 notes (list)", [s["cost"].get("usd_per_1000_notes", "—") for s in summaries])
    for s, name in zip(summaries, names):
        if s["consistency"]["split"]:
            log(f"\n{name}: cases that gave more than one severity across runs:")
            for case, levels in s["consistency"]["split"].items():
                log(f"  {case}: " + ", ".join(f"{k} x{v}" for k, v in levels.items()))
    for (na, nb), rows in pairs:
        log(f"\nCases where {na} and {nb} differ on pass or fail:" if rows else f"\n{na} and {nb} pass and fail the same cases.")
        for r in rows:
            log(f"  {r['case']} ({r['source']}): {na} {r['a']['passed']}/{r['a']['runs']} {r['a']['severities']}; "
                f"{nb} {r['b']['passed']}/{r['b']['runs']} {r['b']['severities']}")
            for side, name in ((r["a"], na), (r["b"], nb)):
                for reason in side["reasons"][:3]:
                    log(f"      {name} reason: {reason}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("records", nargs="+", help="JSON files eval_triage.py --out wrote")
    parser.add_argument("--price", nargs=3, action="append", default=[], metavar=("MODEL_SUBSTRING", "IN", "OUT"),
                        help="dollars per million input and output tokens for models whose id contains the substring")
    parser.add_argument("--json", metavar="FILE", help="write the summaries and disagreements as JSON")
    args = parser.parse_args()
    prices = dict(LIST_PRICES)
    for key, pin, pout in args.price:
        prices[key] = (float(pin), float(pout))
    records = [load(p) for p in args.records]
    files = {r["case_file"] for r in records}
    if len(files) > 1:
        sys.exit(f"the records are of different case files and cannot be compared: {sorted(files)}")
    summaries = [summarize(r, prices) for r in records]
    pairs = []
    for i in range(len(records)):
        for j in range(i + 1, len(records)):
            pairs.append(((summaries[i]["model"].split(".")[-1], summaries[j]["model"].split(".")[-1]),
                          disagreements(records[i], records[j])))
    render(summaries, pairs)
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps({"summaries": summaries,
                                               "disagreements": [{"models": list(k), "cases": v} for k, v in pairs]},
                                              indent=1) + "\n")
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
