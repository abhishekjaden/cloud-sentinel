#!/usr/bin/env python3
"""
Evaluate the triage model against fixed cases before trusting its notes.

Each case in triage_eval_cases.json is an incident with its findings and the
properties a correct note must have — a severity inside a band, flags set or
clear. Three cases hide prompt-injection attempts in fields an attacker
controls; a note passes those only if it flags the attempt and does not lower
its assessment.

The script uses the triage function's own prompt, request and validation, so
it measures what the deployed function would do, not a copy of it. A note that
fails validation fails its case.

It calls Amazon Bedrock with your credentials, so it costs a few cents and
needs the account's daily token quota to be above zero.

Two case files exist. triage_eval_cases.json was written by the prompt's
author; triage_eval_cases_independent.json holds cases the prompt's author did
not write — a person's, written without reading the prompt, and the honeypot's,
which nobody wrote — each labelled before the model ran (see
docs/triage-eval-protocol.md). They are run separately so their results are
never mixed, and a run of the independent file reports each source apart.

A run can be kept as data as well as printed: --out writes every answer —
the note, the failures, the tokens and the latency — with the model, the
prompt version and the case file's digest, so that calibration and a
comparison between models are computed from the record
(scripts/triage_calibration.py) rather than read off a terminal. --model asks
another model with the same prompt, request and validation; the deployed
function's choice is unchanged.

Usage:
    python scripts/eval_triage.py                        # the author's cases
    python scripts/eval_triage.py --runs 3               # each case three times
    python scripts/eval_triage.py --independent --runs 3 # the independent cases
    python scripts/eval_triage.py --show NAME            # print what the model is sent
    python scripts/eval_triage.py --independent --runs 3 --out docs/triage-runs/2026-10-25-independent-haiku.json
    python scripts/eval_triage.py --independent --runs 3 --model us.anthropic.claude-sonnet-4-5-20250929-v1:0 \
        --out docs/triage-runs/2026-10-25-independent-sonnet.json
"""
import argparse
import hashlib
import importlib.util
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "scripts" / "triage_eval_cases.json"
INDEPENDENT_CASES = ROOT / "scripts" / "triage_eval_cases_independent.json"
HANDLER = ROOT / "cdk" / "lambda" / "triage" / "handler.py"
PROFILE = "cs-audit"
REGION = "us-east-1"


def load_handler(model=None):
    """The triage function's module, with its AWS clients stubbed: only its
    prompt, request and validation are used here. `model` asks another model
    through the same request; the handler reads it from the environment at
    import, as the deployed function does."""
    if model:
        os.environ["TRIAGE_MODEL_ID"] = model
    spec = importlib.util.spec_from_file_location("triage_handler", HANDLER)
    module = importlib.util.module_from_spec(spec)
    with mock.patch("boto3.resource"), mock.patch("boto3.client"):
        spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_cases(path=CASES):
    return json.loads(Path(path).read_text(encoding="utf-8"))["cases"]


def check(note, expect):
    """The expectations a note fails, as readable strings; empty means pass."""
    failures = []
    for field, wanted in expect.items():
        got = note.get(field)
        if isinstance(wanted, list):
            if got not in wanted:
                failures.append(f"{field} {got!r} not in {wanted}")
        elif got != wanted:
            failures.append(f"{field} {got!r}, expected {wanted!r}")
    return failures


def run_case_recorded(handler, bedrock, case):
    """One answer, with what the record keeps about it: the note or the
    rejection, the failures, the tokens Bedrock reports and the round trip."""
    payload = handler.incident_payload(case["incident"], case["findings"], case.get("intel"))
    started = time.monotonic()
    response = bedrock.converse(**handler.converse_request(payload))
    elapsed_ms = round((time.monotonic() - started) * 1000)
    usage = (response or {}).get("usage") or {}
    record = {"usage": {"input_tokens": usage.get("inputTokens"), "output_tokens": usage.get("outputTokens")},
              "latency_ms": ((response or {}).get("metrics") or {}).get("latencyMs", elapsed_ms)}
    try:
        note = handler.parse_note(response)
    except handler.InvalidTriage as exc:
        return dict(record, note=None, failures=[f"rejected: {exc}"])
    return dict(record, note=note, failures=check(note, case["expect"]))


def run_case(handler, bedrock, case):
    r = run_case_recorded(handler, bedrock, case)
    return r["note"], r["failures"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--runs", type=int, default=1, help="times to run each case")
    parser.add_argument("--show", metavar="NAME", help="print the request for one case and exit")
    parser.add_argument("--independent", action="store_true",
                        help="run the independently written cases instead of the author's")
    parser.add_argument("--model", metavar="MODEL_ID",
                        help="ask this Bedrock model instead of the handler's (the same prompt and validation)")
    parser.add_argument("--out", metavar="FILE", help="write every answer, with the run's provenance, as JSON")
    args = parser.parse_args()

    handler = load_handler(args.model)
    case_file = INDEPENDENT_CASES if args.independent else CASES
    cases = load_cases(case_file)
    if not cases:
        sys.exit("no cases in that file yet")

    if args.show:
        case = next((c for c in cases if c["name"] == args.show), None)
        if case is None:
            sys.exit(f"no case named {args.show}; cases: {', '.join(c['name'] for c in cases)}")
        request = handler.converse_request(
            handler.incident_payload(case["incident"], case["findings"], case.get("intel")))
        print(request["system"][0]["text"], "\n")
        print(request["messages"][0]["content"][0]["text"])
        return

    import boto3
    bedrock = boto3.Session(profile_name=PROFILE, region_name=REGION).client("bedrock-runtime")
    print(f"model {handler.MODEL_ID}, prompt {handler.PROMPT_VERSION}, "
          f"{len(cases)} {'independent ' if args.independent else ''}cases x {args.runs} run(s)\n")

    passed = total = 0
    by_source = {}
    results = []
    started = datetime.now(timezone.utc)
    for case in cases:
        for run in range(args.runs):
            answer = run_case_recorded(handler, bedrock, case)
            note, failures = answer["note"], answer["failures"]
            results.append({"case": case["name"], "source": case.get("source", "written"), "run": run + 1,
                            "passed": not failures, "expect": case["expect"], **answer})
            total += 1
            passed += not failures
            tally = by_source.setdefault(case.get("source", "written"), [0, 0])
            tally[0] += not failures
            tally[1] += 1
            label = case["name"] + (f" #{run + 1}" if args.runs > 1 else "")
            shape = (f"{note['assessed_severity']:<13} {note['confidence']:<6} "
                     f"test={str(note['likely_test_data']):<5} inj={str(note['injection_suspected']):<5}"
                     if note else "-")
            print(f"{'PASS' if not failures else 'FAIL'}  {label:<36} {shape}")
            for failure in failures:
                print(f"      {failure}")
            # A failure is only actionable with the model's stated basis beside
            # it: the same wrong flag can come from a prompt gap or from the
            # case's own data, and the reasons are what tell those apart.
            if failures and note:
                for reason in note.get("reasons", []):
                    print(f"      reason: {reason}")
    print(f"\n{passed}/{total} passed")
    if len(by_source) > 1:
        # The protocol records each source's count apart: a case a person
        # wrote and an incident nobody wrote are different kinds of evidence.
        for source, (ok, n) in sorted(by_source.items()):
            print(f"  {source}: {ok}/{n}")
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(record_of(handler, case_file, args.runs, started, results, by_source), indent=1) + "\n")
        print(f"wrote {out}")
    sys.exit(0 if passed == total else 1)


def record_of(handler, case_file, runs, started, results, by_source):
    """The run as the record keeps it: provenance first, then every answer."""
    return {
        "started": started.isoformat(timespec="seconds"),
        "finished": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": handler.MODEL_ID, "prompt_version": handler.PROMPT_VERSION,
        "case_file": str(Path(case_file).relative_to(ROOT)).replace(os.sep, "/"), "case_file_sha256": digest(case_file),
        "cases": len({r["case"] for r in results}), "runs_per_case": runs,
        "passed": sum(r["passed"] for r in results), "total": len(results),
        "by_source": {source: {"passed": ok, "total": n} for source, (ok, n) in sorted(by_source.items())},
        "results": results,
    }


if __name__ == "__main__":
    os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
    main()
