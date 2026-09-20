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

Usage:
    python scripts/eval_triage.py              # run every case
    python scripts/eval_triage.py --runs 3     # each case three times
    python scripts/eval_triage.py --show NAME  # print what the model is sent
"""
import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "scripts" / "triage_eval_cases.json"
HANDLER = ROOT / "cdk" / "lambda" / "triage" / "handler.py"
PROFILE = "cs-audit"
REGION = "us-east-1"


def load_handler():
    """The triage function's module, with its AWS clients stubbed: only its
    prompt, request and validation are used here."""
    spec = importlib.util.spec_from_file_location("triage_handler", HANDLER)
    module = importlib.util.module_from_spec(spec)
    with mock.patch("boto3.resource"), mock.patch("boto3.client"):
        spec.loader.exec_module(module)
    return module


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


def run_case(handler, bedrock, case):
    payload = handler.incident_payload(case["incident"], case["findings"])
    response = bedrock.converse(**handler.converse_request(payload))
    try:
        note = handler.parse_note(response)
    except handler.InvalidTriage as exc:
        return None, [f"rejected: {exc}"]
    return note, check(note, case["expect"])


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--runs", type=int, default=1, help="times to run each case")
    parser.add_argument("--show", metavar="NAME", help="print the request for one case and exit")
    args = parser.parse_args()

    handler = load_handler()
    cases = load_cases()

    if args.show:
        case = next((c for c in cases if c["name"] == args.show), None)
        if case is None:
            sys.exit(f"no case named {args.show}; cases: {', '.join(c['name'] for c in cases)}")
        request = handler.converse_request(handler.incident_payload(case["incident"], case["findings"]))
        print(request["system"][0]["text"], "\n")
        print(request["messages"][0]["content"][0]["text"])
        return

    import boto3
    bedrock = boto3.Session(profile_name=PROFILE, region_name=REGION).client("bedrock-runtime")
    print(f"model {handler.MODEL_ID}, prompt {handler.PROMPT_VERSION}, "
          f"{len(cases)} cases x {args.runs} run(s)\n")

    passed = total = 0
    for case in cases:
        for run in range(args.runs):
            note, failures = run_case(handler, bedrock, case)
            total += 1
            passed += not failures
            label = case["name"] + (f" #{run + 1}" if args.runs > 1 else "")
            shape = (f"{note['assessed_severity']:<13} {note['confidence']:<6} "
                     f"test={str(note['likely_test_data']):<5} inj={str(note['injection_suspected']):<5}"
                     if note else "-")
            print(f"{'PASS' if not failures else 'FAIL'}  {label:<36} {shape}")
            for failure in failures:
                print(f"      {failure}")
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
    main()
