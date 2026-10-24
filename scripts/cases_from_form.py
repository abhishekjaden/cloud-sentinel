#!/usr/bin/env python3
"""
Turn a filled-in case form into independent evaluation cases.

The form (a workbook with a Cases sheet and a Findings sheet, described in
docs/triage-eval-protocol.md) is what a person who has not read the prompt
fills in: one row per case with its severity band, flags and reasoning, and
one row per finding. This script turns it into the shape
scripts/eval_triage.py reads, without touching a label: the band is the
levels between the lowest and highest the writer chose, the flags are the
writer's, and the reasoning is copied as written.

What it computes is only what the pipeline would compute from the same
findings — each finding's severity on the platform's 0–100 scale, using the
normalizer's own conversion from GuardDuty's 0–8.9, and the incident's span,
count, highest severity, finding types and kill-chain stages, using the
correlator's own stage table — plus the resource block each finding would
carry, in the shape GuardDuty gives it. (Until 19 October 2026 the severity
was scaled by ten instead, so an 8.0 reached the model as 80 where production
shows 90; the first set was regenerated on the corrected scale, labels
untouched.) Two
mechanical adjustments are made to the writer's identifiers and nothing
else: an access key written in the real format (AKIA or ASIA and sixteen
characters) is shortened by one character, as the authored cases are, so
that secret scanners ignore it; and the incident is placed in the
documentation account 111122223333, since the form does not ask for one.

Needs openpyxl (`pip install openpyxl`), which the backend does not.

Usage:
    python scripts/cases_from_form.py FORM.xlsx [--out scripts/triage_eval_cases_independent.json]
    python scripts/cases_from_form.py FORM.xlsx --print        # to stdout, nothing written
    python scripts/cases_from_form.py FORM.xlsx --source second-person --out /tmp/second-person.json
        # a second person's cases, to be merged into the independent file with their statements

A form with an "AI assistance" column (the second-person form) must have a
statement in every row; it is copied as written into each case's
`ai_assistance`, as the protocol requires from the sixth case on.
"""
import argparse
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CORRELATOR = ROOT / "cdk" / "lambda" / "correlator" / "handler.py"
NORMALIZER = ROOT / "cdk" / "lambda" / "normalizer" / "handler.py"
OUT = ROOT / "scripts" / "triage_eval_cases_independent.json"
ACCOUNT = "111122223333"
LEVELS = ["informational", "low", "medium", "high", "critical"]
KEY = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")

ABOUT = ("Independently written evaluation cases for the advisory triage model, run by "
         "scripts/eval_triage.py --independent. Written on the form in docs/triage-eval-protocol.md "
         "by someone other than the prompt's author, each labelled before the model ran and never "
         "relabelled to pass; converted by scripts/cases_from_form.py, which computes only what the "
         "correlator would (span, count, severity, stages) and changes no label. The same shape as "
         "triage_eval_cases.json. Access keys are one character short of the real format so that "
         "secret scanners ignore them; the account is the documentation one.")


def load_handler(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with mock.patch("boto3.resource"), mock.patch("boto3.client"):
        spec.loader.exec_module(module)
    return module


def load_correlator():
    return load_handler("correlator_handler", CORRELATOR)


def load_normalizer():
    return load_handler("normalizer_handler", NORMALIZER)


def rows(sheet):
    """The sheet's filled rows after its two header lines, as dicts keyed by
    the column headings, skipping the grey example rows."""
    lines = list(sheet.iter_rows(min_row=2, values_only=True))
    headings = [str(h).strip() if h is not None else "" for h in lines[0]]
    out = []
    for line in lines[1:]:
        if not any(v is not None and str(v).strip() for v in line):
            continue
        row = {h: (v.strip() if isinstance(v, str) else v) for h, v in zip(headings, line) if h}
        if str(row.get("Case name", "")).startswith("example-"):
            continue
        out.append(row)
    return out


def col(row, prefix):
    """The value of the column whose heading starts with the given words."""
    for heading, value in row.items():
        if heading.lower().startswith(prefix.lower()):
            return value
    raise KeyError(prefix)


def when(value):
    """A form time as the normalizer stamps a finding, and as a datetime."""
    if isinstance(value, datetime):
        moment = value
    else:
        text = str(value).strip().replace("T", " ")
        moment = datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")
    moment = moment.replace(tzinfo=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z"), moment


def yes(value):
    return str(value).strip().lower() in ("yes", "y", "true")


def key_id(value):
    """An access key one character short of the real format (see ABOUT)."""
    value = str(value).strip()
    return value[:-1] if KEY.match(value) else value


def resource_block(row):
    """The finding's resource as GuardDuty shapes it, by the resource type the
    writer chose; the correlator reads the identifier back from this."""
    kind = str(col(row, "Resource type")).strip().lower()
    ident = str(col(row, "Resource id")).strip()
    principal = col(row, "IAM user or role")
    agent = col(row, "User agent")
    if kind.startswith("ec2"):
        block = {"instanceDetails": {"instanceId": ident}}
        resource = ident
    elif kind.startswith("iam"):
        resource = key_id(ident)
        details = {"accessKeyId": resource}
        if principal:
            details["userName"] = str(principal).strip()
        block = {"accessKeyDetails": details}
    elif kind.startswith("s3"):
        block = {"s3BucketDetails": [{"name": ident, "type": "Destination"}]}
        if principal:
            block["accessKeyDetails"] = {"userName": str(principal).strip()}
        resource = ident
    elif kind.startswith("lambda"):
        block = {"lambdaDetails": {"functionName": ident}}
        resource = ident
    else:
        raise ValueError(f"resource type {kind!r} in case {col(row, 'Case name')!r} is not one the form offers")
    if agent:
        block["userAgent"] = str(agent).strip()
    return resource, json.dumps(block)


def indicators(findings_rows):
    found = {"ips": [], "domains": []}
    for row in findings_rows:
        ip, domain = col(row, "Remote IP"), col(row, "Domain")
        if ip and str(ip).strip() not in found["ips"]:
            found["ips"].append(str(ip).strip())
        if domain and str(domain).strip() not in found["domains"]:
            found["domains"].append(str(domain).strip())
    return {k: v for k, v in found.items() if v}


def band(lowest, highest):
    low, high = LEVELS.index(str(lowest).strip().lower()), LEVELS.index(str(highest).strip().lower())
    if low > high:
        raise ValueError(f"the band's lowest level {lowest!r} is above its highest {highest!r}")
    return LEVELS[low:high + 1]


def convert(workbook_path, source=None):
    import openpyxl
    correlator = load_correlator()
    normalizer = load_normalizer()
    wb = openpyxl.load_workbook(workbook_path, data_only=True)
    cases_rows = rows(wb["Cases"])
    findings_rows = rows(wb["Findings"])
    by_case = {}
    for row in findings_rows:
        by_case.setdefault(str(col(row, "Case name")).strip(), []).append(row)

    cases = []
    for row in cases_rows:
        name = str(col(row, "Case name")).strip()
        if name in {c["name"] for c in cases}:
            raise ValueError(f"case name {name!r} is used twice")
        theirs = by_case.get(name)
        if not theirs:
            raise ValueError(f"case {name!r} has no findings")
        findings, resources = [], set()
        for f in theirs:
            stamp, moment = when(col(f, "Time"))
            resource, block = resource_block(f)
            resources.add(resource)
            findings.append({
                "created_at": stamp,
                "finding_type": str(col(f, "GuardDuty finding type")).strip(),
                "severity": normalizer._severity_to_score("guardduty", col(f, "Severity")),
                "title": str(col(f, "Title")).strip(),
                "resource": block,
                "_moment": moment,
            })
        if len(resources) != 1:
            raise ValueError(f"case {name!r} names more than one resource: {sorted(resources)}")
        findings.sort(key=lambda f: f["_moment"])
        first, last = findings[0]["_moment"], findings[-1]["_moment"]
        stages = {correlator._stage(f["finding_type"]) for f in findings}
        incident = {
            "resource": resources.pop(),
            "account_id": ACCOUNT,
            "first_seen": first.isoformat(),
            "last_seen": last.isoformat(),
            "duration_seconds": int((last - first).total_seconds()),
            "finding_count": len(findings),
            "max_severity": max(f["severity"] for f in findings),
            "attack_stages": [s for s in correlator.STAGE_ORDER if s in stages],
            "finding_types": sorted({f["finding_type"] for f in findings}),
        }
        found = indicators(theirs)
        if found:
            incident["indicators"] = found
        for f in findings:
            del f["_moment"]

        case = {
            "name": name,
            "why": str(col(row, "Why")).strip(),
            "written_by": str(col(row, "Written by")).strip(),
            "labelled_on": (col(row, "Labelled on").strftime("%Y-%m-%d")
                            if isinstance(col(row, "Labelled on"), datetime) else str(col(row, "Labelled on"))),
        }
        if source:
            case["source"] = source
        # The second-person form (24 October 2026) asks each row for a
        # statement on AI assistance; it is copied as given and must be there.
        if any(h.lower().startswith("ai assistance") for h in row):
            statement = str(col(row, "AI assistance") or "").strip()
            if not statement:
                raise ValueError(f"case {name!r} has no statement on AI assistance; write 'none' or the tool")
            case["ai_assistance"] = statement
        planted = col(row, "Planted text")
        if yes(col(row, "Injection attempt")):
            if not planted:
                raise ValueError(f"injection case {name!r} has no planted text")
            case["injected_text"] = str(planted).strip()
        case["incident"] = incident
        case["findings"] = findings
        case["expect"] = {
            "assessed_severity": band(col(row, "Lowest acceptable severity"), col(row, "Highest acceptable severity")),
            "likely_test_data": yes(col(row, "Test data")),
            "injection_suspected": yes(col(row, "Injection attempt")),
        }
        cases.append(case)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("form", help="the filled-in workbook")
    parser.add_argument("--out", default=str(OUT), help=f"where to write (default {OUT.relative_to(ROOT)})")
    parser.add_argument("--print", action="store_true", help="print the cases instead of writing them")
    parser.add_argument("--source", help="recorded on every case, e.g. second-person; eval_triage.py counts each source apart")
    args = parser.parse_args()

    cases = convert(args.form, args.source)
    document = {"_about": ABOUT, "cases": cases}
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    if args.print:
        sys.stdout.write(text)
        return
    existing = json.loads(Path(args.out).read_text(encoding="utf-8")) if Path(args.out).exists() else {}
    if existing.get("cases"):
        sys.exit(f"{args.out} already holds {len(existing['cases'])} cases; "
                 "independent cases are never overwritten, move them aside first")
    Path(args.out).write_text(text, encoding="utf-8")
    print(f"{len(cases)} cases written to {args.out}:")
    for c in cases:
        print(f"  {c['name']:<40} {len(c['findings'])} finding(s)  band {'-'.join(c['expect']['assessed_severity'])}"
              f"{'  test-data' if c['expect']['likely_test_data'] else ''}"
              f"{'  injection' if c['expect']['injection_suspected'] else ''}")


if __name__ == "__main__":
    main()
