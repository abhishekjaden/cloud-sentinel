#!/usr/bin/env python3
"""
Turn the honeypot's incidents into unlabelled evaluation cases.

The honeypot (docs/triage-eval-protocol.md, section 1) exists to be attacked,
so that the platform sees incidents nobody wrote. This script copies each
incident against a resource out of the tables — the incident as the
correlator recorded it, its findings as the triage function reads them, and
the enricher's verdict on each address it names — into the case shape of
scripts/triage_eval_cases.json, with the label left empty for a person to
write before the model is run on the case.

It never reads the triage table. The platform has already written a note on
each of these incidents, and a label written after reading the note is not a
label; whoever labels these must not open the notes in the console either.

Usage, from a terminal with the audit profile logged in:

    python scripts/honeypot_cases.py --resource i-0056dd9b1a24c9c16 --out ~/Downloads/honeypot-cases.json

Then, in the file, fill each case's "why", "expect.assessed_severity" (the
band, lowest to highest), "labelled_by" and "labelled_on"; the two flags are
false for real traffic. The labelled file is merged into
scripts/triage_eval_cases_independent.json with "source": "honeypot", and
scripts/eval_triage.py --independent runs it and reports each source apart.
"""
import argparse
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from boto3.dynamodb.conditions import Key

INCIDENTS_TABLE = "cloudsentinel-incidents"
FINDINGS_TABLE = "cloudsentinel-findings"
INTEL_TABLE = "cloudsentinel-intel"
PROFILE = "cs-audit"
REGION = "us-east-1"
MAX_FINDINGS = 20
MAX_INDICATORS = 20


def _plain(value):
    """DynamoDB's Decimals as JSON numbers, recursively."""
    from decimal import Decimal
    if isinstance(value, Decimal):
        return int(value) if value == int(value) else float(value)
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


def _second_floor(value, delta):
    moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (moment.astimezone(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%S")


def incidents_for(ddb, resource):
    table = ddb.Table(INCIDENTS_TABLE)
    kwargs = {"FilterExpression": "#r = :r", "ExpressionAttributeNames": {"#r": "resource"},
              "ExpressionAttributeValues": {":r": resource}}
    found = []
    while True:
        resp = table.scan(**kwargs)
        found.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    found.sort(key=lambda i: str(i.get("first_seen", "")))
    return found


def findings_of(ddb, incident):
    """The incident's own findings, read as the triage function reads them:
    by the sort-key range of the attack's span, then by finding ID."""
    table = ddb.Table(FINDINGS_TABLE)
    wanted = {str(f) for f in incident.get("finding_ids") or []}
    low = _second_floor(incident["first_seen"], timedelta(seconds=-1))
    high = _second_floor(incident["last_seen"], timedelta(seconds=1))
    found = []
    for source in incident.get("sources") or ["guardduty"]:
        kwargs = {"KeyConditionExpression":
                  Key("pk").eq(f"{source}#{incident['account_id']}") & Key("sk").between(low, high)}
        while True:
            resp = table.query(**kwargs)
            found.extend(i for i in resp.get("Items", []) if str(i.get("finding_id")) in wanted)
            if "LastEvaluatedKey" not in resp:
                break
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    found.sort(key=lambda i: str(i.get("sk", "")))
    return found[:MAX_FINDINGS]


def verdicts_for(ddb, incident):
    """The enricher's rows for the incident's indicators, cut to the fields
    the triage function describes to the model."""
    found = incident.get("indicators") or {}
    keys = [f"ip:{v}" for v in found.get("ips") or []] + [f"domain:{v}" for v in found.get("domains") or []]
    keys = keys[:MAX_INDICATORS]
    if not keys:
        return {}
    resp = ddb.batch_get_item(RequestItems={INTEL_TABLE: {"Keys": [{"indicator": k} for k in keys]}})
    rows = {}
    for row in resp.get("Responses", {}).get(INTEL_TABLE, []):
        kept = {"verdict": row.get("verdict")}
        abuse = row.get("abuseipdb") or {}
        if abuse:
            kept["abuseipdb"] = {"confidence": _plain(abuse.get("confidence", 0)),
                                 "reports": _plain(abuse.get("reports", 0))}
        otx = row.get("otx") or {}
        if otx:
            kept["otx"] = {"pulses": _plain(otx.get("pulses", 0))}
        rows[row["indicator"]] = kept
    return rows


def case_of(ddb, incident, n):
    findings = findings_of(ddb, incident)
    first_day = str(incident.get("first_seen", ""))[:10]
    family = re.sub(r"[^a-z0-9]+", "-", "-".join(sorted({str(f.get("finding_type", "")).split("/")[-1]
                                                        for f in findings})).lower()).strip("-")
    case = {
        "name": f"honeypot-{first_day}-{n}-{family}"[:60],
        "source": "honeypot",
        "why": "",
        "written_by": "nobody: GuardDuty, against the honeypot (docs/triage-eval-protocol.md, section 1)",
        "labelled_by": "",
        "labelled_on": "",
        "incident_id": str(incident.get("incident_id")),
        "incident": {
            "resource": str(incident.get("resource")),
            "account_id": str(incident.get("account_id")),
            "first_seen": str(incident.get("first_seen")),
            "last_seen": str(incident.get("last_seen")),
            "duration_seconds": _plain(incident.get("duration_seconds", 0)),
            "finding_count": _plain(incident.get("finding_count", len(findings))),
            "max_severity": _plain(incident.get("max_severity", 0)),
            "attack_stages": [str(s) for s in incident.get("attack_stages") or []],
            "finding_types": [str(t) for t in incident.get("finding_types") or []],
        },
        "findings": [{
            "created_at": str(f.get("created_at")),
            "finding_type": str(f.get("finding_type")),
            "severity": _plain(f.get("severity", 0)),
            "title": str(f.get("title")),
            "resource": str(f.get("resource")),
        } for f in findings],
        "expect": {"assessed_severity": [], "likely_test_data": False, "injection_suspected": False},
    }
    indicators = incident.get("indicators") or {}
    cleaned = {k: [str(v) for v in indicators.get(k) or []] for k in ("ips", "domains") if indicators.get(k)}
    if cleaned:
        case["incident"]["indicators"] = cleaned
        intel = verdicts_for(ddb, incident)
        if intel:
            case["intel"] = intel
    return case


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--resource", required=True, help="the honeypot instance ID")
    parser.add_argument("--out", required=True, help="where to write the unlabelled cases")
    parser.add_argument("--profile", default=PROFILE)
    args = parser.parse_args()

    ddb = boto3.Session(profile_name=args.profile, region_name=REGION).resource("dynamodb")
    incidents = incidents_for(ddb, args.resource)
    if not incidents:
        raise SystemExit(f"no incident names {args.resource}")
    cases = [case_of(ddb, inc, n + 1) for n, inc in enumerate(incidents)]
    out = Path(args.out).expanduser()
    out.write_text(json.dumps({
        "_about": ("Unlabelled cases copied from the honeypot's incidents by scripts/honeypot_cases.py, "
                   "without reading the triage notes. Fill why, expect.assessed_severity, labelled_by and "
                   "labelled_on before anyone looks at a note; then merge into "
                   "scripts/triage_eval_cases_independent.json."),
        "cases": cases}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{len(cases)} unlabelled case(s) written to {out}:")
    for c in cases:
        verdicts = ", ".join(f"{k.split(':', 1)[1]} {v.get('verdict')}" for k, v in (c.get("intel") or {}).items())
        print(f"  {c['name']:<48} {len(c['findings'])} finding(s), severity {c['incident']['max_severity']}"
              f"{'  ' + verdicts if verdicts else ''}")
    print("Label them without opening their notes in the console.")


if __name__ == "__main__":
    main()
