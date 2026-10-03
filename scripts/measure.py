#!/usr/bin/env python3
"""
Measure what the platform does, from its own records.

Every finding is stamped three times on its way in — when EventBridge emitted
it, when it reached the stream, when the normalizer wrote it — and every
incident and note carries the time it was made. The gaps between those stamps
are the platform's latency, read from the tables rather than estimated, and
this script reports them as percentiles with the count behind each.

It also puts a price on it: the audit account's cost for the period, from
Cost Explorer, divided by the findings stored in it. Cost Explorer may be
closed to the audit account (the payer decides); the latency figures are
reported either way.

What it measures, and what each number means:
  queued      EventBridge event time -> stream arrival     (EventBridge + Kinesis)
  stored      stream arrival -> normalizer write           (the normalizer)
  ingested    EventBridge event time -> normalizer write   (the two above)
  detected    GuardDuty's created_at -> normalizer write   (includes GuardDuty's own delay, and
                                                           for a finding GuardDuty re-reported,
                                                           the time since its first report)
  correlated  incident first_seen -> incident created      (ingestion + the 15-minute schedule)
  triaged     incident created -> note written             (the 15-minute schedule + the model)

Usage:
    python scripts/measure.py                        # everything in the tables
    python scripts/measure.py --since 2026-10-03T09:00Z   # findings stored after a time
    python scripts/measure.py --json out.json        # keep the figures
"""
import argparse
import json
import math
import sys
from datetime import datetime, timedelta, timezone

PROFILE = "cs-audit"
REGION = "us-east-1"
TABLES = {"findings": "cloudsentinel-findings", "incidents": "cloudsentinel-incidents",
          "triage": "cloudsentinel-triage"}

MEASURES = [
    ("queued", "event_time", "queued_at"),
    ("stored", "queued_at", "stored_at"),
    ("ingested", "event_time", "stored_at"),
    ("detected", "created_at", "stored_at"),
]


# ------------------------------------------------------------------ parsing
def moment(value):
    """An ISO timestamp as an aware datetime, or None. The sources differ —
    "Z", "+00:00", with or without fractions — and a value that is not a time
    counts as absent rather than failing the run."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def gap(item, start, end):
    """Seconds from one stamp to another on one record, or None if either is
    missing; negative gaps (clock skew between sources) are kept as they are,
    because hiding them would make the figures look better than they are."""
    a, b = moment(item.get(start)), moment(item.get(end))
    return (b - a).total_seconds() if a and b else None


def percentiles(values):
    """n, p50, p95, max — nearest-rank percentiles, no interpolation: the
    p95 of twenty values is the nineteenth, a value that occurred."""
    values = sorted(v for v in values if v is not None)
    if not values:
        return {"n": 0}

    def rank(p):
        return values[max(0, math.ceil(p * len(values)) - 1)]
    return {"n": len(values), "p50": rank(0.5), "p95": rank(0.95), "max": values[-1]}


# -------------------------------------------------------------- the figures
def latency(findings, incidents, notes):
    """Every latency figure, from the records given."""
    figures = {name: percentiles(gap(f, start, end) for f in findings) for name, start, end in MEASURES}
    figures["correlated"] = percentiles(gap(i, "first_seen", "created_at") for i in incidents)
    by_id = {n.get("incident_id"): n for n in notes}
    figures["triaged"] = percentiles(
        gap({"created_at": i.get("created_at"), "triaged_at": by_id[i["incident_id"]].get("triaged_at")},
            "created_at", "triaged_at")
        for i in incidents if i.get("incident_id") in by_id and by_id[i["incident_id"]].get("status") == "complete")
    return figures


def cost_per_thousand(cost_usd, findings_count):
    return round(cost_usd / findings_count * 1000, 2) if findings_count else None


# ---------------------------------------------------------------- reading
def scan_all(table, **kwargs):
    items = []
    while True:
        resp = table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def period_cost(session, start, end):
    """The account's unblended cost between two dates, by service. Returns
    None when Cost Explorer refuses, which it does for a member account the
    payer has not opened it to."""
    try:
        ce = session.client("ce", region_name="us-east-1")
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start.strftime("%Y-%m-%d"), "End": end.strftime("%Y-%m-%d")},
            Granularity="MONTHLY", Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}])
    except Exception as exc:  # noqa: BLE001 — the latency figures stand without the price
        print(f"cost: unavailable ({type(exc).__name__}: {exc})", file=sys.stderr)
        return None
    by_service = {}
    for result in resp.get("ResultsByTime", []):
        for group in result.get("Groups", []):
            amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
            by_service[group["Keys"][0]] = by_service.get(group["Keys"][0], 0.0) + amount
    return {"total": round(sum(by_service.values()), 2),
            "by_service": {k: round(v, 2) for k, v in sorted(by_service.items(), key=lambda kv: -kv[1]) if v >= 0.01}}


# ---------------------------------------------------------------- report
def seconds(value):
    if value is None:
        return "—"
    if abs(value) < 60:
        return f"{value:.1f}s"
    if abs(value) < 3600:
        return f"{value / 60:.1f}m"
    return f"{value / 3600:.1f}h"


def report(figures, cost, findings_count, since):
    lines = [f"Latency{' since ' + since.isoformat(timespec='minutes') if since else ''}, from the tables",
             "", "| Measure | n | p50 | p95 | max |", "|---|---|---|---|---|"]
    for name in ("queued", "stored", "ingested", "detected", "correlated", "triaged"):
        f = figures[name]
        lines.append(f"| {name} | {f['n']} | {seconds(f.get('p50'))} | {seconds(f.get('p95'))} | {seconds(f.get('max'))} |")
    lines.append("")
    if cost:
        per_thousand = cost_per_thousand(cost["total"], findings_count)
        lines.append(f"Cost: ${cost['total']:.2f} for the period, {findings_count} findings stored, "
                     f"${per_thousand} per 1,000 findings")
        for service, amount in list(cost["by_service"].items())[:8]:
            lines.append(f"  {amount:8.2f}  {service}")
    else:
        lines.append(f"Cost: unavailable; {findings_count} findings stored")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--since", help="count findings stored at or after this ISO time")
    parser.add_argument("--profile", default=PROFILE)
    parser.add_argument("--json", metavar="FILE", help="also write the figures as JSON")
    args = parser.parse_args()
    since = moment(args.since) if args.since else None
    if args.since and not since:
        sys.exit(f"--since {args.since!r} is not an ISO timestamp")

    import boto3
    session = boto3.Session(profile_name=args.profile, region_name=REGION)
    dynamodb = session.resource("dynamodb")
    findings = scan_all(dynamodb.Table(TABLES["findings"]))
    if since:
        findings = [f for f in findings if (moment(f.get("stored_at")) or datetime.min.replace(tzinfo=timezone.utc)) >= since]
    incidents = scan_all(dynamodb.Table(TABLES["incidents"]))
    if since:
        incidents = [i for i in incidents if (moment(i.get("created_at")) or datetime.min.replace(tzinfo=timezone.utc)) >= since]
    notes = scan_all(dynamodb.Table(TABLES["triage"]))

    figures = latency(findings, incidents, notes)
    now = datetime.now(timezone.utc)
    start = since or (now - timedelta(days=30))
    cost = period_cost(session, start, now + timedelta(days=1))

    print(report(figures, cost, len(findings), since))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"measured_at": now.isoformat(timespec="seconds"), "since": since.isoformat() if since else None,
                       "findings": len(findings), "incidents": len(incidents), "latency": figures, "cost": cost,
                       "cost_per_thousand_findings": cost_per_thousand(cost["total"], len(findings)) if cost else None},
                      f, indent=2, default=str)


if __name__ == "__main__":
    main()
