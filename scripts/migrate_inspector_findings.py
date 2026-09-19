#!/usr/bin/env python3
"""
One-off correction of Inspector findings stored before the normalizer fix.

Two defects in how Inspector events were normalized left every stored
Inspector finding wrong:

  - severity: Inspector sends a word ("HIGH"). The normalizer passed it to
    int(), which failed, so every finding was stored as 0 and bucketed INFO.
  - created_at: Inspector sends "Wed Sep 04 16:59:44.356 UTC 2024", which was
    stored as sent. It sorts above every ISO timestamp, so Inspector findings
    headed the newest-first list whatever their age.

The fixed normalizer handles new events. This corrects the rows already stored,
from what they kept: the severity word (raw_severity_label) and the original
timestamp. It uses the normalizer's own conversion functions, loaded from
cdk/lambda/normalizer, so the two cannot disagree.

The timestamp is part of the sort key, so a row cannot be updated in place: it
is written under its corrected key and the old row deleted. Every write
completes before any delete begins, so an interrupted run can leave a
duplicate, which re-running removes, but never lose a row. If a corrected row
already exists because Inspector re-sent the finding after the fix, it is newer
and is kept; only the old row goes.

Only rows the old normalizer wrote are touched. It stored severity 0 for every
Inspector finding, so a non-zero severity marks a row the fixed normalizer
wrote from the precise inspectorScore; the word-based estimate used here must
not overwrite it.

Deploy the fixed normalizer first, or findings arriving meanwhile are stored
the old way again. The findings table has point-in-time recovery enabled.

Without --yes this only reports what it would change.

Usage:
    python scripts/migrate_inspector_findings.py          # report, change nothing
    python scripts/migrate_inspector_findings.py --yes    # rewrite the rows
"""
import argparse
import importlib.util
import sys
from collections import Counter
from pathlib import Path
from unittest import mock

import boto3
from boto3.dynamodb.conditions import Attr

TABLE = "cloudsentinel-findings"
PROFILE = "cs-audit"
REGION = "us-east-1"
NORMALIZER = (Path(__file__).resolve().parents[1]
              / "cdk" / "lambda" / "normalizer" / "handler.py")


def load_normalizer():
    """The normalizer's functions, without it connecting to anything.

    It opens a DynamoDB handle when imported, which needs a default region the
    local machine may not have; that handle is stubbed, since only the pure
    conversion functions are used here."""
    spec = importlib.util.spec_from_file_location("normalizer_handler", NORMALIZER)
    module = importlib.util.module_from_spec(spec)
    with mock.patch("boto3.resource"):
        spec.loader.exec_module(module)
    return module


def inspector_rows(table):
    rows, kwargs = [], {"FilterExpression": Attr("pk").begins_with("inspector#")}
    while True:
        page = table.scan(**kwargs)
        rows.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            return rows
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def plan(rows, normalizer):
    """Work out the corrections without making any.

    Returns (puts, deletes, report): items to write, keys to remove, and counts.
    """
    existing = {(r["pk"], r["sk"]) for r in rows}
    puts, deletes = [], []
    report = Counter()
    before, after = Counter(), Counter()

    for row in rows:
        before[row.get("severity_bucket", "?")] += 1
        created = normalizer._inspector_time(row.get("created_at"), None)
        if created is None:
            report["unreadable timestamp, left as is"] += 1
            after[row.get("severity_bucket", "?")] += 1
            continue

        severity = row.get("severity", 0)
        if not severity:
            severity = normalizer._inspector_score({"severity": row.get("raw_severity_label")})

        fixed = dict(row)
        fixed["created_at"] = created
        fixed["sk"] = f"{created}#{row.get('finding_id') or 'unknown'}"
        fixed["severity"] = severity
        fixed["severity_bucket"] = normalizer._severity_bucket(severity)
        after[fixed["severity_bucket"]] += 1

        if fixed == row:
            report["already correct"] += 1
        elif fixed["sk"] == row["sk"]:
            puts.append(fixed)
            report["severity corrected in place"] += 1
        elif (fixed["pk"], fixed["sk"]) in existing:
            deletes.append({"pk": row["pk"], "sk": row["sk"]})
            report["newer corrected row exists, old row removed"] += 1
        else:
            puts.append(fixed)
            deletes.append({"pk": row["pk"], "sk": row["sk"]})
            report["rewritten under corrected key"] += 1

    return puts, deletes, {"counts": report, "before": before, "after": after}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Correct Inspector findings stored before the normalizer fix.")
    parser.add_argument("--yes", action="store_true", help="make the changes")
    parser.add_argument("--profile", default=PROFILE)
    parser.add_argument("--region", default=REGION)
    args = parser.parse_args(argv)

    normalizer = load_normalizer()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    table = session.resource("dynamodb").Table(TABLE)

    rows = inspector_rows(table)
    puts, deletes, report = plan(rows, normalizer)

    print(f"{TABLE}: {len(rows)} Inspector rows")
    for label, count in sorted(report["counts"].items()):
        print(f"  {count:>5}  {label}")
    buckets = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    print("  severity before: " + ", ".join(f"{b} {report['before'][b]}" for b in buckets))
    print("  severity after:  " + ", ".join(f"{b} {report['after'][b]}" for b in buckets))

    if not args.yes:
        print(f"report only: {len(puts)} writes, {len(deletes)} deletes pending "
              "— re-run with --yes to apply")
        return 0

    # Every write lands before any delete starts: an interruption can leave a
    # duplicate for the next run to remove, never a missing finding.
    with table.batch_writer(overwrite_by_pkeys=["pk", "sk"]) as batch:
        for item in puts:
            batch.put_item(Item=item)
    with table.batch_writer(overwrite_by_pkeys=["pk", "sk"]) as batch:
        for key in deletes:
            batch.delete_item(Key=key)
    print(f"applied: {len(puts)} written, {len(deletes)} removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
