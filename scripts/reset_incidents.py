#!/usr/bin/env python3
"""
One-off reset of the incidents table.

Until the correlator derived each incident's ID from the attack itself, every
scheduled run inserted a fresh copy of every incident it had already recorded:
four incidents became several hundred rows within two days. The fixed
correlator updates records in place, but it cannot recognise rows written
under the old random IDs, so those must be removed once.

Deleting them is safe because the table holds only derived data. Every
incident is rebuilt from the findings table on the correlator's next run, and
no analyst state exists yet — nothing yet lets an analyst close an incident —
so nothing is lost that the next run does not restore.

Deploy the fixed correlator before running this. Reset first and the old
version simply writes the duplicates back within fifteen minutes.

Without --yes this only counts, which also makes it the check that the fix
works: count, invoke the correlator, count again — the number must not move.

Usage:
    python scripts/reset_incidents.py          # count rows (changes nothing)
    python scripts/reset_incidents.py --yes    # delete every row
"""
import argparse
import sys

import boto3

TABLE = "cloudsentinel-incidents"
PROFILE = "cs-audit"
REGION = "us-east-1"


def incident_keys(table):
    """Every incident_id in the table, following scan pagination to the end."""
    keys, kwargs = [], {"ProjectionExpression": "incident_id"}
    while True:
        page = table.scan(**kwargs)
        keys.extend(item["incident_id"] for item in page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            return keys
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Count, or with --yes delete, every row in the incidents table.")
    parser.add_argument("--yes", action="store_true", help="delete the rows")
    parser.add_argument("--profile", default=PROFILE)
    parser.add_argument("--region", default=REGION)
    args = parser.parse_args(argv)

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    table = session.resource("dynamodb").Table(TABLE)

    keys = incident_keys(table)
    print(f"{TABLE}: {len(keys)} rows")
    if not args.yes:
        return 0

    # batch_writer groups deletes into 25-item requests and retries throttled ones.
    with table.batch_writer() as batch:
        for key in keys:
            batch.delete_item(Key={"incident_id": key})
    print(f"deleted {len(keys)} rows — the correlator rebuilds the table on its next run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
