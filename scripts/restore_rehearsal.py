#!/usr/bin/env python3
"""
Rehearse a restore of the findings and incidents tables, and time it.

Point-in-time recovery is on for every table, and until this was first run a
restore had never been tried (docs/well-architected-review.md, "No
disaster-recovery drill"). This is the drill. It restores both tables to one
instant as new tables, waits for the copies to become active, and checks each
copy against the live table it was taken from: the copy should hold exactly
the items the live table holds with a stamp at or before that instant — a
finding is stamped `stored_at` when the normalizer writes it, an incident
`created_at` when the correlator makes it — plus any item that carries no
stamp at all, which predates the stamp. An item stamped after the instant is
either new since or rewritten since (a redelivered finding keeps its key and
takes a new `stored_at`); the copy may hold the rewritten ones under their
old stamp, so the copy can exceed the count by at most that many, and the
report says how many there were. The live tables are only ever read.

The copies are deleted at the end unless `--keep` is given. Deleting one is a
DeleteTable on a name beginning `cloudsentinel-`, which the control-change
watch reports (docs/slos.md, objective 8): expect one message per copy, with
the operator's own identity in it, and record the rehearsal as the reason.

The instant restored to is the earlier of the two tables' latest restorable
times, so that both copies are of the same moment and each is within its
table's range; `--at` names one instead.

Usage:
    python scripts/restore_rehearsal.py                        # restore both, compare, delete the copies
    python scripts/restore_rehearsal.py --keep                 # ... and leave the copies in place
    python scripts/restore_rehearsal.py --at 2026-10-21T17:00Z # restore to a chosen instant
    python scripts/restore_rehearsal.py --json docs/restore-rehearsal-2026-10-21.json
    python scripts/restore_rehearsal.py --delete-copies        # only remove copies an earlier run left
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone

PROFILE = "cs-audit"
REGION = "us-east-1"
# Each live table and the attribute that says when an item was written to it.
TABLES = {"cloudsentinel-findings": "stored_at", "cloudsentinel-incidents": "created_at"}
COPY_MARK = "-restored-"
POLL_SECONDS = 15
WAIT_LIMIT_SECONDS = 3 * 3600


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


def copy_name(table, point):
    """The copy carries its source's name and the instant it is of."""
    return f"{table}{COPY_MARK}{point.astimezone(timezone.utc):%Y%m%dT%H%M%SZ}"


def is_copy(name):
    return any(name.startswith(table + COPY_MARK) for table in TABLES)


# ---------------------------------------------------------------- choosing the instant
def restore_point(client, tables, at=None):
    """The instant to restore to: the one asked for, else the earlier of the
    tables' latest restorable times, so that every copy is of the same moment
    and none is asked for a moment its table cannot yet give."""
    if at:
        return at.astimezone(timezone.utc)
    latest = []
    for table in tables:
        resp = client.describe_continuous_backups(TableName=table)
        pitr = resp["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]
        if pitr.get("PointInTimeRecoveryStatus") != "ENABLED":
            raise SystemExit(f"{table}: point-in-time recovery is not enabled; nothing to rehearse")
        latest.append(pitr["LatestRestorableDateTime"].astimezone(timezone.utc))
    return min(latest)


# ---------------------------------------------------------------- restoring
def start_restore(client, table, copy, point):
    """Ask for the copy. Returns the instant DynamoDB says the copy is of."""
    resp = client.restore_table_to_point_in_time(
        SourceTableName=table, TargetTableName=copy, RestoreDateTime=point)
    summary = resp["TableDescription"].get("RestoreSummary", {})
    taken = summary.get("RestoreDateTime")
    return taken.astimezone(timezone.utc) if taken else point


def wait_active(client, copies, poll=POLL_SECONDS, limit=WAIT_LIMIT_SECONDS, sleep=time.sleep, clock=time.monotonic):
    """Poll until every copy — and every index on it — is ACTIVE. Returns, per
    copy, the seconds it took from the start of the wait and the indexes it
    came back with; copies are timed from the same start, so the slower one's
    figure is the rehearsal's."""
    started = clock()
    done = {}
    while len(done) < len(copies):
        for copy in copies:
            if copy in done:
                continue
            table = client.describe_table(TableName=copy)["Table"]
            indexes = table.get("GlobalSecondaryIndexes", [])
            active = table.get("TableStatus") == "ACTIVE" and all(i.get("IndexStatus") == "ACTIVE" for i in indexes)
            restoring = table.get("RestoreSummary", {}).get("RestoreInProgress", False)
            if active and not restoring:
                done[copy] = {"seconds": round(clock() - started, 1),
                              "active_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                              "indexes": sorted(i["IndexName"] for i in indexes)}
                print(f"{copy}: active after {done[copy]['seconds']} s", file=sys.stderr)
        if len(done) < len(copies):
            if clock() - started > limit:
                raise SystemExit(f"gave up after {limit} s; still restoring: "
                                 + ", ".join(c for c in copies if c not in done))
            sleep(poll)
    return done


# ---------------------------------------------------------------- counting
def scan_pages(client, table, **kwargs):
    while True:
        resp = client.scan(TableName=table, **kwargs)
        yield resp
        if "LastEvaluatedKey" not in resp:
            return
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def count_items(client, table):
    """Every item in the table, counted by DynamoDB page by page — not the
    ItemCount a describe reports, which is hours stale."""
    return sum(page.get("Count", 0) for page in scan_pages(client, table, Select="COUNT"))


def stamps(client, table, attr):
    """The stamp of every item, as a list; an item without one contributes None."""
    values = []
    for page in scan_pages(client, table, ProjectionExpression="#t", ExpressionAttributeNames={"#t": attr}):
        for item in page.get("Items", []):
            values.append(item.get(attr, {}).get("S"))
    return values


def tally(values, point):
    """How many stamps fall at or before the instant, how many after, and how
    many are missing or unreadable — which are neither, and are reported as
    their own number rather than counted on either side."""
    counts = {"at_or_before": 0, "after": 0, "unstamped": 0}
    for value in values:
        when = moment(value)
        if when is None:
            counts["unstamped"] += 1
        elif when <= point:
            counts["at_or_before"] += 1
        else:
            counts["after"] += 1
    return counts


def compare(copy_items, live):
    """The copy against the live table at the instant. `expected` is what the
    copy must hold at least: every item stamped at or before the instant and
    every unstamped one. It may hold up to `after` more, one for each item
    rewritten since; it may not hold fewer."""
    expected = live["at_or_before"] + live["unstamped"]
    excess = copy_items - expected
    if excess == 0:
        verdict = "matches"
    elif 0 < excess <= live["after"]:
        verdict = f"{excess} more than the stamps say, within the {live['after']} written since"
    elif excess > 0:
        verdict = f"{excess} more than the stamps say, beyond the {live['after']} written since — unexplained"
    else:
        verdict = f"short by {-excess} — the copy lacks items the live table held at the instant"
    return {"expected": expected, "excess": excess, "verdict": verdict}


# ---------------------------------------------------------------- deleting
def find_copies(client):
    names = []
    kwargs = {}
    while True:
        resp = client.list_tables(**kwargs)
        names.extend(n for n in resp.get("TableNames", []) if is_copy(n))
        if "LastEvaluatedTableName" not in resp:
            return names
        kwargs["ExclusiveStartTableName"] = resp["LastEvaluatedTableName"]


def delete_copies(client, names, wait=True):
    """Delete copies and nothing else: a name that is not a copy's stops the
    whole call before any table is touched."""
    refused = [n for n in names if not is_copy(n)]
    if refused:
        raise ValueError(f"not a copy, not deleting: {', '.join(refused)}")
    for name in names:
        client.delete_table(TableName=name)
        print(f"{name}: deleting", file=sys.stderr)
    if wait:
        for name in names:
            client.get_waiter("table_not_exists").wait(TableName=name, WaiterConfig={"Delay": 10, "MaxAttempts": 90})
    return list(names)


# ---------------------------------------------------------------- the rehearsal
def rehearse(client, at=None, keep=False, sleep=time.sleep, clock=time.monotonic):
    point = restore_point(client, TABLES, at)
    result = {"rehearsed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "restore_point": point.isoformat(timespec="seconds"), "tables": {}, "copies_deleted": []}
    copies = {}
    for table in TABLES:
        copy = copy_name(table, point)
        requested_at = datetime.now(timezone.utc)
        taken = start_restore(client, table, copy, point)
        copies[table] = copy
        result["tables"][table] = {"copy": copy, "requested_at": requested_at.isoformat(timespec="seconds"),
                                   "copy_is_of": taken.isoformat(timespec="seconds")}
        print(f"{table}: restore requested as {copy}", file=sys.stderr)

    active = wait_active(client, list(copies.values()), sleep=sleep, clock=clock)

    for table, attr in TABLES.items():
        copy = copies[table]
        record = result["tables"][table]
        record.update({"seconds_to_active": active[copy]["seconds"], "active_at": active[copy]["active_at"],
                       "indexes": active[copy]["indexes"]})
        record["copy_items"] = count_items(client, copy)
        live = tally(stamps(client, table, attr), point)
        record["live"] = {"stamp": attr, **live, "total_now": sum(live.values())}
        record["comparison"] = compare(record["copy_items"], live)

    if not keep:
        result["copies_deleted"] = delete_copies(client, list(copies.values()))
    return result


def report(result):
    lines = [f"Restore rehearsal at {result['rehearsed_at']}, both tables restored to {result['restore_point']}", ""]
    for table, r in result["tables"].items():
        live = r["live"]
        lines += [
            f"{table}",
            f"  copy {r['copy']}",
            f"  requested {r['requested_at']}, active {r['active_at']}: {r['seconds_to_active']} s, indexes "
            + (", ".join(r["indexes"]) or "none"),
            f"  copy holds {r['copy_items']} items",
            f"  live table now holds {live['total_now']}: {live['at_or_before']} stamped at or before the instant, "
            + f"{live['after']} after it, {live['unstamped']} without a {live['stamp']}",
            f"  copy against the live table at the instant: {r['comparison']['verdict']}",
            "",
        ]
    if result["copies_deleted"]:
        lines.append("copies deleted: " + ", ".join(result["copies_deleted"]))
    else:
        lines.append("copies kept — remove them with --delete-copies")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--at", help="restore to this ISO instant instead of the latest restorable one")
    parser.add_argument("--keep", action="store_true", help="leave the copies in place")
    parser.add_argument("--delete-copies", action="store_true", help="only delete copies left by an earlier run")
    parser.add_argument("--profile", default=PROFILE)
    parser.add_argument("--json", metavar="FILE", help="also write the result as JSON")
    args = parser.parse_args()
    at = moment(args.at) if args.at else None
    if args.at and not at:
        sys.exit(f"--at {args.at!r} is not an ISO timestamp")

    import boto3
    client = boto3.Session(profile_name=args.profile, region_name=REGION).client("dynamodb")

    if args.delete_copies:
        copies = find_copies(client)
        if not copies:
            print("no copies to delete")
            return
        for name in delete_copies(client, copies):
            print(f"deleted {name}")
        return

    result = rehearse(client, at=at, keep=args.keep)
    print(report(result))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)


if __name__ == "__main__":
    main()
