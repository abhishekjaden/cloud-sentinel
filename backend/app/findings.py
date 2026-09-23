"""
Findings routes — read normalized findings from DynamoDB.

Nothing here scans. A scan reads every item in the table on every request, and
returns them in partition order rather than in time order, so the newest-first
list had to read the whole table and sort it in memory — a cost that grew with
the table for a page of fifty.

Both routes are served from indexes instead, which works because the normalizer
writes a closed set of values: every finding's `source` is one of SOURCES and
its `severity_bucket` one of BUCKETS. Querying each partition therefore covers
the table, with no source or bucket left out. `test_normalizer.py` pins that
the normalizer cannot produce anything else, because the day it can, a finding
written under a value not listed here stops being counted or shown.
"""
import os
from fastapi import APIRouter, HTTPException, Query, Depends
import boto3
from boto3.dynamodb.conditions import Key

from app.auth import require_auth

router = APIRouter()

TABLE_NAME = os.environ.get("FINDINGS_TABLE", "cloudsentinel-findings")
REGION = os.environ.get("AWS_REGION", "us-east-1")

_dynamodb = boto3.resource("dynamodb", region_name=REGION)
_table = _dynamodb.Table(TABLE_NAME)

#: Findings by source, in time order. See the datastores stack.
TIME_INDEX = "source-time-index"
SEVERITY_INDEX = "severity-index"

#: Every value the normalizer writes to `source`.
SOURCES = ("guardduty", "securityhub", "inspector", "unknown")
#: Every value the normalizer writes to `severity_bucket`.
BUCKETS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _count(**kwargs):
    """How many items a query matches, without transferring any of them.

    DynamoDB has no aggregate, so counting still reads every item counted — the
    saving is that none of them cross the wire or land in this process. A count
    is paginated like any other query: a single call returns the count for the
    first megabyte examined, which is the bug this route had when it summed a
    single page of a scan and called it the table's total.
    """
    total = 0
    while True:
        resp = _table.query(Select="COUNT", **kwargs)
        total += resp.get("Count", 0)
        if "LastEvaluatedKey" not in resp:
            return total
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _newest(limit):
    """The newest findings across every source, newest first.

    One query per source, each returning that source's newest `limit` in index
    order. The global newest `limit` can only come from those: a finding left
    out of its own source's newest `limit` has `limit` newer findings ahead of
    it in that source alone.
    """
    merged = []
    for source in SOURCES:
        resp = _table.query(
            IndexName=TIME_INDEX,
            KeyConditionExpression=Key("source").eq(source),
            ScanIndexForward=False,
            Limit=limit,
        )
        merged.extend(resp.get("Items", []))
    return sorted(merged, key=lambda i: i.get("sk", ""), reverse=True)[:limit]


@router.get("/findings", dependencies=[Depends(require_auth)])
def list_findings(
    limit: int = Query(50, ge=1, le=200),
    severity_bucket: str | None = Query(None, description="filter: LOW/MEDIUM/HIGH/CRITICAL"),
):
    """List normalized findings, most recent first. Optional severity filter via GSI."""
    try:
        if severity_bucket:
            resp = _table.query(
                IndexName=SEVERITY_INDEX,
                KeyConditionExpression=Key("severity_bucket").eq(severity_bucket),
                ScanIndexForward=False,
                Limit=limit,
            )
            items = resp.get("Items", [])
        else:
            items = _newest(limit)
        return {"count": len(items), "findings": items}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"findings query failed: {e}")


@router.get("/findings/{pk}", dependencies=[Depends(require_auth)])
def get_finding(pk: str):
    """Fetch a single finding by its partition key."""
    try:
        resp = _table.query(KeyConditionExpression=Key("pk").eq(pk))
        items = resp.get("Items", [])
        if not items:
            raise HTTPException(status_code=404, detail="finding not found")
        return items[0] if len(items) == 1 else {"count": len(items), "items": items}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"finding fetch failed: {e}")


@router.get("/stats", dependencies=[Depends(require_auth)])
def stats():
    """Dashboard summary: counts by severity bucket and finding source.

    Counted a partition at a time rather than by reading the table and
    tallying it here, so the work this process does no longer grows with the
    number of findings. The total comes from the severity buckets, which
    every finding has exactly one of.
    """
    try:
        by_bucket = {
            bucket: _count(IndexName=SEVERITY_INDEX,
                           KeyConditionExpression=Key("severity_bucket").eq(bucket))
            for bucket in BUCKETS
        }
        by_source = {
            source: _count(IndexName=TIME_INDEX,
                           KeyConditionExpression=Key("source").eq(source))
            for source in SOURCES
        }
        return {
            "total": sum(by_bucket.values()),
            # Reported as the old tally did: a bucket or source with nothing in
            # it is absent, not zero.
            "by_severity_bucket": {k: n for k, n in by_bucket.items() if n},
            "by_source": {k: n for k, n in by_source.items() if n},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"stats failed: {e}")
