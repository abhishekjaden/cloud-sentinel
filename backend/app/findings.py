"""Findings routes — read normalized findings from DynamoDB."""
import os
from collections import Counter
from fastapi import APIRouter, HTTPException, Query, Depends
import boto3
from boto3.dynamodb.conditions import Key

from app.auth import require_auth

router = APIRouter()

TABLE_NAME = os.environ.get("FINDINGS_TABLE", "cloudsentinel-findings")
REGION = os.environ.get("AWS_REGION", "us-east-1")

_dynamodb = boto3.resource("dynamodb", region_name=REGION)
_table = _dynamodb.Table(TABLE_NAME)


def _scan_all(**kwargs):
    """Every item a scan matches, following pagination to the end.

    DynamoDB returns at most 1 MB per scan call, and findings are partitioned
    by source — pk is "<source>#<account>" — so one call reads roughly one
    source's partition and stops. Reading a single page, /stats reported 981
    findings, every one from Security Hub, while the same table held the
    GuardDuty findings the correlator was grouping into incidents.
    """
    items = []
    while True:
        resp = _table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


@router.get("/findings", dependencies=[Depends(require_auth)])
def list_findings(
    limit: int = Query(50, ge=1, le=200),
    severity_bucket: str | None = Query(None, description="filter: LOW/MEDIUM/HIGH/CRITICAL"),
):
    """List normalized findings, most recent first. Optional severity filter via GSI."""
    try:
        if severity_bucket:
            resp = _table.query(
                IndexName="severity-index",
                KeyConditionExpression=Key("severity_bucket").eq(severity_bucket),
                ScanIndexForward=False,
                Limit=limit,
            )
            items = resp.get("Items", [])
        else:
            # A scan returns items in partition order, not time order, and a
            # page-limited scan returns only the first source. Recency across
            # every source needs the whole table; sk begins with created_at.
            # This reads the full table per request, which is acceptable at the
            # current size; a recency index is the fix once it is not.
            items = sorted(_scan_all(), key=lambda i: i.get("sk", ""),
                           reverse=True)[:limit]
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
    """Dashboard summary: counts by severity bucket and finding source/type."""
    try:
        items = _scan_all(
            ProjectionExpression="severity_bucket, severity, #s",
            ExpressionAttributeNames={"#s": "source"},
        )
        by_bucket = Counter(i.get("severity_bucket", "UNKNOWN") for i in items)
        by_source = Counter(i.get("source", "unknown") for i in items)
        return {
            "total": len(items),
            "by_severity_bucket": dict(by_bucket),
            "by_source": dict(by_source),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"stats failed: {e}")
