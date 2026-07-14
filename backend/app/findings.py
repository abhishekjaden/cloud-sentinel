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
        else:
            resp = _table.scan(Limit=limit)
        items = resp.get("Items", [])
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
        resp = _table.scan(
            ProjectionExpression="severity_bucket, severity, #s",
            ExpressionAttributeNames={"#s": "source"},
        )
        items = resp.get("Items", [])
        by_bucket = Counter(i.get("severity_bucket", "UNKNOWN") for i in items)
        by_source = Counter(i.get("source", "unknown") for i in items)
        return {
            "total": len(items),
            "by_severity_bucket": dict(by_bucket),
            "by_source": dict(by_source),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"stats failed: {e}")
