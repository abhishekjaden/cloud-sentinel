"""
Incident routes — correlated attacks, read from the table the correlator writes.

A finding is one observation; an incident is the attack that several
observations describe. This is where an analyst starts: fewer items than the
findings list, each with its attack stages already in kill-chain order.
"""
import os
from typing import Literal

import boto3
from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import require_auth

router = APIRouter()

TABLE_NAME = os.environ.get("INCIDENTS_TABLE", "cloudsentinel-incidents")
REGION = os.environ.get("AWS_REGION", "us-east-1")

_dynamodb = boto3.resource("dynamodb", region_name=REGION)
_table = _dynamodb.Table(TABLE_NAME)

# GuardDuty's sample-finding generator attaches every sample to fixed
# placeholder resources. The authoritative marker, the finding's
# service.additionalInfo.sample flag, is not kept by the normalizer, so the
# placeholders are the signal available today. Incidents built from samples
# are labelled rather than hidden: they are the only test data the platform
# has, and hiding them would make the view look emptier than it is while
# pretending the rest is real.
_SAMPLE_INSTANCE = "i-99999999"
_SAMPLE_PREFIX = "GeneratedFinding"


def _is_sample(resource):
    resource = resource or ""
    return resource == _SAMPLE_INSTANCE or resource.startswith(_SAMPLE_PREFIX)


def _scan_all():
    items, kwargs = [], {}
    while True:
        resp = _table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _query_status(status, limit):
    """Incidents with a given status, newest activity first, via the index
    keyed on status and sorted by last_seen."""
    items = []
    kwargs = {
        "IndexName": "status-index",
        "KeyConditionExpression": Key("status").eq(status),
        "ScanIndexForward": False,
    }
    while len(items) < limit:
        resp = _table.query(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return items[:limit]


@router.get("/incidents", dependencies=[Depends(require_auth)])
def list_incidents(
    limit: int = Query(50, ge=1, le=200),
    status: Literal["open", "closed"] | None = Query(
        None, description="filter by lifecycle status"),
):
    """Correlated incidents, most recent activity first.

    With a status filter this queries the status index. Without one it reads
    the whole table, which stays small: the correlator writes one row per
    attack, not one per finding.
    """
    try:
        if status:
            items = _query_status(status, limit)
        else:
            items = sorted(_scan_all(), key=lambda i: i.get("last_seen", ""),
                           reverse=True)[:limit]
        for item in items:
            item["sample"] = _is_sample(item.get("resource"))
        return {
            "count": len(items),
            "multi_stage": sum(1 for i in items if i.get("multi_stage")),
            "incidents": items,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"incidents query failed: {e}")
