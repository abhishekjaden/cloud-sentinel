"""Approval routes — authenticated human decisions on staged remediation.

The Step Functions task token never leaves AWS. Resuming a paused remediation
requires an authenticated call here; this module looks the token up server-side
and records which principal decided, so an approval is attributable to a person
rather than to whoever held a link.
"""
import os
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import require_auth

router = APIRouter()

TABLE_NAME = os.environ.get("APPROVALS_TABLE", "cloudsentinel-approvals")
REGION = os.environ.get("AWS_REGION", "us-east-1")

_table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)
_sfn = boto3.client("stepfunctions", region_name=REGION)


class Decision(BaseModel):
    decision: str = Field(..., pattern="^(approve|reject)$")
    note: str | None = Field(None, max_length=500)


def _public(item: dict) -> dict:
    """Strip the task token before anything reaches a client."""
    return {k: v for k, v in item.items() if k != "task_token"}


@router.get("/approvals", dependencies=[Depends(require_auth)])
def list_approvals(status: str = "pending"):
    """Remediations waiting on a human decision."""
    try:
        resp = _table.query(
            IndexName="status-index",
            KeyConditionExpression=Key("status").eq(status),
            ScanIndexForward=False,
            Limit=50,
        )
        items = [_public(i) for i in resp.get("Items", [])]
        return {"count": len(items), "approvals": items}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"approvals query failed: {e}")


@router.post("/approvals/{approval_id}/decide")
def decide(approval_id: str, body: Decision, claims: dict = Depends(require_auth)):
    """Approve or reject a staged remediation.

    The decision is attributed to the authenticated principal, which is the
    point of routing approval through the API rather than an emailed token.
    """
    resp = _table.get_item(Key={"approval_id": approval_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="approval not found")

    if item.get("status") != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"already {item.get('status')} by {item.get('decided_by', 'unknown')}",
        )

    principal = claims.get("sub") or claims.get("username") or "unknown"
    decided_at = datetime.now(timezone.utc).isoformat()
    token = item["task_token"]

    try:
        if body.decision == "approve":
            _sfn.send_task_success(
                taskToken=token,
                output=f'{{"approved": true, "decided_by": "{principal}"}}',
            )
        else:
            _sfn.send_task_failure(
                taskToken=token,
                error="RemediationRejected",
                cause=f"rejected by {principal}",
            )
    except _sfn.exceptions.TaskTimedOut:
        _table.update_item(
            Key={"approval_id": approval_id},
            UpdateExpression="SET #s = :s",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "expired"},
        )
        raise HTTPException(status_code=410, detail="the remediation timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"could not resume workflow: {e}")

    # Only recorded once the workflow has actually been resumed.
    _table.update_item(
        Key={"approval_id": approval_id},
        UpdateExpression=(
            "SET #s = :s, decided_by = :by, decided_at = :at, decision_note = :n "
            "REMOVE task_token"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "approved" if body.decision == "approve" else "rejected",
            ":by": principal,
            ":at": decided_at,
            ":n": body.note or "",
        },
    )

    return {
        "approval_id": approval_id,
        "status": "approved" if body.decision == "approve" else "rejected",
        "decided_by": principal,
        "decided_at": decided_at,
    }
