"""Remediation routes — recent SOAR executions from Step Functions."""
import os
from fastapi import APIRouter, HTTPException, Query
import boto3

router = APIRouter()

REGION = os.environ.get("AWS_REGION", "us-east-1")
STATE_MACHINE_ARN = os.environ.get(
    "STATE_MACHINE_ARN",
    "arn:aws:states:us-east-1:118821712739:stateMachine:cloudsentinel-remediation",
)

_sfn = boto3.client("stepfunctions", region_name=REGION)


@router.get("/remediations")
def list_remediations(limit: int = Query(20, ge=1, le=100)):
    """Recent remediation executions with status (RUNNING = awaiting approval)."""
    try:
        resp = _sfn.list_executions(
            stateMachineArn=STATE_MACHINE_ARN,
            maxResults=limit,
        )
        execs = [
            {
                "name": e["name"],
                "status": e["status"],
                "started": e["startDate"].isoformat(),
                "stopped": e.get("stopDate").isoformat() if e.get("stopDate") else None,
            }
            for e in resp.get("executions", [])
        ]
        # Summary counts for the dashboard.
        summary = {}
        for e in execs:
            summary[e["status"]] = summary.get(e["status"], 0) + 1
        return {"count": len(execs), "summary": summary, "executions": execs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"remediations query failed: {e}")
