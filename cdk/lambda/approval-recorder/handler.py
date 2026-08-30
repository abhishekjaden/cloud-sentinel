"""
Approval recorder.

Invoked by the SOAR state machine when a destructive playbook reaches its
approval gate. The Step Functions task token is written to DynamoDB and never
leaves AWS; the notification that goes out by email says only that an approval
is waiting.

This is what stops mailbox access from being equivalent to authority: resuming
the workflow requires an authenticated call to the API, which looks the token
up server-side.
"""
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME = os.environ.get("APPROVALS_TABLE", "cloudsentinel-approvals")
TOPIC_ARN = os.environ.get("NOTIFY_TOPIC_ARN", "")
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "")
TTL_HOURS = int(os.environ.get("APPROVAL_TTL_HOURS", "24"))

_table = boto3.resource("dynamodb").Table(TABLE_NAME)
_sns = boto3.client("sns")


def handler(event, context):
    token = event.get("taskToken")
    if not token:
        raise ValueError("no taskToken supplied; the state machine must pass one")

    now = datetime.now(timezone.utc)
    approval_id = str(uuid.uuid4())

    item = {
        "approval_id": approval_id,
        "task_token": token,
        "status": "pending",
        "created_at": now.isoformat(),
        "expires_at": int((now + timedelta(hours=TTL_HOURS)).timestamp()),
        "finding_id": event.get("finding_id") or "unknown",
        "playbook": event.get("playbook") or "unknown",
        "resource": json.dumps(event.get("params", {}))[:1024],
        "execution_arn": event.get("execution_arn") or "unknown",
    }
    _table.put_item(Item=item)

    # Deliberately excludes the task token: this message is a prompt to go and
    # authenticate, not a means of approving.
    if TOPIC_ARN:
        _sns.publish(
            TopicArn=TOPIC_ARN,
            Subject="CloudSentinel: remediation awaiting approval",
            Message=(
                f"A {item['playbook']} remediation is waiting for approval.\n\n"
                f"Finding:  {item['finding_id']}\n"
                f"Approval: {approval_id}\n\n"
                f"Sign in to review and decide: {DASHBOARD_URL}\n\n"
                "This notification cannot be used to approve the action."
            ),
        )

    logger.info("APPROVAL_RECORDED %s", json.dumps(
        {k: v for k, v in item.items() if k != "task_token"}))
    return {"approval_id": approval_id, "status": "pending"}
