"""
CloudSentinel remediation executor.

Invoked by the Step Functions remediation state machine. Performs one
remediation action per invocation, dispatched by `action`. Honors SAFE_MODE:
when set, logs the intended action WITHOUT calling the mutating AWS API, so
the workflow is fully testable without touching real resources.

Expected event shape:
  { "action": "isolate_ec2" | "snapshot_ebs" | "disable_access_key"
              | "block_s3_public" | "enrich",
    "params": { ... action-specific ... } }
"""
import json
import os
import boto3

SAFE_MODE = os.environ.get("SAFE_MODE", "true").lower() == "true"


def _dry(action, detail):
    print(f"[SAFE_MODE] would {action}: {json.dumps(detail)}")
    return {"status": "dry_run", "action": action, "detail": detail}


def isolate_ec2(p):
    """Swap an instance's security groups to a quarantine SG."""
    instance_id = p["instance_id"]
    quarantine_sg = p["quarantine_sg"]
    if SAFE_MODE:
        return _dry("isolate_ec2", {"instance_id": instance_id, "sg": quarantine_sg})
    ec2 = boto3.client("ec2")
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[quarantine_sg])
    return {"status": "done", "action": "isolate_ec2", "instance_id": instance_id}


def snapshot_ebs(p):
    """Snapshot all EBS volumes attached to an instance for forensics."""
    instance_id = p["instance_id"]
    if SAFE_MODE:
        return _dry("snapshot_ebs", {"instance_id": instance_id})
    ec2 = boto3.client("ec2")
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    vols = []
    for r in resp["Reservations"]:
        for inst in r["Instances"]:
            for bdm in inst.get("BlockDeviceMappings", []):
                vid = bdm.get("Ebs", {}).get("VolumeId")
                if vid:
                    snap = ec2.create_snapshot(
                        VolumeId=vid,
                        Description=f"CloudSentinel forensic snapshot {instance_id}",
                    )
                    vols.append(snap["SnapshotId"])
    return {"status": "done", "action": "snapshot_ebs", "snapshots": vols}


def disable_access_key(p):
    """Deactivate a compromised IAM access key."""
    user = p["user_name"]
    key_id = p["access_key_id"]
    if SAFE_MODE:
        return _dry("disable_access_key", {"user": user, "key": key_id})
    iam = boto3.client("iam")
    iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
    return {"status": "done", "action": "disable_access_key", "key": key_id}


def block_s3_public(p):
    """Apply full Block Public Access to a bucket."""
    bucket = p["bucket"]
    if SAFE_MODE:
        return _dry("block_s3_public", {"bucket": bucket})
    s3 = boto3.client("s3")
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    return {"status": "done", "action": "block_s3_public", "bucket": bucket}


def enrich(p):
    """Non-destructive: echo enrichment context for the generic playbook."""
    return {"status": "done", "action": "enrich", "finding": p.get("finding_id")}


ACTIONS = {
    "isolate_ec2": isolate_ec2,
    "snapshot_ebs": snapshot_ebs,
    "disable_access_key": disable_access_key,
    "block_s3_public": block_s3_public,
    "enrich": enrich,
}


def handler(event, context):
    action = event.get("action")
    params = event.get("params", {})
    print(f"remediation action={action} safe_mode={SAFE_MODE} params={json.dumps(params)}")
    fn = ACTIONS.get(action)
    if not fn:
        raise ValueError(f"unknown action: {action}")
    return fn(params)
