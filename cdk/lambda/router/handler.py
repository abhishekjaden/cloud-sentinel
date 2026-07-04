"""
CloudSentinel remediation router.

Triggered by EventBridge on high-severity GuardDuty / Security Hub findings.
Maps the finding to a remediation playbook, extracts the parameters that
playbook needs, and starts an execution of the remediation state machine.

Finding type -> playbook mapping (prefix match on GuardDuty finding type):
  UnauthorizedAccess:EC2 / Backdoor:EC2 / Trojan:EC2  -> ec2_compromise
  UnauthorizedAccess:IAMUser / CredentialAccess       -> iam_credential
  Policy:S3 / Discovery:S3 / Exfiltration:S3          -> s3_public
  (anything else high-severity)                        -> generic
"""
import json
import os
import boto3

sfn = boto3.client("stepfunctions")
STATE_MACHINE_ARN = os.environ["STATE_MACHINE_ARN"]
QUARANTINE_SG = os.environ.get("QUARANTINE_SG", "sg-quarantine-placeholder")


def _classify(finding_type):
    t = finding_type or ""
    if t.startswith(("UnauthorizedAccess:EC2", "Backdoor:EC2", "Trojan:EC2")):
        return "ec2_compromise"
    if t.startswith(("UnauthorizedAccess:IAMUser", "CredentialAccess")):
        return "iam_credential"
    if t.startswith(("Policy:S3", "Discovery:S3", "Exfiltration:S3")):
        return "s3_public"
    return "generic"


def _extract_params(playbook, detail):
    """Pull playbook-specific params out of the GuardDuty finding detail."""
    resource = detail.get("resource", {})
    if playbook == "ec2_compromise":
        instance = resource.get("instanceDetails", {}).get("instanceId", "unknown")
        return {"instance_id": instance, "quarantine_sg": QUARANTINE_SG}
    if playbook == "iam_credential":
        access_key = resource.get("accessKeyDetails", {})
        return {
            "user_name": access_key.get("userName", "unknown"),
            "access_key_id": access_key.get("accessKeyId", "unknown"),
        }
    if playbook == "s3_public":
        buckets = resource.get("s3BucketDetails", [{}])
        name = buckets[0].get("name", "unknown") if buckets else "unknown"
        return {"bucket": name}
    return {}


def handler(event, context):
    detail = event.get("detail", {})
    finding_id = detail.get("id", detail.get("Id", "unknown"))
    finding_type = detail.get("type", detail.get("Types", [""])[0]
                              if isinstance(detail.get("Types"), list) else "")
    playbook = _classify(finding_type)
    params = _extract_params(playbook, detail)
    params["finding_id"] = finding_id

    sm_input = {"finding_id": finding_id, "playbook": playbook, "params": params}
    print(f"routing finding {finding_id} type={finding_type} -> playbook={playbook}")

    resp = sfn.start_execution(
        stateMachineArn=STATE_MACHINE_ARN,
        input=json.dumps(sm_input),
    )
    return {"executionArn": resp["executionArn"], "playbook": playbook}
