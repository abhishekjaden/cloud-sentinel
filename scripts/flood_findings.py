#!/usr/bin/env python3
"""
Drive the pipeline at many times its normal volume.

Writes synthetic GuardDuty findings straight into the findings stream, shaped
exactly as EventBridge delivers them, at a rate you choose. The normalizer,
the correlator, the triage function and the dashboard then see them as they
would see a real burst: this is the load test for everything downstream of
EventBridge, which cannot itself be fed — a custom event may not claim an
"aws." source.

The findings are unmistakably synthetic and separable afterwards. They belong
to account 000000000000, carry IDs beginning "flood-", name instances
beginning "i-0f100d", and have low severity, so nothing routes them to
remediation. `--purge` removes every trace of a run: its findings, the
incidents the correlator built from them, and the notes the triage model
wrote about them. Those notes cost a few cents a hundred — the one real cost
of a flood, since the tables are billed per request.

Measure the run with scripts/measure.py --since <the start time it prints>.

Usage:
    python scripts/flood_findings.py --count 10000 --rate 200     # ~10x a busy day, in 50 seconds
    python scripts/flood_findings.py --purge                       # remove every flood finding
"""
import argparse
import base64
import json
import random
import sys
import time
import uuid
from datetime import datetime, timezone

PROFILE = "cs-audit"
REGION = "us-east-1"
STREAM = "cloudsentinel-findings"
FINDINGS_TABLE = "cloudsentinel-findings"
INCIDENTS_TABLE = "cloudsentinel-incidents"
TRIAGE_TABLE = "cloudsentinel-triage"
ACCOUNT = "000000000000"
BATCH = 500                 # PutRecords' maximum

# Low severity throughout: a flood finding must never reach the remediation
# router's threshold, and should not make the triage queue look like an
# attack. Scores are GuardDuty's 0-8.9 scale, rescaled by the normalizer.
TYPES = [
    ("Recon:EC2/PortProbeUnprotectedPort", 2.0, "Unprotected port on EC2 instance {instance} is being probed."),
    ("Recon:EC2/Portscan", 3.0, "EC2 instance {instance} is performing outbound port scans."),
    ("UnauthorizedAccess:EC2/SSHBruteForce", 3.9, "{remote} is performing SSH brute force attacks against {instance}."),
    ("Impact:EC2/PortSweep", 3.5, "EC2 instance {instance} is probing a port on a large number of IP addresses."),
]


def finding(run, n, resources, when=None):
    """One finding as EventBridge hands it to the stream. Its remote address
    is a documentation one, so the enricher never spends a lookup on it."""
    finding_type, severity, title = TYPES[n % len(TYPES)]
    instance = f"i-0f100d{run}{n % resources:07x}"
    remote = f"198.51.100.{n % 254 + 1}"
    created = (when or datetime.now(timezone.utc)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    detail = {
        "schemaVersion": "2.0", "accountId": ACCOUNT, "region": REGION, "partition": "aws",
        "id": f"flood-{run}-{n:06d}", "arn": f"arn:aws:guardduty:{REGION}:{ACCOUNT}:detector/flood/finding/flood-{run}-{n:06d}",
        "type": finding_type, "severity": severity,
        "title": "[flood] " + title.format(instance=instance, remote=remote),
        "description": "Synthetic finding written by scripts/flood_findings.py for a load test.",
        "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": instance, "instanceType": "t3.micro"}},
        "service": {"serviceName": "guardduty", "detectorId": "flood", "count": 1,
                    "action": {"actionType": "NETWORK_CONNECTION", "networkConnectionAction": {
                        "connectionDirection": "INBOUND", "remoteIpDetails": {"ipAddressV4": remote}}},
                    "eventFirstSeen": created, "eventLastSeen": created},
        "createdAt": created, "updatedAt": created,
    }
    return {
        "version": "0", "id": str(uuid.uuid4()), "detail-type": "GuardDuty Finding", "source": "aws.guardduty",
        "account": ACCOUNT, "time": created, "region": REGION, "resources": [], "detail": detail,
    }


def records(events):
    return [{"Data": json.dumps(e).encode("utf-8"), "PartitionKey": e["detail"]["resource"]["instanceDetails"]["instanceId"]}
            for e in events]


def put_all(kinesis, events, rate, log=print):
    """Send every event, BATCH at a time, no faster than `rate` a second,
    resending the records a batch reports as failed. Returns what was sent
    and how many resends it took."""
    sent, resent, started = 0, 0, time.monotonic()
    pending = records(events)
    while pending:
        batch, pending = pending[:BATCH], pending[BATCH:]
        resp = kinesis.put_records(StreamName=STREAM, Records=batch)
        failed = [r for r, result in zip(batch, resp.get("Records", [])) if result.get("ErrorCode")]
        if failed:
            resent += len(failed)
            pending = failed + pending
            # A throttled shard; let it breathe before the resend.
            time.sleep(0.5)  # nosemgrep: python.lang.best-practice.arbitrary-sleep
        sent += len(batch) - len(failed)
        # Hold the rate: how long sending this many should have taken, minus
        # how long it has.
        ahead = sent / rate - (time.monotonic() - started)
        if ahead > 0:
            # This sleep is the rate limiter itself.
            time.sleep(ahead)  # nosemgrep: python.lang.best-practice.arbitrary-sleep
        log(f"  {sent}/{len(events)} sent, {resent} resent, {time.monotonic() - started:.0f}s")
    return sent, resent, time.monotonic() - started


# ----------------------------------------------------------------- purge
def purge(dynamodb, log=print):
    """Remove every flood finding, the incidents built from them and their
    notes. Findings share one partition, so a query finds them all; incidents
    are scanned for the flood account."""
    from boto3.dynamodb.conditions import Key
    findings = dynamodb.Table(FINDINGS_TABLE)
    removed = {"findings": 0, "incidents": 0}
    kwargs = {"KeyConditionExpression": Key("pk").eq(f"guardduty#{ACCOUNT}"), "ProjectionExpression": "pk, sk"}
    with findings.batch_writer() as writer:
        while True:
            resp = findings.query(**kwargs)
            for item in resp.get("Items", []):
                writer.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
                removed["findings"] += 1
            if "LastEvaluatedKey" not in resp:
                break
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

    incidents = dynamodb.Table(INCIDENTS_TABLE)
    flood_ids = []
    kwargs = {"ProjectionExpression": "incident_id, account_id"}
    while True:
        resp = incidents.scan(**kwargs)
        flood_ids.extend(i["incident_id"] for i in resp.get("Items", []) if i.get("account_id") == ACCOUNT)
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    with incidents.batch_writer() as writer:
        for incident_id in flood_ids:
            writer.delete_item(Key={"incident_id": incident_id})
            removed["incidents"] += 1
    # A note exists only for incidents the triage function reached; deleting
    # a key that is not there is not an error, so every flood incident's note
    # slot is cleared without first reading which are filled.
    with dynamodb.Table(TRIAGE_TABLE).batch_writer() as writer:
        for incident_id in flood_ids:
            writer.delete_item(Key={"incident_id": incident_id})
    log(f"removed {removed['findings']} findings and {removed['incidents']} incidents with their notes")
    return removed


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--count", type=int, default=1000, help="findings to send")
    parser.add_argument("--rate", type=float, default=100.0, help="findings per second, at most")
    parser.add_argument("--resources", type=int, default=50, help="distinct instances the findings name")
    parser.add_argument("--purge", action="store_true", help="remove every flood finding, incident and note instead")
    parser.add_argument("--profile", default=PROFILE)
    args = parser.parse_args()

    import boto3
    session = boto3.Session(profile_name=args.profile, region_name=REGION)
    if args.purge:
        purge(session.resource("dynamodb"))
        return

    run = base64.b32encode(uuid.uuid4().bytes)[:4].decode().lower()
    started = datetime.now(timezone.utc)
    events = [finding(run, n, args.resources) for n in range(args.count)]
    print(f"run {run}: {args.count} findings across {args.resources} instances at up to {args.rate:.0f}/s, "
          f"from {started.isoformat(timespec='seconds')}")
    sent, resent, elapsed = put_all(session.client("kinesis"), events, args.rate)
    print(f"sent {sent} in {elapsed:.1f}s ({sent / max(elapsed, 0.001):.0f}/s), {resent} resent after throttling")
    print(f"\nmeasure it once the correlator and triage have run (15 minutes each):\n"
          f"  python scripts/measure.py --since {started.isoformat(timespec='seconds')}\n"
          f"then remove every trace:\n  python scripts/flood_findings.py --purge")
    sys.exit(0 if sent == args.count else 1)


if __name__ == "__main__":
    main()
