"""
CloudSentinel finding normalizer.

Consumes raw security findings from Kinesis, maps each source's native
shape into a single common schema, and persists to DynamoDB (queryable
store; the dashboard's primary data source).

DynamoDB item keys:
  pk = "<source>#<account_id>"
  sk = "<created_at>#<finding_id>"
  severity_bucket = CRITICAL|HIGH|MEDIUM|LOW|INFO  (for severity GSI)
  indicators = {ips, domains} the finding names (GuardDuty only), kept for
               threat-intelligence enrichment; absent when it names none
  event_time, queued_at, stored_at = when EventBridge emitted the event, when it
               reached the stream, and when this function wrote it: the three
               stamps the latency measurement (scripts/measure.py) reads

created_at is ISO 8601 for every source. sk sorts by time only because of that,
so a source that sends another format is converted here, not downstream.

A record that fails is caught so the rest of its batch still goes through, and
its sequence number is returned to Lambda, which rewinds the shard to it and
delivers it again. Records after it in the batch are delivered again too —
Kinesis retries from the lowest reported sequence number — so persisting has to
be idempotent, and is: the key is derived from the finding, so a second write of
the same record overwrites the first.

Each batch reports how many records it received and how many it had to hand back
as CloudWatch metrics. Neither is a lost finding: a record is lost only once
Lambda has retried it to exhaustion, at which point Lambda reports the batch to
the failure queue, which is what the findings-stored alarm watches (docs/slos.md).
"""
import base64
import ipaddress
import json
import logging
import os
import time
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_TABLE_NAME = os.environ.get("FINDINGS_TABLE", "cloudsentinel-findings")
_table = boto3.resource("dynamodb").Table(_TABLE_NAME)

# Pinned on both sides: the observability stack's alarms read these names.
_METRIC_NAMESPACE = "CloudSentinel"
_COMPONENT = "normalizer"


def _severity_bucket(score):
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "INFO"


def _severity_to_score(source, raw):
    if raw is None:
        return 0
    if source == "guardduty":
        try:
            return round(float(raw) / 8.9 * 100)
        except (TypeError, ValueError):
            return 0
    if source == "securityhub":
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0
    return 0


# Inspector's severity words, used only when a finding carries no
# inspectorScore. Each lands in the middle of the matching bucket.
_INSPECTOR_LABEL_SCORE = {
    "CRITICAL": 95, "HIGH": 80, "MEDIUM": 55, "LOW": 20,
    "INFORMATIONAL": 0, "UNTRIAGED": 0,
}


def _inspector_score(detail):
    """Severity for an Inspector finding, on the same 0–100 scale as the others.

    Inspector sends severity as a word ("HIGH") alongside a 0–10 inspectorScore.
    The word used to be passed to int(), which failed, so every Inspector
    finding was stored as severity 0 and bucketed INFO. The score scaled by ten
    falls into the same bands the buckets use — CVSS 7.0 is HIGH either way — so
    it is preferred, with the word as the fallback.
    """
    try:
        return max(0, min(100, round(float(detail.get("inspectorScore")) * 10)))
    except (TypeError, ValueError, OverflowError):
        return _INSPECTOR_LABEL_SCORE.get(str(detail.get("severity") or "").upper(), 0)


# Inspector timestamps look like "Wed Sep 04 16:59:44.356 UTC 2024". The zone is
# matched literally: %Z would also accept the host's local zone name, and a
# non-UTC time read as UTC is wrong by the offset without any error.
_INSPECTOR_TIME_FORMATS = ("%a %b %d %H:%M:%S.%f UTC %Y", "%a %b %d %H:%M:%S UTC %Y")


def _inspector_time(value, fallback):
    """An Inspector timestamp as ISO 8601 UTC, or the fallback if unreadable.

    Stored as sent, "Wed Sep 04 ..." sorts above every ISO timestamp, which
    pinned Inspector findings to the top of the newest-first findings list
    whatever their age, and the correlator could not parse it at all.
    """
    if not value:
        return fallback
    text = str(value).strip()
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
        return text  # already ISO 8601; stored as sent, like the other sources
    except ValueError:
        pass
    for fmt in _INSPECTOR_TIME_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        return parsed.strftime("%Y-%m-%dT%H:%M:%S.") + f"{parsed.microsecond // 1000:03d}Z"
    return fallback


# How many of each kind of indicator one finding keeps. A port probe can list
# dozens of remote addresses; the first few are what an analyst will look up.
MAX_INDICATORS = 10


def _public_ip(value):
    """The address if it is a public one, else None: private, loopback and
    link-local addresses belong to the VPC, not to an attacker, and would only
    spend threat-intelligence lookups on nothing."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    # is_global is a property of the address, not a method.
    public = address.is_global  # nosemgrep: python.lang.maintainability.is-function-without-parentheses
    return str(address) if public else None


def _indicators(detail):
    """The remote addresses and domains a GuardDuty finding names, from the
    action block under service. GuardDuty puts the remote end of a connection,
    probe, API call or login attempt under remoteIpDetails and a DNS request's
    name under dnsRequestAction; nothing else in a finding is an indicator a
    threat-intelligence feed can be asked about."""
    action = ((detail.get("service") or {}).get("action") or {})
    remote = []
    for key in ("networkConnectionAction", "awsApiCallAction", "kubernetesApiCallAction",
                "rdsLoginAttemptAction"):
        remote.append(((action.get(key) or {}).get("remoteIpDetails") or {}).get("ipAddressV4"))
    for probe in (action.get("portProbeAction") or {}).get("portProbeDetails") or []:
        remote.append(((probe or {}).get("remoteIpDetails") or {}).get("ipAddressV4"))
    ips, domains = [], []
    for value in remote:
        public = _public_ip(value) if value else None
        if public and public not in ips:
            ips.append(public)
    domain = (action.get("dnsRequestAction") or {}).get("domain")
    if isinstance(domain, str) and domain.strip():
        domains.append(domain.strip().rstrip(".").lower()[:253])
    found = {}
    if ips:
        found["ips"] = ips[:MAX_INDICATORS]
    if domains:
        found["domains"] = domains[:MAX_INDICATORS]
    return found or None


def _normalize(event):
    src = event.get("source", "")
    detail = event.get("detail", {})
    if src == "aws.guardduty":
        return {
            "finding_id": detail.get("id"),
            "source": "guardduty",
            "account_id": event.get("account"),
            "region": event.get("region"),
            "severity": _severity_to_score("guardduty", detail.get("severity")),
            "raw_severity_label": str(detail.get("severity")),
            "title": detail.get("title"),
            "finding_type": detail.get("type"),
            "resource": json.dumps(detail.get("resource", {}))[:1024],
            "created_at": detail.get("createdAt") or event.get("time"),
            # Kept for threat-intelligence enrichment; absent when the finding
            # names no public address or domain.
            "indicators": _indicators(detail),
        }
    if src == "aws.securityhub":
        findings = detail.get("findings", [{}])
        f = findings[0] if findings else {}
        sev = (f.get("Severity") or {}).get("Normalized")
        return {
            "finding_id": f.get("Id"),
            "source": "securityhub",
            "account_id": f.get("AwsAccountId") or event.get("account"),
            "region": event.get("region"),
            "severity": _severity_to_score("securityhub", sev),
            "raw_severity_label": (f.get("Severity") or {}).get("Label"),
            "title": f.get("Title"),
            "finding_type": ",".join(f.get("Types", []))[:256],
            "resource": json.dumps(f.get("Resources", []))[:1024],
            "created_at": f.get("CreatedAt") or event.get("time"),
        }
    if src == "aws.inspector2":
        return {
            "finding_id": detail.get("findingArn"),
            "source": "inspector",
            "account_id": event.get("account"),
            "region": event.get("region"),
            "severity": _inspector_score(detail),
            "raw_severity_label": detail.get("severity"),
            "title": detail.get("title"),
            "finding_type": detail.get("type"),
            "resource": json.dumps(detail.get("resources", []))[:1024],
            "created_at": _inspector_time(detail.get("firstObservedAt"), event.get("time")),
        }
    # Anything else is stored under "unknown" rather than under its own source
    # name, with the name it came with kept beside it. The findings routes
    # query one partition per source and count the same way, so a source they
    # have never heard of would be neither listed nor counted — invisible in
    # the one place it most needs to be seen. This keeps the set of sources
    # closed at four, which is what makes those queries cover the table.
    return {
        "finding_id": event.get("id"),
        "source": "unknown",
        "raw_source": src or None,
        "account_id": event.get("account"),
        "region": event.get("region"),
        "severity": 0,
        "raw_severity_label": None,
        "title": detail.get("title") or "unrecognized finding source",
        "finding_type": None,
        "resource": None,
        "created_at": event.get("time"),
    }


def _iso(epoch):
    """An epoch timestamp as ISO 8601 UTC, or None if it is not a number."""
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat(timespec="milliseconds")
    except (TypeError, ValueError, OverflowError):
        return None


def _persist(finding, event_time=None, queued_at=None):
    """Write a normalized finding to DynamoDB, stamped with when the event
    was emitted, when it reached the stream and when it was written."""
    fid = finding.get("finding_id") or "unknown"
    created = finding.get("created_at") or "unknown"
    item = dict(finding)
    item["pk"] = f"{finding.get('source', 'unknown')}#{finding.get('account_id', 'unknown')}"
    item["sk"] = f"{created}#{fid}"
    item["severity_bucket"] = _severity_bucket(finding.get("severity", 0))
    item["event_time"] = event_time
    item["queued_at"] = _iso(queued_at)
    item["stored_at"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    # DynamoDB rejects empty strings in some contexts; drop null/empty values
    item = {k: v for k, v in item.items() if v is not None and v != ""}
    _table.put_item(Item=item)


def _metrics_line(**counts):
    """One record in CloudWatch Embedded Metric Format.

    EMF is a log line that CloudWatch turns into metrics as it arrives, so it
    needs no SDK and no extra API call. CloudWatch drops a malformed line
    without an error anywhere, which would silence the alarm that watches it,
    so the tests pin this shape.
    """
    return json.dumps({
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": _METRIC_NAMESPACE,
                "Dimensions": [["Component"]],
                "Metrics": [{"Name": name, "Unit": "Count"} for name in counts],
            }],
        },
        "Component": _COMPONENT,
        **counts,
    })


def handler(event, context):
    records = event.get("Records", [])
    failed = 0
    retry = []
    for record in records:
        # Read before the work, so a record that fails can still be named.
        sequence_number = (record.get("kinesis") or {}).get("sequenceNumber")
        try:
            payload = base64.b64decode(record["kinesis"]["data"])
            raw_event = json.loads(payload)
            normalized = _normalize(raw_event)
            _persist(normalized, event_time=raw_event.get("time"),
                     queued_at=record["kinesis"].get("approximateArrivalTimestamp"))
            logger.info("NORMALIZED_FINDING %s", json.dumps(normalized))
        except Exception as exc:  # noqa: BLE001
            failed += 1
            logger.error("Failed to process record %s: %s: %s",
                         sequence_number or "unidentified", type(exc).__name__, exc)
            if sequence_number:
                retry.append({"itemIdentifier": sequence_number})
    # Printed rather than logged: Lambda's log handler prefixes each line with a
    # level and request ID, and CloudWatch reads EMF only from a line that is
    # JSON from its first character.
    print(_metrics_line(RecordsReceived=len(records), RecordsFailed=failed))
    # Nothing else may go in this response. Lambda reads it as a partial batch
    # report, and treats a response it cannot read as the whole batch failing —
    # so an extra key would turn one bad record into a hundred retried ones.
    return {"batchItemFailures": retry}
