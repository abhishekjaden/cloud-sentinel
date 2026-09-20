"""
CloudSentinel finding normalizer.

Consumes raw security findings from Kinesis, maps each source's native
shape into a single common schema, and persists to DynamoDB (queryable
store; the dashboard's primary data source).

DynamoDB item keys:
  pk = "<source>#<account_id>"
  sk = "<created_at>#<finding_id>"
  severity_bucket = CRITICAL|HIGH|MEDIUM|LOW|INFO  (for severity GSI)

created_at is ISO 8601 for every source. sk sorts by time only because of that,
so a source that sends another format is converted here, not downstream.

Each batch also reports how many records it received and how many failed, as
CloudWatch metrics. A record that fails is caught so the rest of its batch still
goes through, which also keeps the failure out of Lambda's own Errors metric:
the invocation succeeds either way. These counts are what make a lost finding
visible, and the findings-stored alarm watches them (docs/slos.md).
"""
import base64
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
    return {
        "finding_id": event.get("id"),
        "source": src or "unknown",
        "account_id": event.get("account"),
        "region": event.get("region"),
        "severity": 0,
        "raw_severity_label": None,
        "title": detail.get("title") or "unrecognized finding source",
        "finding_type": None,
        "resource": None,
        "created_at": event.get("time"),
    }


def _persist(finding):
    """Write a normalized finding to DynamoDB."""
    fid = finding.get("finding_id") or "unknown"
    created = finding.get("created_at") or "unknown"
    item = dict(finding)
    item["pk"] = f"{finding.get('source', 'unknown')}#{finding.get('account_id', 'unknown')}"
    item["sk"] = f"{created}#{fid}"
    item["severity_bucket"] = _severity_bucket(finding.get("severity", 0))
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
    processed = 0
    for record in records:
        try:
            payload = base64.b64decode(record["kinesis"]["data"])
            raw_event = json.loads(payload)
            normalized = _normalize(raw_event)
            _persist(normalized)
            logger.info("NORMALIZED_FINDING %s", json.dumps(normalized))
            processed += 1
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to process record: %s", exc)
    # Printed rather than logged: Lambda's log handler prefixes each line with a
    # level and request ID, and CloudWatch reads EMF only from a line that is
    # JSON from its first character.
    print(_metrics_line(RecordsReceived=len(records), RecordsFailed=len(records) - processed))
    return {"processed": processed}
