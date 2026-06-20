"""
CloudSentinel finding normalizer.

Consumes raw security findings from Kinesis (delivered as base64 records),
maps each source's native shape to a single common schema, and emits the
normalized finding to CloudWatch Logs (interim sink; DynamoDB/OpenSearch
added Day 5).

Common schema:
  finding_id, source, account_id, region, severity (0-100 normalized),
  title, resource, finding_type, created_at, raw_severity_label
"""
import base64
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _severity_to_score(source, raw):
    if raw is None:
        return 0
    if source == "guardduty":
        try:
            return round(float(raw) / 8.9 * 100)
        except (TypeError, ValueError):
            return 0
    if source in ("securityhub", "inspector"):
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0
    return 0


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
            "severity": _severity_to_score("inspector", detail.get("severity")),
            "raw_severity_label": detail.get("severity"),
            "title": detail.get("title"),
            "finding_type": detail.get("type"),
            "resource": json.dumps(detail.get("resources", []))[:1024],
            "created_at": detail.get("firstObservedAt") or event.get("time"),
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


def handler(event, context):
    processed = 0
    for record in event.get("Records", []):
        try:
            payload = base64.b64decode(record["kinesis"]["data"])
            raw_event = json.loads(payload)
            normalized = _normalize(raw_event)
            logger.info("NORMALIZED_FINDING %s", json.dumps(normalized))
            processed += 1
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to process record: %s", exc)
    return {"processed": processed}
