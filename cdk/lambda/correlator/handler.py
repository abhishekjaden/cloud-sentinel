"""
Incident correlation.

A finding describes one observation. An incident describes an attack. Port
probing, then SSH brute force, then a command-and-control callout against the
same instance is one intrusion attempt, not three alerts — and presenting it as
three is how analysts end up triaging the same event repeatedly.

This groups threat findings that share a resource and fall within a time window,
and records each group as an incident with its attack stages ordered.

Scope: GuardDuty only. Security Hub findings describe configuration posture — a
bucket that permits public access, a password policy that is too weak — and
Inspector findings describe vulnerable packages. Both are weaknesses, not
events: correlating them by resource would group every CVE in an image, all
observed by one scan in the same second, into an "attack" with no stages.
Inspector was listed here originally, but its timestamps could not be parsed,
so it was excluded in practice; it is now excluded by design.

Idempotency: the correlator runs on a schedule over a lookback window, so it
sees the same findings on every run. An incident's identity is therefore
derived from what it is — the account, the resource, and when the attack began
— and each run updates the existing record rather than adding another. The
incident's status belongs to the analyst once it exists and is never
overwritten by a later run.
"""
import hashlib
import json
import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger()
logger.setLevel(logging.INFO)

FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE", "cloudsentinel-findings")
INCIDENTS_TABLE = os.environ.get("INCIDENTS_TABLE", "cloudsentinel-incidents")
WINDOW_MINUTES = int(os.environ.get("CORRELATION_WINDOW_MINUTES", "30"))
LOOKBACK_HOURS = int(os.environ.get("CORRELATION_LOOKBACK_HOURS", "168"))

# Sources whose findings describe events rather than a standing weakness.
THREAT_SOURCES = ("guardduty",)

_ddb = boto3.resource("dynamodb")
_findings = _ddb.Table(FINDINGS_TABLE)
_incidents = _ddb.Table(INCIDENTS_TABLE)

# GuardDuty finding types are `ThreatPurpose:ResourceType/ThreatFamily`. The
# threat purpose maps onto a rough kill-chain stage.
STAGE_BY_PURPOSE = {
    "Recon": "reconnaissance",
    "UnauthorizedAccess": "initial-access",
    "CredentialAccess": "credential-access",
    "Discovery": "discovery",
    "Execution": "execution",
    "Persistence": "persistence",
    "PrivilegeEscalation": "privilege-escalation",
    "DefenseEvasion": "defense-evasion",
    "Backdoor": "command-and-control",
    "Trojan": "command-and-control",
    "CryptoCurrency": "impact",
    "Impact": "impact",
    "Exfiltration": "exfiltration",
    "Policy": "policy-violation",
    "PenTest": "reconnaissance",
    "Stealth": "defense-evasion",
}

STAGE_ORDER = [
    "reconnaissance", "initial-access", "credential-access", "discovery",
    "execution", "persistence", "privilege-escalation", "defense-evasion",
    "command-and-control", "exfiltration", "impact", "policy-violation",
    "unknown",
]


def _stage(finding_type):
    """Map a finding type onto a kill-chain stage."""
    if not finding_type:
        return "unknown"
    purpose = finding_type.split(":", 1)[0]
    return STAGE_BY_PURPOSE.get(purpose, "unknown")


def _resource_id(item):
    """Extract the identifier of the resource a finding concerns.

    The normalizer stores the raw resource block as a JSON string truncated to
    1024 characters, and each source shapes it differently, so the identifier is
    pulled out by pattern rather than by parsing.
    """
    raw = item.get("resource") or ""
    for pattern in (
        r'"instanceId":\s*"([^"]+)"',
        r'"accessKeyId":\s*"([^"]+)"',
        r'"bucketName":\s*"([^"]+)"',
        r'"functionName":\s*"([^"]+)"',
        r'"instance/([^"/]+)"',
    ):
        m = re.search(pattern, raw)
        if m:
            return m.group(1)
    return None


def _parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _recent_threat_findings(cutoff):
    """Every threat finding written since the cutoff, across all threat sources."""
    out = []
    for source in THREAT_SOURCES:
        kwargs = {
            "KeyConditionExpression": Key("pk").eq(
                f"{source}#{os.environ.get('ACCOUNT_ID', '')}")
        }
        # The partition key embeds the account, which is not known ahead of time
        # in every deployment, so fall back to a filtered scan when it is absent.
        if not os.environ.get("ACCOUNT_ID"):
            kwargs = {
                "FilterExpression": "begins_with(pk, :p)",
                "ExpressionAttributeValues": {":p": f"{source}#"},
            }
            paginate = _findings.scan
        else:
            paginate = _findings.query

        resp = paginate(**kwargs)
        out.extend(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            resp = paginate(**kwargs)
            out.extend(resp.get("Items", []))

    fresh = []
    for item in out:
        ts = _parse_ts(item.get("created_at"))
        if ts and ts >= cutoff:
            fresh.append((ts, item))
    return fresh


def _cluster(findings):
    """Group findings by resource, then split each group on time gaps.

    A gap longer than the window starts a new incident: the same instance
    attacked in June and again in August is two intrusions, not one long one.
    """
    by_resource = defaultdict(list)
    for ts, item in findings:
        resource = _resource_id(item)
        if not resource:
            continue
        key = (item.get("account_id", "unknown"), resource)
        by_resource[key].append((ts, item))

    window = timedelta(minutes=WINDOW_MINUTES)
    clusters = []
    for (account, resource), entries in by_resource.items():
        entries.sort(key=lambda e: e[0])
        current = [entries[0]]
        for ts, item in entries[1:]:
            if ts - current[-1][0] <= window:
                current.append((ts, item))
            else:
                clusters.append((account, resource, current))
                current = [(ts, item)]
        clusters.append((account, resource, current))
    return clusters


def _incident_id(account, resource, first_seen):
    """Stable identity for an incident: the same attack always maps to the same ID.

    A random ID made every scheduled run insert a fresh copy of every incident
    it had already recorded — four incidents became several hundred rows within
    two days. Keying on the start of the attack means a cluster that grows as
    new findings arrive keeps its identity, because new findings extend the end
    of the window, not the beginning.
    """
    key = f"{account}|{resource}|{first_seen.isoformat()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def _build_incident(account, resource, entries):
    findings = [item for _, item in entries]
    stages = {_stage(f.get("finding_type")) for f in findings}
    ordered = [s for s in STAGE_ORDER if s in stages]

    severities = [int(f.get("severity", 0)) for f in findings]
    first, last = entries[0][0], entries[-1][0]

    return {
        "incident_id": _incident_id(account, resource, first),
        "account_id": account,
        "resource": resource,
        "first_seen": first.isoformat(),
        "last_seen": last.isoformat(),
        "duration_seconds": int((last - first).total_seconds()),
        "finding_count": len(findings),
        "max_severity": max(severities) if severities else 0,
        "attack_stages": ordered,
        "stage_count": len(ordered),
        # A single-stage incident is one observation; several stages against one
        # resource is a sequence, which is what warrants an analyst's attention.
        "multi_stage": len(ordered) > 1,
        "finding_types": sorted({f.get("finding_type", "?") for f in findings}),
        "finding_ids": [f.get("finding_id") for f in findings][:50],
        "sources": sorted({f.get("source", "?") for f in findings}),
        "correlated_at": datetime.now(timezone.utc).isoformat(),
    }


# Attributes the analyst owns once the incident exists. A scheduled run sets
# them only when the record is first created, so closing an incident sticks.
_SET_ONCE = {"status": "open"}


def _upsert(incident):
    """Write an incident, updating it in place if this attack was seen before.

    A put_item would replace the whole record, resetting a closed incident to
    open every fifteen minutes. update_item refreshes the computed fields —
    the cluster may have grown — while if_not_exists leaves analyst-owned
    attributes as the analyst set them.
    """
    now = datetime.now(timezone.utc).isoformat()
    set_once = {**_SET_ONCE, "created_at": now}
    # Excluding set-once names here as well keeps a later edit that adds one of
    # them to _build_incident from producing two SETs on the same attribute,
    # which DynamoDB rejects outright.
    computed = {k: v for k, v in incident.items()
                if k != "incident_id" and k not in set_once}

    names, values, clauses = {}, {}, []
    # Every attribute name goes through a placeholder: several of these
    # (status, resource) collide with DynamoDB reserved words.
    for i, (name, value) in enumerate(computed.items()):
        names[f"#c{i}"] = name
        values[f":c{i}"] = value
        clauses.append(f"#c{i} = :c{i}")
    for i, (name, initial) in enumerate(set_once.items()):
        names[f"#o{i}"] = name
        values[f":o{i}"] = initial
        clauses.append(f"#o{i} = if_not_exists(#o{i}, :o{i})")

    _incidents.update_item(
        Key={"incident_id": incident["incident_id"]},
        UpdateExpression="SET " + ", ".join(clauses),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def handler(event, context):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
    findings = _recent_threat_findings(cutoff)
    logger.info("CORRELATION_INPUT %s",
                json.dumps({"threat_findings": len(findings),
                            "lookback_hours": LOOKBACK_HOURS}))

    clusters = _cluster(findings)
    written = 0
    multi_stage = 0
    for account, resource, entries in clusters:
        incident = _build_incident(account, resource, entries)
        _upsert(incident)
        written += 1
        if incident["multi_stage"]:
            multi_stage += 1
            logger.info("MULTI_STAGE_INCIDENT %s", json.dumps({
                "resource": incident["resource"],
                "stages": incident["attack_stages"],
                "findings": incident["finding_count"],
                "max_severity": incident["max_severity"],
            }))

    summary = {"incidents": written, "multi_stage": multi_stage,
               "findings_correlated": len(findings)}
    logger.info("CORRELATION_COMPLETE %s", json.dumps(summary))
    return summary
