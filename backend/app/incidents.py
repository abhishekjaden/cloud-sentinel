"""
Incident routes — correlated attacks, read from the table the correlator writes.

A finding is one observation; an incident is the attack that several
observations describe. This is where an analyst starts: fewer items than the
findings list, each with its attack stages already in kill-chain order.

Each incident carries its advisory triage note, if the triage function has
written one, and the threat-intelligence verdict on each address and domain it
names, if the enricher has looked it up. Both are read-only here and optional:
when they cannot be read, incidents are still served without them.
"""
import logging
import os
from typing import Literal

import boto3
from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import require_auth

router = APIRouter()

TABLE_NAME = os.environ.get("INCIDENTS_TABLE", "cloudsentinel-incidents")
TRIAGE_TABLE = os.environ.get("TRIAGE_TABLE", "cloudsentinel-triage")
INTEL_TABLE = os.environ.get("INTEL_TABLE", "cloudsentinel-intel")
REGION = os.environ.get("AWS_REGION", "us-east-1")

logger = logging.getLogger(__name__)

_dynamodb = boto3.resource("dynamodb", region_name=REGION)
_table = _dynamodb.Table(TABLE_NAME)

# GuardDuty's sample-finding generator attaches every sample to fixed
# placeholder resources. The authoritative marker, the finding's
# service.additionalInfo.sample flag, is not kept by the normalizer, so the
# placeholders are the signal available today. Incidents built from samples
# are labelled rather than hidden: they are the only test data the platform
# has, and hiding them would make the view look emptier than it is while
# pretending the rest is real.
_SAMPLE_INSTANCE = "i-99999999"
_SAMPLE_PREFIX = "GeneratedFinding"


def _is_sample(resource):
    resource = resource or ""
    return resource == _SAMPLE_INSTANCE or resource.startswith(_SAMPLE_PREFIX)


def _scan_all():
    items, kwargs = [], {}
    while True:
        resp = _table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _query_status(status, limit):
    """Incidents with a given status, newest activity first, via the index
    keyed on status and sorted by last_seen."""
    items = []
    kwargs = {
        "IndexName": "status-index",
        "KeyConditionExpression": Key("status").eq(status),
        "ScanIndexForward": False,
    }
    while len(items) < limit:
        resp = _table.query(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return items[:limit]


# What the dashboard shows of a note. Token counts and the fingerprint stay
# server-side; a note that failed validation exposes only that it failed.
_NOTE_FIELDS = ("status", "summary", "assessed_severity", "confidence",
                "likely_test_data", "injection_suspected", "reasons",
                "next_steps", "model_id", "triaged_at")


def _public(note):
    if not note:
        return None
    if note.get("status") != "complete":
        return {"status": note.get("status"), "triaged_at": note.get("triaged_at")}
    return {k: note.get(k) for k in _NOTE_FIELDS}


def _batch_get(table, key_name, keys):
    """Rows of one table by key. BatchGetItem takes 100 keys a call and may
    hand some back unprocessed; those are retried a few times, then left out
    rather than delaying the response."""
    rows = {}
    for start in range(0, len(keys), 100):
        request = {table: {"Keys": [{key_name: k} for k in keys[start:start + 100]]}}
        for _ in range(3):
            resp = _dynamodb.batch_get_item(RequestItems=request)
            for row in resp.get("Responses", {}).get(table, []):
                rows[row[key_name]] = row
            request = resp.get("UnprocessedKeys") or {}
            if not request.get(table, {}).get("Keys"):
                break
    return rows


def _triage_notes(incident_ids):
    """Notes for the given incidents, keyed by incident ID."""
    return _batch_get(TRIAGE_TABLE, "incident_id", list(incident_ids))


def indicator_keys(incident):
    """The incident's indicators as the intel table keys them."""
    found = incident.get("indicators") or {}
    return ([f"ip:{v}" for v in found.get("ips") or []]
            + [f"domain:{v}" for v in found.get("domains") or []])


# What the dashboard shows of a verdict: everything the enricher kept except
# the row's housekeeping. The row holds counts and scores by design.
_INTEL_FIELDS = ("kind", "value", "verdict", "abuseipdb", "otx", "providers_asked",
                 "providers_failed", "looked_up_at")


def _public_intel(row):
    return {k: row.get(k) for k in _INTEL_FIELDS if k in row}


def intel_for(incidents):
    """Verdicts for every indicator the incidents name, keyed by the
    indicator's value, in one pass: an attacker's address appears on many
    incidents and is read once."""
    keys = []
    for incident in incidents:
        keys.extend(k for k in indicator_keys(incident) if k not in keys)
    rows = _batch_get(INTEL_TABLE, "indicator", keys) if keys else {}
    return {row["value"]: _public_intel(row) for row in rows.values() if row.get("value")}


def _attach_intel(items):
    try:
        verdicts = intel_for(items)
    except Exception:  # noqa: BLE001 — a missing verdict must not cost the incidents
        logger.exception("threat-intel verdicts could not be read")
        verdicts = {}
    for item in items:
        found = item.get("indicators") or {}
        values = list(found.get("ips") or []) + list(found.get("domains") or [])
        item["intel"] = {v: verdicts[v] for v in values if v in verdicts}


def _attach_triage(items):
    try:
        notes = _triage_notes([i["incident_id"] for i in items])
    except Exception:  # noqa: BLE001 — a missing note must not cost the incidents
        logger.exception("triage notes could not be read")
        notes = {}
    for item in items:
        item["triage"] = _public(notes.get(item["incident_id"]))


@router.get("/incidents", dependencies=[Depends(require_auth)])
def list_incidents(
    limit: int = Query(50, ge=1, le=200),
    status: Literal["open", "closed"] | None = Query(
        None, description="filter by lifecycle status"),
):
    """Correlated incidents, most recent activity first.

    With a status filter this queries the status index. Without one it reads
    the whole table, which stays small: the correlator writes one row per
    attack, not one per finding.
    """
    try:
        if status:
            items = _query_status(status, limit)
        else:
            items = sorted(_scan_all(), key=lambda i: i.get("last_seen", ""),
                           reverse=True)[:limit]
        for item in items:
            item["sample"] = _is_sample(item.get("resource"))
        _attach_triage(items)
        _attach_intel(items)
        return {
            "count": len(items),
            "multi_stage": sum(1 for i in items if i.get("multi_stage")),
            "incidents": items,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"incidents query failed: {e}")
