"""
Incident report: one incident as a PDF an analyst can hand to someone else.

The report is assembled from what the platform recorded — the correlator's
incident, the findings it was built from, the advisory triage note, and any
remediation that reached the approval gate — and rendered with reportlab. It
adds an ATT&CK placement derived from the finding types, and nothing else: no
text in it is generated here, so the report claims only what the record holds.

Two things about untrusted text. Finding titles and resource blocks are
written by the source, which on a compromised instance means by the attacker,
and reportlab paragraphs interpret inline markup, so every value is escaped
before it becomes part of a paragraph; a title containing <b> prints as the
five characters. And the triage note is model output over that same text, so
it is printed under a heading that says so, after the record rather than in
place of it.

The standard PDF fonts cover Latin text; characters from other scripts print
as boxes rather than failing the report.
"""
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from html import escape
from io import BytesIO

import boto3
from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer, Table,
    TableStyle,
)

from app import attack
from app.auth import require_auth
from app.incidents import _is_sample, _public, _triage_notes, indicator_keys, intel_for

router = APIRouter()
logger = logging.getLogger(__name__)

REGION = os.environ.get("AWS_REGION", "us-east-1")
INCIDENTS_TABLE = os.environ.get("INCIDENTS_TABLE", "cloudsentinel-incidents")
FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE", "cloudsentinel-findings")
APPROVALS_TABLE = os.environ.get("APPROVALS_TABLE", "cloudsentinel-approvals")

_dynamodb = boto3.resource("dynamodb", region_name=REGION)
_incidents = _dynamodb.Table(INCIDENTS_TABLE)
_findings = _dynamodb.Table(FINDINGS_TABLE)
_approvals = _dynamodb.Table(APPROVALS_TABLE)

MAX_FINDINGS = 50          # the correlator keeps this many IDs per incident
MAX_TEXT = 600             # any one untrusted value in the report
APPROVAL_STATUSES = ("pending", "approved", "rejected", "expired")

# The identifiers a finding's resource block may name, in the order the
# correlator prefers them. The resource block is kept as a JSON string cut to
# length, so identifiers are found by pattern rather than by parsing.
_RESOURCE_PATTERNS = (
    r'"instanceId":\s*"([^"]+)"',
    r'"accessKeyId":\s*"([^"]+)"',
    r'"bucketName":\s*"([^"]+)"',
    r'"name":\s*"([^"]+)"',
    r'"functionName":\s*"([^"]+)"',
    r'"instance/([^"/]+)"',
)


# ------------------------------------------------------------------- reading
def _second_floor(value, delta):
    """An ISO timestamp moved by delta and cut to whole seconds, as a sort-key
    bound. created_at is stored as each source sent it, with or without
    fractions or a Z, so the bounds are widened by a second each way and exact
    membership is settled by finding ID."""
    moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (moment.astimezone(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%S")


def _incident_findings(incident):
    """The incident's own findings, read by sort-key range: sk begins with
    created_at, so the attack's time span bounds the query."""
    wanted = {str(f) for f in incident.get("finding_ids") or []}
    account = incident.get("account_id")
    if not wanted or not account:
        return []
    low = _second_floor(incident["first_seen"], timedelta(seconds=-1))
    high = _second_floor(incident["last_seen"], timedelta(seconds=1))
    found = []
    for source in incident.get("sources") or ["guardduty"]:
        kwargs = {"KeyConditionExpression":
                  Key("pk").eq(f"{source}#{account}") & Key("sk").between(low, high)}
        while True:
            resp = _findings.query(**kwargs)
            found.extend(i for i in resp.get("Items", []) if str(i.get("finding_id")) in wanted)
            if "LastEvaluatedKey" not in resp:
                break
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    found.sort(key=lambda i: str(i.get("sk", "")))
    return found[:MAX_FINDINGS]


def _approvals_for(finding_ids):
    """Every approval raised for one of the incident's findings. The approvals
    table is indexed by status, not by finding, so each status is read and
    filtered; the table holds one row per gated remediation and stays small."""
    wanted = {str(f) for f in finding_ids}
    rows = []
    for status in APPROVAL_STATUSES:
        kwargs = {"IndexName": "status-index",
                  "KeyConditionExpression": Key("status").eq(status)}
        while True:
            resp = _approvals.query(**kwargs)
            rows.extend(i for i in resp.get("Items", []) if str(i.get("finding_id")) in wanted)
            if "LastEvaluatedKey" not in resp:
                break
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    rows.sort(key=lambda r: str(r.get("created_at", "")))
    return [{k: r.get(k) for k in ("created_at", "playbook", "status", "finding_id",
                                   "decided_by", "decided_at", "decision_note")}
            for r in rows]


def _intel(incident):
    try:
        return intel_for([incident]) if indicator_keys(incident) else {}
    except Exception:  # noqa: BLE001 — a missing verdict is said in the report, not fatal to it
        logger.exception("threat-intel verdicts could not be read for the report")
        return {}


def _triage_note(incident_id):
    try:
        return _triage_notes([incident_id]).get(incident_id)
    except Exception:  # noqa: BLE001 — the record is the report; the note is a note
        logger.exception("triage note could not be read for the report")
        return None


# ------------------------------------------------------------------ shaping
def severity_bucket(score):
    """The normalizer's buckets, so the report reads like the dashboard."""
    score = int(score or 0)
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "INFO"


def _text(value, limit=MAX_TEXT):
    return str(value)[:limit] if value is not None else ""


def _resource_ids(resource_json):
    ids = []
    for pattern in _RESOURCE_PATTERNS:
        for match in re.findall(pattern, str(resource_json or "")):
            if match not in ids:
                ids.append(match)
    return ids


def _described_indicators(incident, intel):
    """Each indicator the incident names with its verdict, or a row that says
    it has not been looked up: an analyst should see that a verdict is
    missing, not infer it from a blank."""
    intel = intel or {}
    found = incident.get("indicators") or {}
    rows = []
    for kind, plural in (("ip", "ips"), ("domain", "domains")):
        for value in found.get(plural) or []:
            value = _text(value, 253)
            row = intel.get(value) or {}
            abuse = row.get("abuseipdb") or {}
            otx = row.get("otx") or {}
            rows.append({
                "kind": kind, "value": value,
                "verdict": _text(row.get("verdict") or "not yet looked up", 20),
                "abuseipdb": (f"{int(abuse.get('confidence') or 0)}% confidence, "
                              f"{int(abuse.get('reports') or 0)} reports"
                              + (f", {_text(abuse.get('country'), 8)}" if abuse.get("country") else "")
                              + (", Tor exit" if abuse.get("tor") else "")) if abuse else "—",
                "otx": f"{int(otx.get('pulses') or 0)} pulses" if otx else "—",
                "looked_up_at": _text(row.get("looked_up_at")),
            })
    return rows


def build_report(incident, findings, note, approvals, intel=None, now=None):
    """Everything the PDF says, as plain data, so it can be checked without
    parsing a PDF. Numbers come back from DynamoDB as Decimals; they are made
    ints here, once."""
    finding_ids = [str(f) for f in incident.get("finding_ids") or []]
    resources = [_text(incident.get("resource"))]
    rows = []
    for f in findings:
        for rid in _resource_ids(f.get("resource")):
            if rid not in resources:
                resources.append(rid)
        rows.append({
            "created_at": _text(f.get("created_at")),
            "finding_type": _text(f.get("finding_type")),
            "stage": attack.stage(f.get("finding_type")),
            "severity": int(f.get("severity") or 0),
            "severity_bucket": severity_bucket(f.get("severity")),
            "title": _text(f.get("title")),
            "finding_id": _text(f.get("finding_id")),
        })
    stages = [_text(s) for s in incident.get("attack_stages") or []]
    return {
        "generated_at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "incident": {
            "incident_id": _text(incident.get("incident_id")),
            "account_id": _text(incident.get("account_id")),
            "resource": _text(incident.get("resource")),
            "status": _text(incident.get("status") or "open"),
            "first_seen": _text(incident.get("first_seen")),
            "last_seen": _text(incident.get("last_seen")),
            "duration_seconds": int(incident.get("duration_seconds") or 0),
            "finding_count": int(incident.get("finding_count") or 0),
            "max_severity": int(incident.get("max_severity") or 0),
            "severity_bucket": severity_bucket(incident.get("max_severity")),
            "attack_stages": stages,
            "sample": _is_sample(incident.get("resource")),
        },
        "resources": resources,
        "indicators": _described_indicators(incident, intel),
        "findings": rows,
        # The correlator keeps up to 50 IDs; a finding that has since expired
        # from the table is counted here rather than silently absent.
        "findings_missing": max(len(finding_ids) - len(rows), 0),
        "attack": attack.mapping([r["finding_type"] for r in rows]
                                 or [_text(t) for t in incident.get("finding_types") or []]),
        # The same view of a note the dashboard gets: token counts and the
        # fingerprint stay server-side, and a rejected note shows only that.
        "triage": _public(note),
        "approvals": approvals,
    }


# ---------------------------------------------------------------- rendering
_styles = getSampleStyleSheet()
_BODY = ParagraphStyle("body", parent=_styles["BodyText"], fontSize=9.5, leading=13)
_SMALL = ParagraphStyle("small", parent=_BODY, fontSize=8, leading=10, textColor=colors.HexColor("#555555"))
_CELL = ParagraphStyle("cell", parent=_BODY, fontSize=8.5, leading=11, alignment=TA_LEFT)
_H1 = ParagraphStyle("h1", parent=_styles["Title"], fontSize=18, leading=22, alignment=TA_LEFT, spaceAfter=2)
_H2 = ParagraphStyle("h2", parent=_styles["Heading2"], fontSize=12, leading=15, spaceBefore=10, spaceAfter=4)
_GRID = TableStyle([
    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf3")),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
])


def _p(text, style=_BODY):
    """A paragraph of untrusted text: escaped, so markup in the data is shown,
    not interpreted."""
    return Paragraph(escape(str(text), quote=False), style)


def _cell(text):
    return _p(text, _CELL)


def _table(header, rows, widths):
    data = [[_cell(h) for h in header]] + [[_cell(c) for c in row] for row in rows]
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(_GRID)
    return table


def _bullets(items):
    return ListFlowable([ListItem(_p(i), leftIndent=10) for i in items],
                        bulletType="bullet", start="•", leftIndent=12, bulletFontSize=8)


def _clock(value):
    """A recorded timestamp as `YYYY-MM-DD HH:MM:SS` in UTC for a table cell;
    anything unparseable is shown as recorded."""
    if not value:
        return ""
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def _duration(seconds):
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s" if seconds else f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m" if minutes else f"{hours}h"


def _summary_sentence(inc):
    stages = ", ".join(s.replace("-", " ") for s in inc["attack_stages"]) or "no recorded stage"
    count = inc["finding_count"]
    if count == 1:
        opening = (f"A single GuardDuty finding against {inc['resource']} in account "
                   f"{inc['account_id']} forms this incident, at the {stages} stage.")
    else:
        span = ("within a second" if inc["duration_seconds"] < 1
                else f"over {_duration(inc['duration_seconds'])}")
        n_stages = len(inc["attack_stages"])
        opening = (f"{count} GuardDuty findings against {inc['resource']} in account "
                   f"{inc['account_id']} were correlated into one incident {span}, spanning "
                   f"{n_stages} attack stage{'s' if n_stages != 1 else ''}: {stages}.")
    return (f"{opening} The highest finding severity was {inc['max_severity']} of 100 "
            f"({inc['severity_bucket']}). The incident is {inc['status']}.")


def render_pdf(report):
    inc = report["incident"]
    provenance = ("Assembled from the platform's own records: the correlated incident, the findings "
                  "it was built from, the threat-intelligence verdicts on the addresses and domains "
                  "it names, remediation that reached the approval gate, and the advisory note a "
                  "language model wrote about it. The ATT&CK placement is indicative.")
    story = [
        _p("CloudSentinel incident report", _H1),
        _p(f"Incident {inc['incident_id']} · generated {report['generated_at']}", _SMALL),
        _p(provenance, _SMALL),
        Spacer(1, 6),

        _p("Executive summary", _H2),
        _p(_summary_sentence(inc)),
    ]
    if inc["sample"]:
        story.append(_p("The resource is a placeholder used by GuardDuty's sample-finding "
                        "generator, so this incident was built from sample findings, not live traffic."))
    if report["triage"] and report["triage"].get("status") == "complete":
        story.append(_p(f"Advisory triage (language model): {report['triage'].get('summary', '')}"))

    story += [
        Spacer(1, 4),
        _table(["Field", "Value"], [
            ["Account", inc["account_id"]],
            ["Resource", inc["resource"]],
            ["Status", inc["status"]],
            ["First seen", inc["first_seen"]],
            ["Last seen", inc["last_seen"]],
            ["Duration", _duration(inc["duration_seconds"])],
            ["Findings", str(inc["finding_count"])],
            ["Highest severity", f"{inc['max_severity']} ({inc['severity_bucket']})"],
            ["Attack stages", " → ".join(inc["attack_stages"]) or "—"],
        ], [40 * mm, 130 * mm]),

        _p("Affected resources", _H2),
        _bullets(report["resources"]),

        _p("Indicators and threat intelligence", _H2),
    ]
    if report["indicators"]:
        story.append(_table(
            ["Indicator", "Kind", "Verdict", "AbuseIPDB", "AlienVault OTX", "Looked up (UTC)"],
            [[i["value"], i["kind"], i["verdict"], i["abuseipdb"], i["otx"], _clock(i["looked_up_at"])]
             for i in report["indicators"]],
            [44 * mm, 14 * mm, 24 * mm, 42 * mm, 24 * mm, 26 * mm]))
        story.append(_p("Verdicts are reputation, not proof: malicious means the feeds hold many "
                        "reports of the indicator, not listed means they hold none, and a targeted "
                        "attacker is never listed. Nothing in the platform acts on a verdict.", _SMALL))
    else:
        story.append(_p("The findings name no public address or domain."))

    story += [
        _p("Timeline", _H2),
    ]
    if report["findings"]:
        story.append(_table(
            ["Time (UTC)", "Stage", "Finding type", "Sev.", "Title"],
            [[_clock(f["created_at"]), f["stage"], f["finding_type"].replace("/", "/ "),
              f"{f['severity']} {f['severity_bucket']}", f["title"]] for f in report["findings"]],
            [30 * mm, 28 * mm, 44 * mm, 18 * mm, 54 * mm]))
    else:
        story.append(_p("The incident's findings could not be read; the summary above is from "
                        "the incident record alone."))
    if report["findings_missing"]:
        story.append(_p(f"{report['findings_missing']} of the incident's findings were not found "
                        "in the findings table and are not shown.", _SMALL))

    story.append(_p("ATT&CK placement (indicative)", _H2))
    tactics = report["attack"]["tactics"]
    techniques = report["attack"]["techniques"]
    if tactics:
        story.append(_table(["Tactic", "ID", "Stage recorded"],
                            [[name, tid, stage] for stage, tid, name in tactics],
                            [60 * mm, 25 * mm, 85 * mm]))
    else:
        story.append(_p("No recorded stage maps to an ATT&CK tactic."))
    if techniques:
        story += [Spacer(1, 4),
                  _table(["Technique", "ID", "From finding type"],
                         [[name, tid, ftype] for ftype, tid, name in techniques],
                         [60 * mm, 25 * mm, 85 * mm])]
    else:
        story.append(_p("None of the finding types pins a technique; tactics only.", _SMALL))

    story.append(_p("Actions taken", _H2))
    if report["approvals"]:
        story.append(_table(
            ["Raised (UTC)", "Playbook", "Status", "Decided by", "Decided (UTC)"],
            [[_clock(a.get("created_at")), a.get("playbook") or "", a.get("status") or "",
              a.get("decided_by") or "—", _clock(a.get("decided_at")) or "—"] for a in report["approvals"]],
            [34 * mm, 34 * mm, 22 * mm, 50 * mm, 34 * mm]))
        story.append(_p("Destructive playbooks pause at the approval gate; the decision is "
                        "attributed to the authenticated operator who made it.", _SMALL))
    else:
        story.append(_p("No remediation reached the approval gate for these findings."))

    story.append(_p("Advisory triage by a language model", _H2))
    note = report["triage"]
    if not note:
        story.append(_p("No triage note has been recorded for this incident."))
    elif note.get("status") != "complete":
        story.append(_p("The model's answer was rejected by validation; the incident is retried "
                        "when it changes. No note is shown."))
    else:
        flags = []
        if note.get("likely_test_data"):
            flags.append("looks like test data")
        if note.get("injection_suspected"):
            flags.append("possible prompt injection in the findings")
        head = (f"Assessed {note.get('assessed_severity', '?')}, {note.get('confidence', '?')} "
                f"confidence" + (f" — {'; '.join(flags)}" if flags else ""))
        block = [_p(head), _p(note.get("summary", ""))]
        if note.get("reasons"):
            block += [_p("Why:", _SMALL), _bullets(note["reasons"])]
        if note.get("next_steps"):
            block += [_p("Suggested next steps:", _SMALL), _bullets(note["next_steps"])]
        block.append(_p(f"{note.get('model_id', '')} · {note.get('triaged_at', '')} · This note is "
                        "model output over attacker-influenced text. It is advisory; nothing in the "
                        "platform acts on it.", _SMALL))
        story.append(KeepTogether(block))

    buf = BytesIO()
    SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"CloudSentinel incident {inc['incident_id']}", author="CloudSentinel",
    ).build(story)
    return buf.getvalue()


# -------------------------------------------------------------------- route
@router.get("/incidents/{incident_id}/report", dependencies=[Depends(require_auth)],
            response_class=Response, responses={200: {"content": {"application/pdf": {}}}})
def incident_report(incident_id: str):
    """One incident as a PDF: summary, affected resources, timeline, ATT&CK
    placement, actions taken, and the advisory triage note."""
    try:
        incident = _incidents.get_item(Key={"incident_id": incident_id}).get("Item")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"report failed: {e}")
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")
    try:
        findings = _incident_findings(incident)
        approvals = _approvals_for(incident.get("finding_ids") or [])
        report = build_report(incident, findings, _triage_note(incident_id), approvals, _intel(incident))
        pdf = render_pdf(report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"report failed: {e}")
    # Incident IDs are hex, but the path segment is whatever the caller sent;
    # only characters safe in a quoted header value reach the filename.
    stem = re.sub(r"[^A-Za-z0-9_-]", "", incident_id)[:12] or "incident"
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="cloudsentinel-incident-{stem}.pdf"'},
    )
