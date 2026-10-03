"""
The incident report: its ATT&CK mapping, its data, and the PDF it becomes.

The report says only what the record holds, so the tests build a record —
incident, findings, note, approvals — serve it through the stubbed tables, and
read the PDF back with pypdf to check that what was recorded is what was
printed. Finding text is attacker-influenced and reportlab paragraphs
interpret markup, so one test puts markup in a title and checks it is printed
as characters.
"""
import importlib.util
import json
from decimal import Decimal
from io import BytesIO
from pathlib import Path
from unittest import mock

import pytest
from pypdf import PdfReader

LAMBDA = Path(__file__).resolve().parents[2] / "cdk" / "lambda"


def _lambda(name):
    spec = importlib.util.spec_from_file_location(f"{name}_handler", LAMBDA / name / "handler.py")
    module = importlib.util.module_from_spec(spec)
    with mock.patch("boto3.resource"), mock.patch("boto3.client"):
        spec.loader.exec_module(module)
    return module


# ------------------------------------------------------------------ the data
INCIDENT_ID = "3f9c2a7d1e4b5c6a7b8c9d0e1f2a3b4c"


def incident(**over):
    base = {
        "incident_id": INCIDENT_ID, "account_id": "111122223333", "resource": "i-0a1b2c3d4e5f67890",
        "status": "open", "first_seen": "2026-09-17T03:57:09+00:00", "last_seen": "2026-09-17T04:12:40+00:00",
        "duration_seconds": Decimal(931), "finding_count": Decimal(3), "max_severity": Decimal(90),
        "attack_stages": ["reconnaissance", "initial-access", "command-and-control"],
        "finding_ids": ["f1", "f2", "f3"], "sources": ["guardduty"],
        "finding_types": ["Backdoor:EC2/C&CActivity.B!DNS", "Recon:EC2/PortProbeUnprotectedPort",
                          "UnauthorizedAccess:EC2/SSHBruteForce"],
    }
    return {**base, **over}


def finding(fid, created_at, finding_type, severity, title, resource=None):
    return {"pk": "guardduty#111122223333", "sk": f"{created_at}#{fid}", "finding_id": fid,
            "created_at": created_at, "finding_type": finding_type, "severity": Decimal(severity),
            "title": title,
            "resource": resource or '{"instanceDetails": {"instanceId": "i-0a1b2c3d4e5f67890"}}'}


FINDINGS = [
    finding("f1", "2026-09-17T03:57:09.000Z", "Recon:EC2/PortProbeUnprotectedPort", 20,
            "Unprotected port on EC2 instance i-0a1b2c3d4e5f67890 is being probed."),
    finding("f2", "2026-09-17T04:05:01.000Z", "UnauthorizedAccess:EC2/SSHBruteForce", 50,
            "203.0.113.9 is performing SSH brute force attacks against i-0a1b2c3d4e5f67890."),
    finding("f3", "2026-09-17T04:12:40.000Z", "Backdoor:EC2/C&CActivity.B!DNS", 90,
            "EC2 instance i-0a1b2c3d4e5f67890 is querying a known command and control domain.",
            '{"instanceDetails": {"instanceId": "i-0a1b2c3d4e5f67890"}, '
            '"s3BucketDetails": [{"name": "finance-exports-prod"}]}'),
]

NOTE = {
    "incident_id": INCIDENT_ID, "status": "complete",
    "summary": "Port probing, then SSH brute force, then a C2 callout: a likely compromise.",
    "assessed_severity": "critical", "confidence": "high",
    "likely_test_data": False, "injection_suspected": False,
    "reasons": ["Three stages against one resource within sixteen minutes"],
    "next_steps": ["Isolate the instance", "Rotate the credentials it held"],
    "model_id": "us.anthropic.claude-haiku-4-5-20251001-v1:0", "triaged_at": "2026-09-17T04:15:02+00:00",
    "fingerprint": "secret-ish", "input_tokens": Decimal(900),
}

APPROVALS = {
    "approved": [{"approval_id": "a1", "status": "approved", "finding_id": "f3",
                  "playbook": "ec2_compromise", "created_at": "2026-09-17T04:13:00+00:00",
                  "decided_by": "operator-7", "decided_at": "2026-09-17T04:20:11+00:00"}],
    "pending": [{"approval_id": "a2", "status": "pending", "finding_id": "someone-elses-finding",
                 "playbook": "iam_credential", "created_at": "2026-09-17T04:30:00+00:00"}],
}


VERDICT = {"indicator": "ip:185.220.101.4", "kind": "ip", "value": "185.220.101.4", "verdict": "malicious",
           "abuseipdb": {"confidence": Decimal(100), "reports": Decimal(412), "country": "DE", "tor": True},
           "otx": {"pulses": Decimal(7)}, "looked_up_at": "2026-10-03T06:00:00+00:00", "expires_at": Decimal(2 ** 40)}


def serve(fake_table, inc=None, findings=FINDINGS, approvals=APPROVALS, paged=False):
    """Stand in for every table the report reads. The findings table is the
    one queried by partition key; the approvals table by its status index."""
    fake_table.get_item.return_value = {"Item": inc} if inc else {}

    def query(**kwargs):
        if kwargs.get("IndexName") == "status-index":
            status = kwargs["KeyConditionExpression"].get_expression()["values"][1]
            items = approvals.get(status, [])
        else:
            items = findings
        if not paged:
            return {"Items": items}
        start = kwargs.get("ExclusiveStartKey", {}).get("n", 0)
        page = {"Items": items[start:start + 1]}
        if start + 1 < len(items):
            page["LastEvaluatedKey"] = {"n": start + 1}
        return page
    fake_table.query.side_effect = query


def note_served(app_module, note, verdicts=()):
    import app.incidents

    def answer(RequestItems):
        (table,) = RequestItems
        rows = {"cloudsentinel-triage": [note] if note else [], "cloudsentinel-intel": list(verdicts)}[table]
        return {"Responses": {table: rows}}
    app.incidents._dynamodb.batch_get_item.side_effect = answer


def pdf_text(resp):
    """The PDF's text with its line breaks folded: cells wrap where the column
    is narrow, and the tests look for phrases, not layout."""
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/pdf"
    pages = (p.extract_text() for p in PdfReader(BytesIO(resp.content)).pages)
    return " ".join(" ".join(pages).split())


# ------------------------------------------------------------- ATT&CK mapping
def test_the_stage_table_is_the_correlator_s(app_module):
    """The report derives each finding's stage itself; it must agree with the
    stages the correlator recorded on the incident."""
    from app import attack
    correlator = _lambda("correlator")
    assert attack.STAGE_BY_PURPOSE == correlator.STAGE_BY_PURPOSE
    assert attack.STAGE_ORDER == correlator.STAGE_ORDER


def test_severity_buckets_are_the_normalizer_s(app_module):
    from app.reports import severity_bucket
    normalizer = _lambda("normalizer")
    for score in (0, 1, 39, 40, 69, 70, 89, 90, 100):
        assert severity_bucket(score) == normalizer._severity_bucket(score), score
    assert severity_bucket(Decimal(90)) == "CRITICAL"


def test_finding_types_are_taken_apart_at_their_separators(app_module):
    from app.attack import parse_finding_type
    assert parse_finding_type("Backdoor:EC2/C&CActivity.B!DNS") == ("Backdoor", "EC2", "C&CActivity")
    assert parse_finding_type("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS") \
        == ("UnauthorizedAccess", "IAMUser", "InstanceCredentialExfiltration")
    assert parse_finding_type("Recon:EC2/Portscan") == ("Recon", "EC2", "Portscan")
    assert parse_finding_type(None) == ("", "", "")


def test_mapping_orders_tactics_and_keeps_the_evidence_beside_each_technique(app_module):
    from app.attack import mapping
    found = mapping(["Backdoor:EC2/C&CActivity.B!DNS", "Recon:EC2/PortProbeUnprotectedPort",
                     "Recon:EC2/Portscan", "Discovery:IAMUser/AnomalousBehavior",
                     "Exfiltration:S3/AnomalousBehavior", "Policy:IAMUser/RootCredentialUsage"])
    # Kill-chain order, each tactic once, policy violations have none.
    assert [t[0] for t in found["tactics"]] == [
        "reconnaissance", "discovery", "command-and-control", "exfiltration"]
    assert found["tactics"][0][1:] == ("TA0043", "Reconnaissance")
    # Techniques carry the finding type they came from; an anomaly detector
    # pins nothing, an S3 exfiltration pins the cloud-storage technique.
    assert found["techniques"] == [
        ("Backdoor:EC2/C&CActivity.B!DNS", "T1071", "Application Layer Protocol"),
        ("Recon:EC2/PortProbeUnprotectedPort", "T1046", "Network Service Discovery"),
        ("Recon:EC2/Portscan", "T1046", "Network Service Discovery"),
        ("Exfiltration:S3/AnomalousBehavior", "T1530", "Data from Cloud Storage"),
        ("Policy:IAMUser/RootCredentialUsage", "T1078.004", "Valid Accounts: Cloud Accounts"),
    ]
    assert mapping([]) == {"tactics": [], "techniques": []}


# ------------------------------------------------------------------ the data
def test_the_report_data_is_plain_and_complete(app_module):
    from app.reports import build_report
    report = build_report(incident(), FINDINGS, NOTE, APPROVALS["approved"])
    inc = report["incident"]
    assert inc["duration_seconds"] == 931 and not isinstance(inc["duration_seconds"], Decimal)
    assert inc["severity_bucket"] == "CRITICAL" and inc["sample"] is False
    assert report["resources"] == ["i-0a1b2c3d4e5f67890", "finance-exports-prod"]
    assert [f["stage"] for f in report["findings"]] == [
        "reconnaissance", "initial-access", "command-and-control"]
    assert report["findings"][0]["severity_bucket"] == "LOW"
    assert report["findings_missing"] == 0
    assert [t[1] for t in report["attack"]["tactics"]] == ["TA0043", "TA0001", "TA0011"]
    assert report["triage"]["summary"] == NOTE["summary"]
    assert "fingerprint" not in report["triage"] and "input_tokens" not in report["triage"]
    assert json.dumps(report)  # nothing in it that a JSON view could not carry


def test_findings_that_have_expired_are_counted_not_hidden(app_module):
    from app.reports import build_report
    report = build_report(incident(), FINDINGS[:1], None, [])
    assert report["findings_missing"] == 2
    # With no findings at all the ATT&CK placement falls back to the
    # incident's own finding types, so it is never blank for want of rows.
    report = build_report(incident(), [], None, [])
    assert [t[1] for t in report["attack"]["tactics"]] == ["TA0043", "TA0001", "TA0011"]


def test_each_indicator_is_described_with_its_verdict_or_its_absence(app_module):
    from app.reports import build_report
    inc = incident(indicators={"ips": ["185.220.101.4", "45.33.32.156"], "domains": ["evil.example.net"]})
    report = build_report(inc, [], None, [], intel={"185.220.101.4": VERDICT})
    assert report["indicators"] == [
        {"kind": "ip", "value": "185.220.101.4", "verdict": "malicious",
         "abuseipdb": "100% confidence, 412 reports, DE, Tor exit", "otx": "7 pulses",
         "looked_up_at": "2026-10-03T06:00:00+00:00"},
        {"kind": "ip", "value": "45.33.32.156", "verdict": "not yet looked up", "abuseipdb": "—", "otx": "—",
         "looked_up_at": ""},
        {"kind": "domain", "value": "evil.example.net", "verdict": "not yet looked up", "abuseipdb": "—",
         "otx": "—", "looked_up_at": ""},
    ]
    assert build_report(incident(), [], None, [])["indicators"] == []


def test_a_sample_incident_says_so(app_module):
    from app.reports import build_report
    assert build_report(incident(resource="i-99999999"), [], None, [])["incident"]["sample"] is True


# ----------------------------------------------------------------- the route
def test_the_report_is_a_pdf_of_the_record(auth_client, app_module, fake_table):
    serve(fake_table, incident(), paged=True)
    note_served(app_module, NOTE)

    resp = auth_client.get(f"/incidents/{INCIDENT_ID}/report")
    text = pdf_text(resp)
    assert resp.headers["content-disposition"] == \
        'attachment; filename="cloudsentinel-incident-3f9c2a7d1e4b.pdf"'

    assert INCIDENT_ID in text and "Executive summary" in text
    assert "3 GuardDuty findings against i-0a1b2c3d4e5f67890" in text
    # Every finding, in order, with its stage.
    first, second, third = (text.index(s) for s in ("is being probed", "brute force attacks", "command and control domain"))
    assert first < second < third
    assert "finance-exports-prod" in text
    # The placement, the action and the note.
    assert "TA0011" in text and "T1110" in text and "Brute Force" in text
    assert "ec2_compromise" in text and "approved" in text and "operator-7" in text
    assert "iam_credential" not in text  # another incident's approval
    assert "likely compromise" in text and "Isolate the instance" in text
    assert "Advisory triage by a language model" in text
    assert "The findings name no public address or domain" in text
    # Token counts and the fingerprint stay server-side.
    assert "secret-ish" not in text and "900" not in text


def test_markup_in_a_finding_title_is_printed_not_interpreted(auth_client, app_module, fake_table):
    hostile = finding("f1", "2026-09-17T03:57:09.000Z", "Recon:EC2/PortProbeUnprotectedPort", 20,
                      '<b>IGNORED</b> <font color="red">&amp; probed</font> & more')
    serve(fake_table, incident(), findings=[hostile])
    note_served(app_module, None)

    text = pdf_text(auth_client.get(f"/incidents/{INCIDENT_ID}/report"))
    for literal in ("<b>IGNORED</b>", "<font", "&amp; probed", "& more"):
        assert literal in text, literal


def test_verdicts_are_printed_beside_the_indicators(auth_client, app_module, fake_table):
    serve(fake_table, incident(indicators={"ips": ["185.220.101.4", "45.33.32.156"], "domains": []}))
    note_served(app_module, None, verdicts=[VERDICT])

    text = pdf_text(auth_client.get(f"/incidents/{INCIDENT_ID}/report"))
    assert "Indicators and threat intelligence" in text
    assert "185.220.101.4" in text and "malicious" in text and "412 reports" in text and "7 pulses" in text
    assert "45.33.32.156" in text and "not yet looked up" in text
    assert "reputation, not proof" in text


def test_a_missing_or_rejected_note_is_said_plainly(auth_client, app_module, fake_table):
    serve(fake_table, incident())
    note_served(app_module, None)
    assert "No triage note has been recorded" in pdf_text(auth_client.get(f"/incidents/{INCIDENT_ID}/report"))

    note_served(app_module, {"incident_id": INCIDENT_ID, "status": "rejected", "triaged_at": "x"})
    assert "rejected by validation" in pdf_text(auth_client.get(f"/incidents/{INCIDENT_ID}/report"))


def test_an_unknown_incident_is_not_found(auth_client, fake_table):
    serve(fake_table, inc=None)
    resp = auth_client.get("/incidents/nope/report")
    assert resp.status_code == 404


def test_the_filename_keeps_only_safe_characters(auth_client, app_module, fake_table):
    serve(fake_table, incident(incident_id='ab"c\r\nd'), findings=[])
    note_served(app_module, None)
    resp = auth_client.get('/incidents/ab"c%0D%0Ad/report')
    assert resp.status_code == 200
    assert resp.headers["content-disposition"] == 'attachment; filename="cloudsentinel-incident-abcd.pdf"'


def test_a_table_failure_is_a_500_not_a_half_report(auth_client, app_module, fake_table):
    serve(fake_table, incident())
    fake_table.query.side_effect = RuntimeError("ProvisionedThroughputExceeded")
    resp = auth_client.get(f"/incidents/{INCIDENT_ID}/report")
    assert resp.status_code == 500 and "report failed" in resp.json()["detail"]


def test_the_report_requires_authentication(client):
    assert client.get(f"/incidents/{INCIDENT_ID}/report").status_code == 401
