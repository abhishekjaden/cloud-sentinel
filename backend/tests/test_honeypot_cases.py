"""
The honeypot export: an incident out of the tables into the case shape, with
the label empty and the triage table never read.
"""
import importlib.util
import json
from decimal import Decimal
from pathlib import Path
from unittest import mock

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "honeypot_cases.py"


@pytest.fixture(scope="module")
def exporter():
    spec = importlib.util.spec_from_file_location("honeypot_cases", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INCIDENT = {
    "incident_id": "00a2f41bcde2af0c85c1640e586bca93", "account_id": "118821712739",
    "resource": "i-0056dd9b1a24c9c16", "first_seen": "2026-10-13T00:55:36.409000+00:00",
    "last_seen": "2026-10-13T00:55:36.409000+00:00", "duration_seconds": Decimal(0),
    "finding_count": Decimal(1), "max_severity": Decimal(22),
    "attack_stages": ["initial-access"], "finding_types": ["UnauthorizedAccess:EC2/SSHBruteForce"],
    "finding_ids": ["2ed09960fe6cc677153fb4baed7ff703"], "sources": ["guardduty"],
    "indicators": {"ips": ["84.43.239.210"], "domains": []},
}
FINDING = {
    "pk": "guardduty#118821712739", "sk": "2026-10-13T00:55:36.409Z#2ed09960fe6cc677153fb4baed7ff703",
    "finding_id": "2ed09960fe6cc677153fb4baed7ff703", "finding_type": "UnauthorizedAccess:EC2/SSHBruteForce",
    "severity": Decimal(22), "created_at": "2026-10-13T00:55:36.409Z",
    "title": "An EC2 instance was involved in SSH brute force attacks.",
    "resource": json.dumps({"instanceDetails": {"instanceId": "i-0056dd9b1a24c9c16"}}),
}
VERDICT = {"indicator": "ip:84.43.239.210", "verdict": "malicious",
           "abuseipdb": {"confidence": Decimal(100), "reports": Decimal(2451)}, "otx": {"pulses": Decimal(3)},
           "looked_up_at": "2026-10-13T01:00:00+00:00"}


def _ddb():
    ddb = mock.MagicMock()
    tables = {}
    ddb.Table.side_effect = lambda name: tables.setdefault(name, mock.MagicMock(name=name))
    ddb.batch_get_item.return_value = {"Responses": {"cloudsentinel-intel": [VERDICT]}}
    return ddb, tables


def test_an_incident_becomes_an_unlabelled_case_in_the_authored_shape(exporter):
    ddb, tables = _ddb()
    tables.setdefault("cloudsentinel-findings", mock.MagicMock()).query.return_value = {"Items": [FINDING]}
    case = exporter.case_of(ddb, INCIDENT, 1)

    assert case["source"] == "honeypot"
    assert case["name"] == "honeypot-2026-10-13-1-sshbruteforce"
    assert case["why"] == "" and case["labelled_by"] == ""
    # The labeller's statement on AI assistance is a field of the case, to be
    # filled with the label (protocol section 5); the export leaves it empty.
    assert case["ai_assistance"] == ""
    assert case["expect"] == {"assessed_severity": [], "likely_test_data": False, "injection_suspected": False}
    assert case["incident"]["resource"] == "i-0056dd9b1a24c9c16"
    assert case["incident"]["max_severity"] == 22 and isinstance(case["incident"]["max_severity"], int)
    assert case["incident"]["indicators"] == {"ips": ["84.43.239.210"]}
    assert case["findings"] == [{
        "created_at": "2026-10-13T00:55:36.409Z", "finding_type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "severity": 22, "title": "An EC2 instance was involved in SSH brute force attacks.",
        "resource": FINDING["resource"]}]
    # The verdict is cut to what the triage function describes, and nothing else.
    assert case["intel"] == {"ip:84.43.239.210": {"verdict": "malicious",
                                                   "abuseipdb": {"confidence": 100, "reports": 2451},
                                                   "otx": {"pulses": 3}}}
    json.dumps(case)   # no Decimal left anywhere


def test_the_export_never_touches_the_triage_table(exporter):
    ddb, tables = _ddb()
    tables.setdefault("cloudsentinel-findings", mock.MagicMock()).query.return_value = {"Items": [FINDING]}
    exporter.case_of(ddb, INCIDENT, 1)
    assert "cloudsentinel-triage" not in tables
    assert all("triage" not in str(c) for c in ddb.batch_get_item.call_args_list)


def test_findings_are_read_by_the_attacks_span_and_filtered_by_id(exporter):
    ddb, tables = _ddb()
    other = dict(FINDING, finding_id="someone-else", sk="2026-10-13T00:55:36.000Z#someone-else")
    tables.setdefault("cloudsentinel-findings", mock.MagicMock()).query.return_value = {"Items": [other, FINDING]}
    found = exporter.findings_of(ddb, INCIDENT)
    assert [f["finding_id"] for f in found] == ["2ed09960fe6cc677153fb4baed7ff703"]
    condition = tables["cloudsentinel-findings"].query.call_args.kwargs["KeyConditionExpression"]
    values = []
    def walk(c):
        for v in c.get_expression()["values"]:
            walk(v) if hasattr(v, "get_expression") else values.append(v)
    walk(condition)
    assert "guardduty#118821712739" in values
    assert any(str(v).startswith("2026-10-13T00:55:35") for v in values)   # a second either side
    assert any(str(v).startswith("2026-10-13T00:55:37") for v in values)


def test_a_later_export_can_take_only_what_arrived_since_and_number_on(exporter):
    """The five labelled on 18 October stay as they are; an export before the
    honeypot is destroyed takes the incidents after them and numbers from six,
    so the names say which case is which across the two exports."""
    earlier = dict(INCIDENT, first_seen="2026-10-17T19:45:11.027000+00:00")
    later = dict(INCIDENT, incident_id="b" * 32, first_seen="2026-10-19T01:45:11.350000+00:00",
                 last_seen="2026-10-19T01:45:11.350000+00:00")
    assert exporter.incidents_since([earlier, later], "2026-10-18") == [later]
    assert exporter.incidents_since([earlier, later], "2026-10-17T19:45:11") == [earlier, later]
    assert exporter.incidents_since([earlier, later], None) == [earlier, later]
    ddb, tables = _ddb()
    tables.setdefault("cloudsentinel-findings", mock.MagicMock()).query.return_value = {"Items": [FINDING]}
    assert exporter.case_of(ddb, later, 6)["name"] == "honeypot-2026-10-19-6-sshbruteforce"

