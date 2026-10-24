"""
Tests for the form converter's handling of the second-person form.

The converter copies labels and computes only what the pipeline would; what
is pinned here is the part added for cases from a second person: the
statement on AI assistance is copied as written and must be present, the
source is recorded when asked, and nothing about a label changes.
"""
import importlib.util
from pathlib import Path

import pytest

openpyxl = pytest.importorskip("openpyxl")

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "cases_from_form.py"
CASE_HEADERS = ["Case name", "Lowest acceptable severity", "Highest acceptable severity", "Test data?",
                "Injection attempt?", "Planted text (injection cases only)", "Why (one or two sentences)",
                "Written by", "Labelled on (date)"]
FINDING_HEADERS = ["Case name", "Time (UTC)", "GuardDuty finding type", "Severity (GuardDuty, 1.0 to 8.9)", "Title",
                   "Resource type", "Resource id", "IAM user or role (keys and buckets)", "Remote IP (optional)",
                   "Domain (optional)", "User agent (optional)"]


@pytest.fixture(scope="module")
def converter():
    spec = importlib.util.spec_from_file_location("cases_from_form", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def form(path, ai_column=True, statements=("none", "ChatGPT suggested the finding types")):
    wb = openpyxl.Workbook()
    cases = wb.active
    cases.title = "Cases"
    cases.append(["Fill in the yellow cells."])
    cases.append(CASE_HEADERS + (["AI assistance (none, or the tool and what it did)"] if ai_column else []))
    cases.append(["example-lone-port-probe", "informational", "medium", "No", "No", None, "x", "(example)", None]
                 + (["(example) none"] if ai_column else []))
    cases.append(["rc-lone-probe", "informational", "medium", "No", "No", None, "One probe, nothing after.",
                  "Rahul C", "2026-10-28"] + ([statements[0]] if ai_column else []))
    cases.append(["rc-key-chain", "high", "critical", "No", "No", None, "Stolen key used from outside AWS.",
                  "Rahul C", "2026-10-28"] + ([statements[1]] if ai_column else []))
    findings = wb.create_sheet("Findings")
    findings.append(["Fill in the yellow cells."])
    findings.append(FINDING_HEADERS)
    findings.append(["rc-lone-probe", "2026-10-28 03:12:05", "Recon:EC2/PortProbeUnprotectedPort", 2,
                     "Unprotected port on EC2 instance i-0a1b2c3d4e5f67890 is being probed.", "EC2 instance",
                     "i-0a1b2c3d4e5f67890", None, "198.51.100.7", None, None])
    findings.append(["rc-key-chain", "2026-10-28 04:00:00", "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                     8, "Credentials for instance role app-role were used from a remote AWS account.", "IAM access key",
                     "ASIA5RX7QKT2NW4PVB3Q", "app-role", None, None, None])
    findings.append(["rc-key-chain", "2026-10-28 04:10:00", "Persistence:IAMUser/UserPermissions", 5,
                     "Principal app-role attempted to add a policy.", "IAM access key", "ASIA5RX7QKT2NW4PVB3Q",
                     "app-role", None, None, None])
    wb.save(path)
    return path


def test_the_statement_on_ai_assistance_is_copied_as_written_with_the_source(converter, tmp_path):
    cases = converter.convert(form(tmp_path / "f.xlsx"), source="second-person")
    assert [c["name"] for c in cases] == ["rc-lone-probe", "rc-key-chain"]
    assert [c["ai_assistance"] for c in cases] == ["none", "ChatGPT suggested the finding types"]
    assert all(c["source"] == "second-person" and c["written_by"] == "Rahul C" for c in cases)
    assert cases[0]["expect"] == {"assessed_severity": ["informational", "low", "medium"],
                                  "likely_test_data": False, "injection_suspected": False}
    assert cases[1]["expect"]["assessed_severity"] == ["high", "critical"]
    assert cases[1]["incident"]["finding_count"] == 2 and cases[1]["incident"]["duration_seconds"] == 600
    assert cases[1]["incident"]["resource"] == "ASIA5RX7QKT2NW4PVB3"           # one character short, for the scanners


def test_a_missing_statement_is_refused_and_the_old_form_still_converts(converter, tmp_path):
    with pytest.raises(ValueError, match="rc-lone-probe.*AI assistance"):
        converter.convert(form(tmp_path / "g.xlsx", statements=("", "none")))
    cases = converter.convert(form(tmp_path / "h.xlsx", ai_column=False))
    assert all("ai_assistance" not in c and "source" not in c for c in cases)
