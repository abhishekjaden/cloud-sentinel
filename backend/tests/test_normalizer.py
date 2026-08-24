"""
Tests for the finding normalizer.

The normalizer is the point where three unrelated AWS schemas become one, and
where the severity score that drives the SOAR loop is decided. A regression
here corrupts the data store silently, so the mapping is pinned by tests.

boto3 is stubbed before import because handler.py builds its DynamoDB resource
at module scope.
"""
import base64
import importlib
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

HANDLER_DIR = Path(__file__).resolve().parents[2] / "cdk" / "lambda" / "normalizer"


@pytest.fixture(scope="module")
def normalizer():
    sys.path.insert(0, str(HANDLER_DIR))
    with mock.patch("boto3.resource"):
        module = importlib.import_module("handler")
        importlib.reload(module)
    yield module
    sys.path.remove(str(HANDLER_DIR))


# --------------------------------------------------------------- severity map
@pytest.mark.parametrize("score,expected", [
    (100, "CRITICAL"), (90, "CRITICAL"),
    (89, "HIGH"), (70, "HIGH"),
    (69, "MEDIUM"), (40, "MEDIUM"),
    (39, "LOW"), (1, "LOW"),
    (0, "INFO"), (-5, "INFO"),
])
def test_severity_bucket_boundaries(normalizer, score, expected):
    assert normalizer._severity_bucket(score) == expected


@pytest.mark.parametrize("raw,expected", [
    (8.9, 100),   # GuardDuty's maximum maps to the top of the scale
    (8.0, 90),    # the high-severity findings that trigger remediation
    (4.45, 50),
    (0.0, 0),
])
def test_guardduty_severity_is_rescaled(normalizer, raw, expected):
    assert normalizer._severity_to_score("guardduty", raw) == expected


def test_guardduty_high_severity_reaches_critical_bucket(normalizer):
    """A severity-8 GuardDuty finding must classify as CRITICAL, because the
    remediation EventBridge rule keys off the resulting bucket."""
    score = normalizer._severity_to_score("guardduty", 8.0)
    assert normalizer._severity_bucket(score) == "CRITICAL"


@pytest.mark.parametrize("source", ["securityhub", "inspector"])
def test_normalized_sources_pass_score_through(normalizer, source):
    assert normalizer._severity_to_score(source, 69) == 69


@pytest.mark.parametrize("source,raw", [
    ("guardduty", None), ("guardduty", "not-a-number"),
    ("securityhub", None), ("securityhub", "abc"),
    ("inspector", None),
    ("unknown-source", 50),
])
def test_malformed_severity_degrades_to_zero(normalizer, source, raw):
    assert normalizer._severity_to_score(source, raw) == 0


# ------------------------------------------------------------ schema mapping
def test_guardduty_event_is_normalized(normalizer):
    event = {
        "source": "aws.guardduty",
        "account": "111122223333",
        "region": "us-east-1",
        "time": "2026-01-01T00:00:00Z",
        "detail": {
            "id": "gd-finding-1",
            "severity": 8.0,
            "title": "C&C activity detected",
            "type": "Backdoor:EC2/C&CActivity.B!DNS",
            "resource": {"instanceDetails": {"instanceId": "i-123"}},
            "createdAt": "2026-01-01T00:00:00Z",
        },
    }
    out = normalizer._normalize(event)
    assert out["finding_id"] == "gd-finding-1"
    assert out["source"] == "guardduty"
    assert out["account_id"] == "111122223333"
    assert out["severity"] == 90
    assert out["finding_type"] == "Backdoor:EC2/C&CActivity.B!DNS"


def test_securityhub_event_is_normalized(normalizer):
    event = {
        "source": "aws.securityhub",
        "region": "us-east-1",
        "time": "2026-01-01T00:00:00Z",
        "detail": {"findings": [{
            "Id": "sh-finding-1",
            "AwsAccountId": "444455556666",
            "Severity": {"Normalized": 70, "Label": "HIGH"},
            "Title": "S3 bucket allows public read",
            "Types": ["Software and Configuration Checks"],
            "Resources": [{"Type": "AwsS3Bucket"}],
            "CreatedAt": "2026-01-01T00:00:00Z",
        }]},
    }
    out = normalizer._normalize(event)
    assert out["finding_id"] == "sh-finding-1"
    assert out["source"] == "securityhub"
    assert out["account_id"] == "444455556666"
    assert out["severity"] == 70
    assert out["raw_severity_label"] == "HIGH"


def test_inspector_event_is_normalized(normalizer):
    event = {
        "source": "aws.inspector2",
        "account": "777788889999",
        "region": "us-east-1",
        "time": "2026-01-01T00:00:00Z",
        "detail": {
            "findingArn": "arn:aws:inspector2:...:finding/abc",
            "severity": 40,
            "title": "CVE-2026-0001 in openssl",
            "type": "PACKAGE_VULNERABILITY",
            "resources": [{"type": "AWS_EC2_INSTANCE"}],
            "firstObservedAt": "2026-01-01T00:00:00Z",
        },
    }
    out = normalizer._normalize(event)
    assert out["source"] == "inspector"
    assert out["severity"] == 40


def test_unknown_source_does_not_raise(normalizer):
    """An unrecognized source must degrade gracefully rather than poison the
    batch — one bad record should never stop the others being processed."""
    out = normalizer._normalize({"source": "aws.somethingelse", "detail": {}})
    assert out["source"] == "aws.somethingelse"
    assert out["severity"] == 0
    assert out["title"] == "unrecognized finding source"


def test_securityhub_event_with_no_findings_does_not_raise(normalizer):
    out = normalizer._normalize({"source": "aws.securityhub", "detail": {"findings": []}})
    assert out["source"] == "securityhub"
    assert out["severity"] == 0
