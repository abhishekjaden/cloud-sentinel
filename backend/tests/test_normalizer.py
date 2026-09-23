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


def test_securityhub_normalized_score_passes_through(normalizer):
    assert normalizer._severity_to_score("securityhub", 69) == 69


@pytest.mark.parametrize("source,raw", [
    ("guardduty", None), ("guardduty", "not-a-number"),
    ("securityhub", None), ("securityhub", "abc"),
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


# ---------------------------------------------------------------- inspector
# Field values follow the example event in AWS's Amazon Inspector EventBridge
# documentation. An earlier version of this test used a numeric severity that
# Inspector never sends, which is how every Inspector finding came to be stored
# as INFO while the suite passed.
INSPECTOR_EVENT = {
    "source": "aws.inspector2",
    "account": "777788889999",
    "region": "us-east-1",
    "time": "2024-09-04T17:00:37Z",
    "detail": {
        "findingArn": "arn:aws:inspector2:us-east-1:777788889999:finding/abc",
        "severity": "MEDIUM",
        "inspectorScore": 4.8,
        "title": "CVE-2024-0001 - openssl",
        "type": "PACKAGE_VULNERABILITY",
        "resources": [{"type": "AWS_EC2_INSTANCE", "id": "i-0abc"}],
        "firstObservedAt": "Wed Sep 04 16:59:44.356 UTC 2024",
    },
}


def test_inspector_event_is_normalized(normalizer):
    out = normalizer._normalize(INSPECTOR_EVENT)
    assert out["source"] == "inspector"
    assert out["finding_id"] == "arn:aws:inspector2:us-east-1:777788889999:finding/abc"
    assert out["severity"] == 48
    assert normalizer._severity_bucket(out["severity"]) == "MEDIUM"
    assert out["raw_severity_label"] == "MEDIUM"
    assert out["created_at"] == "2024-09-04T16:59:44.356Z"


def test_inspector_high_finding_is_not_stored_as_info(normalizer):
    """The regression: the word "HIGH" went through int(), failed, and became 0."""
    event = {**INSPECTOR_EVENT,
             "detail": {**INSPECTOR_EVENT["detail"], "severity": "HIGH", "inspectorScore": 7.4}}
    assert normalizer._severity_bucket(normalizer._normalize(event)["severity"]) == "HIGH"


@pytest.mark.parametrize("score,bucket", [
    (10.0, "CRITICAL"), (9.0, "CRITICAL"), (8.9, "HIGH"), (7.0, "HIGH"),
    (6.9, "MEDIUM"), (4.0, "MEDIUM"), (3.9, "LOW"), (0.1, "LOW"), (0.0, "INFO"),
])
def test_inspector_score_bands_match_the_buckets(normalizer, score, bucket):
    """Scaled by ten, CVSS bands land exactly on the bucket boundaries."""
    got = normalizer._inspector_score({"inspectorScore": score})
    assert normalizer._severity_bucket(got) == bucket


@pytest.mark.parametrize("detail,bucket", [
    ({"severity": "CRITICAL"}, "CRITICAL"),
    ({"severity": "HIGH"}, "HIGH"),
    ({"severity": "high"}, "HIGH"),
    ({"severity": "MEDIUM"}, "MEDIUM"),
    ({"severity": "LOW"}, "LOW"),
    ({"severity": "INFORMATIONAL"}, "INFO"),
    ({"severity": "UNTRIAGED"}, "INFO"),
    ({}, "INFO"),
    ({"severity": "HIGH", "inspectorScore": "n/a"}, "HIGH"),
    ({"severity": "HIGH", "inspectorScore": float("nan")}, "HIGH"),
    ({"severity": "HIGH", "inspectorScore": float("inf")}, "HIGH"),
])
def test_inspector_label_is_the_fallback_when_there_is_no_usable_score(normalizer, detail, bucket):
    assert normalizer._severity_bucket(normalizer._inspector_score(detail)) == bucket


@pytest.mark.parametrize("raw,expected", [
    ("Wed Sep 04 16:59:44.356 UTC 2024", "2024-09-04T16:59:44.356Z"),
    ("Wed Sep 04 16:59:44 UTC 2024", "2024-09-04T16:59:44.000Z"),
    ("2026-09-17T03:57:09Z", "2026-09-17T03:57:09Z"),       # ISO passes through
    ("2026-09-17T03:57:09.123+00:00", "2026-09-17T03:57:09.123+00:00"),
])
def test_inspector_time_is_stored_as_iso(normalizer, raw, expected):
    assert normalizer._inspector_time(raw, "fallback") == expected


@pytest.mark.parametrize("raw", [None, "", "not a date", "Wed Sep 04 16:59:44 IST 2024"])
def test_unreadable_inspector_time_falls_back_to_event_time(normalizer, raw):
    assert normalizer._inspector_time(raw, "2024-09-04T17:00:37Z") == "2024-09-04T17:00:37Z"


def test_inspector_findings_sort_by_time_among_the_other_sources(normalizer):
    """sk begins with created_at and the findings list orders by sk. Stored as
    sent, "Wed Sep 04 ... 2024" sorted above a 2026 GuardDuty finding."""
    inspector = normalizer._inspector_time("Wed Sep 04 16:59:44.356 UTC 2024", None)
    guardduty = "2026-09-17T03:57:09.000Z"
    newest_first = sorted([f"{inspector}#insp", f"{guardduty}#gd"], reverse=True)
    assert newest_first[0].endswith("#gd")


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


# --------------------------------------------------------- failures and loss
# A record that fails is handed back to Lambda by sequence number, so the shard
# rewinds to it and it is delivered again rather than skipped. Getting this
# wrong is silent: the batch still succeeds, the alarm still reads zero, and the
# finding is simply not in the table.
def _batch(*payloads):
    return {"Records": [
        {"kinesis": {"data": base64.b64encode(p).decode(), "sequenceNumber": f"4957{i:04d}"}}
        for i, p in enumerate(payloads)
    ]}


def _metric_lines(capsys):
    """Embedded Metric Format records the handler printed."""
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()
            if line.startswith("{") and '"_aws"' in line]


def test_a_failed_record_is_handed_back_by_sequence_number(normalizer, capsys):
    good = json.dumps(INSPECTOR_EVENT).encode()
    with mock.patch.object(normalizer, "_table") as table:
        # one record that cannot be parsed, one that DynamoDB refuses
        table.put_item.side_effect = [None, RuntimeError("throttled"), None]
        event = _batch(good, b"not json", good, good)
        result = normalizer.handler(event, None)

    assert result == {"batchItemFailures": [
        {"itemIdentifier": "49570001"},  # the unparseable record
        {"itemIdentifier": "49570002"},  # the one DynamoDB refused
    ]}
    (line,) = _metric_lines(capsys)
    assert line["RecordsReceived"] == 4
    assert line["RecordsFailed"] == 2


def test_a_stored_record_is_never_handed_back(normalizer):
    """Reporting a record Lambda already stored rewinds the shard over it for
    nothing, and every record after it in the batch with it."""
    with mock.patch.object(normalizer, "_table"):
        result = normalizer.handler(_batch(*[json.dumps(INSPECTOR_EVENT).encode()] * 3), None)

    assert result == {"batchItemFailures": []}


def test_the_response_carries_nothing_but_the_failures(normalizer):
    """Lambda reads this response as a partial batch report and treats one it
    cannot read as the whole batch failing, so an extra key here would turn one
    bad record into a hundred retried ones."""
    with mock.patch.object(normalizer, "_table"):
        result = normalizer.handler(_batch(json.dumps(INSPECTOR_EVENT).encode()), None)

    assert set(result) == {"batchItemFailures"}


def test_a_record_with_no_sequence_number_is_still_counted(normalizer, capsys):
    """Nothing can be handed back for a record Lambda did not identify, but the
    count is what the dashboard shows, so it must not quietly read zero."""
    with mock.patch.object(normalizer, "_table"):
        result = normalizer.handler({"Records": [{"kinesis": {}}]}, None)

    assert result == {"batchItemFailures": []}
    (line,) = _metric_lines(capsys)
    assert (line["RecordsReceived"], line["RecordsFailed"]) == (1, 1)


def test_a_redelivered_record_overwrites_rather_than_duplicates(normalizer):
    """Kinesis redelivers from the lowest reported sequence number, so records
    after a failed one are processed twice. The key has to come from the
    finding, or a retry would double every finding that shared its batch."""
    with mock.patch.object(normalizer, "_table") as table:
        normalizer.handler(_batch(*[json.dumps(INSPECTOR_EVENT).encode()] * 2), None)

    first, second = (call.kwargs["Item"] for call in table.put_item.call_args_list)
    assert (first["pk"], first["sk"]) == (second["pk"], second["sk"])


def test_a_clean_batch_reports_no_failures(normalizer, capsys):
    """Zero is published rather than omitted, so the stored-share graph has a
    denominator for every batch."""
    with mock.patch.object(normalizer, "_table"):
        normalizer.handler(_batch(json.dumps(INSPECTOR_EVENT).encode()), None)

    (line,) = _metric_lines(capsys)
    assert (line["RecordsReceived"], line["RecordsFailed"]) == (1, 0)


def test_the_metrics_line_is_embedded_metric_format(normalizer, capsys):
    """CloudWatch drops a malformed EMF line without reporting an error, and the
    alarm reading the metric then never fires. Namespace, dimension and names
    are the ones the observability stack's alarm is built on."""
    with mock.patch.object(normalizer, "_table"):
        normalizer.handler(_batch(json.dumps(INSPECTOR_EVENT).encode()), None)

    (line,) = _metric_lines(capsys)
    (spec,) = line["_aws"]["CloudWatchMetrics"]
    assert spec["Namespace"] == "CloudSentinel"
    assert spec["Dimensions"] == [["Component"]]
    assert line["Component"] == "normalizer"
    declared = {m["Name"] for m in spec["Metrics"]}
    assert declared == {"RecordsReceived", "RecordsFailed"}
    for name in declared:
        assert isinstance(line[name], int)
    assert all(m["Unit"] == "Count" for m in spec["Metrics"])
    assert isinstance(line["_aws"]["Timestamp"], int)
