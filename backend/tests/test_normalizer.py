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
from botocore.exceptions import ClientError

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


def test_a_member_accounts_finding_is_filed_under_the_member_not_the_administrator(normalizer):
    """The audit account is the organization's delegated administrator, so a
    member account's finding arrives in an EventBridge event whose top-level
    account is the administrator's; detail.accountId is the account the
    finding is about. The honeypot's first five findings (workload account,
    13–17 October 2026) were filed under the audit account for want of this."""
    event = {
        "source": "aws.guardduty", "account": "118821712739", "region": "us-east-1",
        "time": "2026-10-13T00:55:40Z",
        "detail": {"id": "gd-honeypot-1", "accountId": "743181156000", "severity": 2.0,
                   "title": "84.43.239.210 is performing SSH brute force attacks against i-0056dd9b1a24c9c16.",
                   "type": "UnauthorizedAccess:EC2/SSHBruteForce",
                   "resource": {"instanceDetails": {"instanceId": "i-0056dd9b1a24c9c16"}},
                   "createdAt": "2026-10-13T00:55:36.409Z"},
    }
    out = normalizer._normalize(event)
    assert out["account_id"] == "743181156000"
    normalizer._persist(out)
    item = normalizer._table.put_item.call_args.kwargs["Item"]
    assert item["pk"] == "guardduty#743181156000"


def test_an_inspector_finding_is_filed_under_its_own_account_too(normalizer):
    event = dict(INSPECTOR_EVENT, account="118821712739",
                 detail=dict(INSPECTOR_EVENT["detail"], awsAccountId="777788889999"))
    assert normalizer._normalize(event)["account_id"] == "777788889999"


def test_a_finding_without_its_own_account_falls_back_to_the_envelope(normalizer):
    out = normalizer._normalize({"source": "aws.guardduty", "account": "111122223333", "region": "us-east-1",
                                 "time": "2026-01-01T00:00:00Z",
                                 "detail": {"id": "x", "severity": 2.0, "title": "t", "type": "Recon:EC2/Portscan",
                                            "resource": {}, "createdAt": "2026-01-01T00:00:00Z"}})
    assert out["account_id"] == "111122223333"


def _guardduty(action, finding_type="UnauthorizedAccess:EC2/SSHBruteForce"):
    return {"source": "aws.guardduty", "account": "111122223333", "region": "us-east-1",
            "time": "2026-01-01T00:00:00Z",
            "detail": {"id": "gd-1", "severity": 5.0, "title": "t", "type": finding_type,
                       "resource": {"instanceDetails": {"instanceId": "i-123"}},
                       "createdAt": "2026-01-01T00:00:00Z",
                       "service": {"action": action}}}


def test_the_remote_end_of_a_connection_is_kept_as_an_indicator(normalizer):
    """GuardDuty puts the other party under remoteIpDetails, for a connection,
    an API call, a Kubernetes call or a database login alike."""
    for key in ("networkConnectionAction", "awsApiCallAction", "kubernetesApiCallAction",
                "rdsLoginAttemptAction"):
        out = normalizer._normalize(_guardduty({key: {"remoteIpDetails": {"ipAddressV4": "45.33.32.156"}}}))
        assert out["indicators"] == {"ips": ["45.33.32.156"]}, key


def test_a_port_probe_keeps_each_prober_once_and_only_so_many(normalizer):
    probes = [{"remoteIpDetails": {"ipAddressV4": f"45.33.32.{n}"}} for n in range(1, 15)]
    probes.insert(0, {"remoteIpDetails": {"ipAddressV4": "45.33.32.1"}})  # a repeat
    out = normalizer._normalize(_guardduty({"portProbeAction": {"portProbeDetails": probes}},
                                           "Recon:EC2/PortProbeUnprotectedPort"))
    assert out["indicators"]["ips"][:2] == ["45.33.32.1", "45.33.32.2"]
    assert len(out["indicators"]["ips"]) == normalizer.MAX_INDICATORS


def test_a_dns_request_keeps_the_domain_normalised(normalizer):
    out = normalizer._normalize(_guardduty({"dnsRequestAction": {"domain": " Evil.Example.NET. "}},
                                           "Backdoor:EC2/C&CActivity.B!DNS"))
    assert out["indicators"] == {"domains": ["evil.example.net"]}


def test_private_documentation_and_malformed_addresses_are_not_indicators(normalizer):
    """A VPC-internal address names the victim's own network, not an attacker,
    and the documentation ranges are what GuardDuty's sample findings use;
    either would only spend threat-intelligence lookups on nothing."""
    for address in ("10.0.0.5", "172.16.3.4", "192.168.1.1", "127.0.0.1", "169.254.169.254",
                    "198.51.100.7", "203.0.113.9", "fe80::1", "not an ip", "", None):
        out = normalizer._normalize(_guardduty({"networkConnectionAction": {"remoteIpDetails": {"ipAddressV4": address}}}))
        assert out["indicators"] is None, address


def test_a_finding_without_an_action_block_stores_no_indicators(normalizer):
    out = normalizer._normalize(_guardduty({}))
    assert out["indicators"] is None
    # And the attribute is left off the item rather than stored as a null.
    with mock.patch.object(normalizer, "_table") as table:
        normalizer._persist(out)
    assert "indicators" not in table.put_item.call_args.kwargs["Item"]


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
    assert out["source"] == "unknown"
    assert out["raw_source"] == "aws.somethingelse"   # kept, just not partitioned by
    assert out["severity"] == 0
    assert out["title"] == "unrecognized finding source"


def test_securityhub_event_with_no_findings_does_not_raise(normalizer):
    out = normalizer._normalize({"source": "aws.securityhub", "detail": {"findings": []}})
    assert out["source"] == "securityhub"
    assert out["severity"] == 0


# ---------------------------------------------------------- what the routes see
# /findings and /stats query one partition per source and per severity bucket
# instead of reading the table. That covers every finding only while the
# normalizer writes nothing outside those two sets: a finding stored under a
# value the routes do not ask for is in the table, correct, and in no answer
# the dashboard ever shows. These are the two halves of that contract.
@pytest.fixture(scope="module")
def routes():
    with mock.patch("boto3.resource"):
        import app.findings
        return importlib.reload(app.findings)


def test_every_source_the_normalizer_writes_is_one_the_routes_query(normalizer, routes):
    written = {normalizer._normalize(event)["source"] for event in (
        {"source": "aws.guardduty", "detail": {}},
        {"source": "aws.securityhub", "detail": {"findings": [{}]}},
        {"source": "aws.inspector2", "detail": {}},
        {"source": "aws.macie", "detail": {}},   # a service nothing routes yet
        {"source": "", "detail": {}},
        {},                                      # not an EventBridge event at all
    )}
    # Equality both ways: every source is asked for, and none of the four the
    # routes ask for is a partition that can never exist.
    assert written == set(routes.SOURCES)


def test_every_bucket_the_normalizer_writes_is_one_the_routes_count(normalizer, routes):
    produced = {normalizer._severity_bucket(score) for score in range(-20, 121)}
    assert produced == set(routes.BUCKETS)


# --------------------------------------------------------- failures and loss
# A record whose write failed is handed back to Lambda by sequence number and
# delivered again rather than skipped (ADR 0007). A record that can never be
# stored is reported to the failure queue instead, at once (ADR 0008): handed
# back, it would hold the shard for an hour, and experiment E1 showed the
# finding behind it lost when it was finally dropped. Getting either wrong is
# silent: the batch still succeeds, and the finding is simply not in the table.
QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/111122223333/cloudsentinel-failed-findings"


def _batch(*payloads):
    return {"Records": [
        {"kinesis": {"data": base64.b64encode(p).decode(), "sequenceNumber": f"4957{i:04d}"}}
        for i, p in enumerate(payloads)
    ]}


def _metric_lines(capsys):
    """Embedded Metric Format records the handler printed."""
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()
            if line.startswith("{") and '"_aws"' in line]


@pytest.fixture
def queue(normalizer):
    """The failure queue, as the handler sees it."""
    client = mock.MagicMock()
    with mock.patch.object(normalizer, "_FAILED_QUEUE_URL", QUEUE_URL), \
            mock.patch.object(normalizer, "_queue", return_value=client):
        yield client


def _sent(queue):
    """The bodies the handler sent to the failure queue."""
    for call in queue.send_message.call_args_list:
        assert call.kwargs["QueueUrl"] == QUEUE_URL
    return [json.loads(call.kwargs["MessageBody"]) for call in queue.send_message.call_args_list]


def _refusal(code):
    return ClientError({"Error": {"Code": code, "Message": "refused"}}, "PutItem")


def test_each_failure_goes_where_it_can_be_recovered_from(normalizer, queue, capsys):
    good = json.dumps(INSPECTOR_EVENT).encode()
    with mock.patch.object(normalizer, "_table") as table:
        # one record that cannot be read, and one write the table throttles
        table.put_item.side_effect = [None, RuntimeError("throttled"), None]
        result = normalizer.handler(_batch(good, b"not json", good, good), None)

    # the throttled write is retried; the unreadable record is reported, not retried
    assert result == {"batchItemFailures": [{"itemIdentifier": "49570002"}]}
    (body,) = _sent(queue)
    assert body["KinesisBatchInfo"]["startSequenceNumber"] == "49570001"
    (line,) = _metric_lines(capsys)
    assert (line["RecordsReceived"], line["RecordsFailed"], line["RecordsRejected"]) == (4, 1, 1)


@pytest.mark.parametrize("payload", [
    b"this is not a finding",        # experiment E1's record
    b'"a JSON string"', b"[1, 2]", b"null", b"42",
    b"",
])
def test_a_record_that_cannot_be_read_is_reported_at_once_and_not_handed_back(
        normalizer, queue, payload):
    with mock.patch.object(normalizer, "_table") as table:
        result = normalizer.handler(_batch(payload), None)

    assert result == {"batchItemFailures": []}
    table.put_item.assert_not_called()
    (body,) = _sent(queue)
    assert body["requestContext"]["condition"] == "RecordRejected"


def test_nothing_behind_a_rejected_record_waits_for_it(normalizer, queue):
    """The finding E1 lost was the one sent 4.6 seconds behind the garbage.
    Rejected rather than handed back, the garbage holds nothing up: the
    finding behind it is stored in the same delivery."""
    with mock.patch.object(normalizer, "_table") as table:
        result = normalizer.handler(
            _batch(b"this is not a finding", json.dumps(INSPECTOR_EVENT).encode()), None)

    assert result == {"batchItemFailures": []}
    table.put_item.assert_called_once()


def test_the_rejection_points_into_the_stream_like_lambdas_own_message(normalizer, queue):
    """Same shape as the message Lambda sends when it gives a batch up, so the
    recovery runbook in docs/slos.md reads both; a pointer, not a copy, so the
    queue keeps no finding content (it is encrypted with SQS-managed keys for
    that reason)."""
    record = {
        "eventID": "shardId-000000000000:49677756101047019183198917362009111694844355380493942786",
        "eventSourceARN": "arn:aws:kinesis:us-east-1:118821712739:stream/cloudsentinel-findings",
        "kinesis": {
            "data": base64.b64encode(b"record content not to be copied").decode(),
            "sequenceNumber": "49677756101047019183198917362009111694844355380493942786",
            "approximateArrivalTimestamp": 1791830733.044,
            "partitionKey": "chaos",
        },
    }
    context = mock.Mock(aws_request_id="req-1",
                        invoked_function_arn="arn:aws:lambda:us-east-1:118821712739:function:CloudSentinel-Normalizer")
    with mock.patch.object(normalizer, "_table"):
        normalizer.handler({"Records": [record]}, context)

    (body,) = _sent(queue)
    assert body["requestContext"]["condition"] == "RecordRejected"
    assert body["requestContext"]["reason"].startswith("JSONDecodeError: ")
    assert body["requestContext"]["requestId"] == "req-1"
    info = body["KinesisBatchInfo"]
    assert info == {
        "shardId": "shardId-000000000000",
        "startSequenceNumber": record["kinesis"]["sequenceNumber"],
        "endSequenceNumber": record["kinesis"]["sequenceNumber"],
        "approximateArrivalOfFirstRecord": "2026-10-12T18:45:33.044+00:00",
        "approximateArrivalOfLastRecord": "2026-10-12T18:45:33.044+00:00",
        "batchSize": 1,
        "streamArn": record["eventSourceARN"],
    }
    sent = queue.send_message.call_args.kwargs["MessageBody"]
    assert "not to be copied" not in sent and record["kinesis"]["data"] not in sent


@pytest.mark.parametrize("refusal", [
    _refusal("ValidationException"),     # an item DynamoDB will never accept
    TypeError("Float types are not supported. Use Decimal types instead."),
])
def test_a_write_refused_because_of_the_item_is_rejected_too(normalizer, queue, refusal):
    with mock.patch.object(normalizer, "_table") as table:
        table.put_item.side_effect = refusal
        result = normalizer.handler(_batch(json.dumps(INSPECTOR_EVENT).encode()), None)

    assert result == {"batchItemFailures": []}
    assert len(_sent(queue)) == 1


@pytest.mark.parametrize("refusal", [
    _refusal("AccessDeniedException"),               # experiment E2: the table denied
    _refusal("ProvisionedThroughputExceededException"),
    _refusal("ResourceNotFoundException"),
    _refusal("KMSAccessDeniedException"),
    RuntimeError("timed out"),
])
def test_a_write_that_could_succeed_later_is_handed_back_not_reported(normalizer, queue, refusal):
    """ADR 0007 stands for these: the shard holds, findings-fresh reports it,
    and the record stores itself when the table or key comes back."""
    with mock.patch.object(normalizer, "_table") as table:
        table.put_item.side_effect = refusal
        result = normalizer.handler(_batch(json.dumps(INSPECTOR_EVENT).encode()), None)

    assert result == {"batchItemFailures": [{"itemIdentifier": "49570000"}]}
    queue.send_message.assert_not_called()


def test_a_rejection_the_queue_refuses_is_handed_back_rather_than_dropped(normalizer, queue, capsys):
    queue.send_message.side_effect = _refusal("AccessDenied")
    with mock.patch.object(normalizer, "_table"):
        result = normalizer.handler(_batch(b"this is not a finding"), None)

    assert result == {"batchItemFailures": [{"itemIdentifier": "49570000"}]}
    (line,) = _metric_lines(capsys)
    assert (line["RecordsFailed"], line["RecordsRejected"]) == (1, 0)


def test_without_a_failure_queue_a_bad_record_is_handed_back(normalizer):
    with mock.patch.object(normalizer, "_FAILED_QUEUE_URL", None), \
            mock.patch.object(normalizer, "_table"):
        result = normalizer.handler(_batch(b"this is not a finding"), None)

    assert result == {"batchItemFailures": [{"itemIdentifier": "49570000"}]}


def test_a_stored_finding_carries_the_three_latency_stamps(normalizer):
    """Emitted, queued, stored: the measurement script reads the gaps between
    them, so a finding missing one would vanish from the latency figures."""
    event = {**INSPECTOR_EVENT, "time": "2026-10-03T09:00:00Z"}
    batch = _batch(json.dumps(event).encode())
    batch["Records"][0]["kinesis"]["approximateArrivalTimestamp"] = 1790000000.25
    with mock.patch.object(normalizer, "_table") as table:
        normalizer.handler(batch, None)

    item = table.put_item.call_args.kwargs["Item"]
    assert item["event_time"] == "2026-10-03T09:00:00Z"
    assert item["queued_at"] == "2026-09-21T14:13:20.250+00:00"
    assert item["stored_at"] >= item["queued_at"] and item["stored_at"].endswith("+00:00")


def test_a_record_without_an_arrival_time_is_stored_without_one(normalizer):
    with mock.patch.object(normalizer, "_table") as table:
        normalizer.handler(_batch(json.dumps(INSPECTOR_EVENT).encode()), None)
    item = table.put_item.call_args.kwargs["Item"]
    assert "queued_at" not in item and "stored_at" in item


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
    with mock.patch.object(normalizer, "_FAILED_QUEUE_URL", None), \
            mock.patch.object(normalizer, "_table"):
        result = normalizer.handler({"Records": [{"kinesis": {}}]}, None)

    assert result == {"batchItemFailures": []}
    (line,) = _metric_lines(capsys)
    assert (line["RecordsReceived"], line["RecordsFailed"], line["RecordsRejected"]) == (1, 1, 0)


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
    assert (line["RecordsReceived"], line["RecordsFailed"], line["RecordsRejected"]) == (1, 0, 0)


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
    assert declared == {"RecordsReceived", "RecordsFailed", "RecordsRejected"}
    for name in declared:
        assert isinstance(line[name], int)
    assert all(m["Unit"] == "Count" for m in spec["Metrics"])
    assert isinstance(line["_aws"]["Timestamp"], int)
