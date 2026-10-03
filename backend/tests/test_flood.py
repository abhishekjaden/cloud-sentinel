"""
Tests for the findings flood.

A flood finding has to pass through the real normalizer as a real finding
would and be removable afterwards without touching anything else, so the
tests run the normalizer over one, and drive the sender and the purge against
stand-ins for the stream and the tables.
"""
import importlib.util
import json
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with mock.patch("boto3.resource"), mock.patch("boto3.client"):
        spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def flood():
    return _load("flood_findings", ROOT / "scripts" / "flood_findings.py")


@pytest.fixture(scope="module")
def normalizer():
    return _load("normalizer_handler", ROOT / "cdk" / "lambda" / "normalizer" / "handler.py")


def test_a_flood_finding_is_a_low_severity_guardduty_finding_the_normalizer_accepts(flood, normalizer):
    event = flood.finding("ab2c", 7, resources=50)
    out = normalizer._normalize(event)
    assert out["source"] == "guardduty" and out["account_id"] == flood.ACCOUNT
    assert out["finding_id"] == "flood-ab2c-000007"
    assert out["severity"] < 40, "a flood finding must stay below the remediation threshold"
    assert out["title"].startswith("[flood] ")
    assert json.loads(out["resource"])["instanceDetails"]["instanceId"].startswith("i-0f100d")
    # Its remote address is a documentation one: the enricher never looks it up.
    assert out["indicators"] is None
    with mock.patch.object(normalizer, "_table") as table:
        normalizer._persist(out)
    assert table.put_item.call_args.kwargs["Item"]["pk"] == f"guardduty#{flood.ACCOUNT}"


def test_findings_spread_over_the_resources_and_types_asked_for(flood):
    events = [flood.finding("r", n, resources=3) for n in range(12)]
    instances = {e["detail"]["resource"]["instanceDetails"]["instanceId"] for e in events}
    types = {e["detail"]["type"] for e in events}
    assert len(instances) == 3 and len(types) == len(flood.TYPES)
    assert len({e["detail"]["id"] for e in events}) == 12


def test_the_sender_batches_by_five_hundred_and_resends_what_the_stream_refused(flood):
    events = [flood.finding("r", n, resources=5) for n in range(1200)]
    calls = []

    class Kinesis:
        def put_records(self, StreamName, Records):
            calls.append(len(Records))
            assert StreamName == flood.STREAM and len(Records) <= flood.BATCH
            # The first batch has two throttled records; everything else lands.
            results = [{"SequenceNumber": "1"} for _ in Records]
            if len(calls) == 1:
                results[3] = results[9] = {"ErrorCode": "ProvisionedThroughputExceededException"}
            return {"FailedRecordCount": sum(1 for r in results if "ErrorCode" in r), "Records": results}

    with mock.patch.object(flood.time, "sleep"):
        sent, resent, _ = flood.put_all(Kinesis(), events, rate=1e9, log=lambda *_: None)
    assert sent == 1200 and resent == 2
    assert calls == [500, 500, 202]  # the two refused records rejoin the queue ahead of the rest


def test_purge_removes_the_flood_partition_and_its_incidents_only(flood):
    deleted = {"findings": [], "incidents": [], "notes": []}

    class Writer:
        def __init__(self, sink): self.sink = sink
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def delete_item(self, Key): self.sink.append(Key)

    class Table:
        def __init__(self, name): self.name = name
        def batch_writer(self):
            return Writer({flood.FINDINGS_TABLE: deleted["findings"], flood.INCIDENTS_TABLE: deleted["incidents"],
                           flood.TRIAGE_TABLE: deleted["notes"]}[self.name])
        def query(self, **kwargs):
            assert kwargs["KeyConditionExpression"].get_expression()["values"][1] == f"guardduty#{flood.ACCOUNT}"
            return {"Items": [{"pk": f"guardduty#{flood.ACCOUNT}", "sk": f"t#flood-r-{n}"} for n in range(3)]}
        def scan(self, **kwargs):
            return {"Items": [{"incident_id": "flood-inc", "account_id": flood.ACCOUNT},
                              {"incident_id": "real-inc", "account_id": "111122223333"}]}

    class DynamoDB:
        def Table(self, name): return Table(name)

    removed = flood.purge(DynamoDB(), log=lambda *_: None)
    assert removed == {"findings": 3, "incidents": 1}
    assert deleted["incidents"] == [{"incident_id": "flood-inc"}]
    assert deleted["notes"] == [{"incident_id": "flood-inc"}]
    assert all(k["pk"] == f"guardduty#{flood.ACCOUNT}" for k in deleted["findings"])
