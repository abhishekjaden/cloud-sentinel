"""
/incidents behaviour with AWS stubbed.

The dashboard's incidents panel depends on this contract: the order an analyst
sees attacks in, the bound on how much one request can pull, and which
incidents are marked as built from GuardDuty sample data.
"""
from decimal import Decimal


def _incident(iid, resource, last_seen, stages, status="open"):
    return {
        "incident_id": iid, "resource": resource, "status": status,
        "first_seen": last_seen, "last_seen": last_seen,
        "finding_count": Decimal(len(stages)), "max_severity": Decimal("80"),
        "attack_stages": stages, "multi_stage": len(stages) > 1,
    }


REAL = _incident("a", "i-0abc", "2026-09-10T00:00:00+00:00",
                 ["reconnaissance", "initial-access"])
SAMPLE_EC2 = _incident("b", "i-99999999", "2026-09-17T03:57:09+00:00", ["impact"])
SAMPLE_KEY = _incident("c", "GeneratedFindingAccessKeyId",
                       "2026-09-12T00:00:00+00:00", ["credential-access", "exfiltration"])


def _by_id(body):
    return {i["incident_id"]: i for i in body["incidents"]}


def test_returns_count_multi_stage_total_and_incidents(auth_client, fake_table):
    fake_table.scan.return_value = {"Items": [REAL, SAMPLE_EC2, SAMPLE_KEY]}
    body = auth_client.get("/incidents").json()

    assert body["count"] == 3
    assert body["multi_stage"] == 2
    assert _by_id(body)["a"]["attack_stages"] == ["reconnaissance", "initial-access"]


def test_most_recent_activity_comes_first(auth_client, fake_table):
    fake_table.scan.return_value = {"Items": [REAL, SAMPLE_EC2, SAMPLE_KEY]}
    body = auth_client.get("/incidents").json()
    assert [i["incident_id"] for i in body["incidents"]] == ["b", "c", "a"]


def test_every_page_is_read(auth_client, fake_table):
    """An unpaginated scan is how /stats came to report one page as the table."""
    fake_table.scan.side_effect = [
        {"Items": [REAL], "LastEvaluatedKey": {"incident_id": "a"}},
        {"Items": [SAMPLE_EC2]},
    ]
    body = auth_client.get("/incidents").json()

    assert body["count"] == 2
    assert fake_table.scan.call_args_list[1].kwargs["ExclusiveStartKey"] == {"incident_id": "a"}


def test_incidents_built_from_guardduty_samples_are_labelled_not_hidden(auth_client, fake_table):
    fake_table.scan.return_value = {"Items": [REAL, SAMPLE_EC2, SAMPLE_KEY]}
    incidents = _by_id(auth_client.get("/incidents").json())

    assert incidents["a"]["sample"] is False
    assert incidents["b"]["sample"] is True     # the EC2 placeholder instance
    assert incidents["c"]["sample"] is True     # GeneratedFinding* placeholders
    assert len(incidents) == 3


def test_status_filter_queries_the_status_index_newest_first(auth_client, fake_table):
    fake_table.query.return_value = {"Items": [REAL]}
    body = auth_client.get("/incidents?status=open").json()

    assert body["count"] == 1
    kwargs = fake_table.query.call_args.kwargs
    assert kwargs["IndexName"] == "status-index"
    assert kwargs["ScanIndexForward"] is False
    fake_table.scan.assert_not_called()


def test_status_query_follows_pages_and_stops_once_the_limit_is_met(auth_client, fake_table):
    fake_table.query.side_effect = [
        {"Items": [SAMPLE_EC2], "LastEvaluatedKey": {"incident_id": "b"}},
        {"Items": [SAMPLE_KEY], "LastEvaluatedKey": {"incident_id": "c"}},
        {"Items": [REAL]},
    ]
    body = auth_client.get("/incidents?status=open&limit=2").json()

    assert [i["incident_id"] for i in body["incidents"]] == ["b", "c"]
    assert fake_table.query.call_count == 2          # the third page is never read
    assert fake_table.query.call_args.kwargs["ExclusiveStartKey"] == {"incident_id": "b"}


def test_status_filter_accepts_only_known_statuses(auth_client, fake_table):
    fake_table.query.return_value = {"Items": []}
    assert auth_client.get("/incidents?status=closed").status_code == 200
    assert auth_client.get("/incidents?status=deleted").status_code == 422


def test_limit_is_bounded(auth_client, fake_table):
    fake_table.scan.return_value = {"Items": []}
    assert auth_client.get("/incidents?limit=0").status_code == 422
    assert auth_client.get("/incidents?limit=500").status_code == 422
    assert auth_client.get("/incidents?limit=200").status_code == 200


def test_limit_applies_after_ordering(auth_client, fake_table):
    fake_table.scan.return_value = {"Items": [REAL, SAMPLE_EC2, SAMPLE_KEY]}
    body = auth_client.get("/incidents?limit=1").json()
    assert [i["incident_id"] for i in body["incidents"]] == ["b"]


def test_empty_table(auth_client, fake_table):
    fake_table.scan.return_value = {"Items": []}
    assert auth_client.get("/incidents").json() == {
        "count": 0, "multi_stage": 0, "incidents": []}


def test_backend_failure_is_a_500(auth_client, fake_table):
    fake_table.scan.side_effect = RuntimeError("dynamo unavailable")
    assert auth_client.get("/incidents").status_code == 500
