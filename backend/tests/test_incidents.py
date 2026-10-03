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


# ------------------------------------------------------------------ triage
# Notes come from a language model, so the API passes on only the fields the
# triage function validated, and treats the whole feature as optional: a note
# that cannot be read must never cost the analyst the incidents themselves.
NOTE = {
    "incident_id": "a", "status": "complete", "fingerprint": "f" * 64,
    "summary": "Recon followed by initial access on i-0abc.",
    "assessed_severity": "high", "confidence": "medium",
    "likely_test_data": False, "injection_suspected": False,
    "reasons": ["Two stages within minutes."], "next_steps": ["Review SSH logs."],
    "model_id": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "prompt_version": "2026-09-20.1", "triaged_at": "2026-09-20T15:00:00+00:00",
    "input_tokens": Decimal("900"), "output_tokens": Decimal("120"),
}


def _dynamodb(app_module):
    """The DynamoDB resource the incidents route holds, as stubbed by conftest."""
    import app.incidents
    return app.incidents._dynamodb


def test_each_incident_carries_its_triage_note(auth_client, app_module, fake_table):
    fake_table.scan.return_value = {"Items": [REAL, SAMPLE_EC2]}
    _dynamodb(app_module).batch_get_item.return_value = {
        "Responses": {"cloudsentinel-triage": [NOTE]}}

    incidents = _by_id(auth_client.get("/incidents").json())

    assert incidents["a"]["triage"]["summary"] == NOTE["summary"]
    assert incidents["a"]["triage"]["next_steps"] == ["Review SSH logs."]
    assert incidents["b"]["triage"] is None


def test_only_the_notes_display_fields_leave_the_server(auth_client, app_module, fake_table):
    fake_table.scan.return_value = {"Items": [REAL]}
    _dynamodb(app_module).batch_get_item.return_value = {
        "Responses": {"cloudsentinel-triage": [NOTE]}}

    note = auth_client.get("/incidents").json()["incidents"][0]["triage"]

    assert set(note) == {"status", "summary", "assessed_severity", "confidence",
                         "likely_test_data", "injection_suspected", "reasons",
                         "next_steps", "model_id", "triaged_at"}


def test_a_rejected_note_shows_only_that_it_was_rejected(auth_client, app_module, fake_table):
    fake_table.scan.return_value = {"Items": [REAL]}
    _dynamodb(app_module).batch_get_item.return_value = {"Responses": {"cloudsentinel-triage": [
        {"incident_id": "a", "status": "invalid_output", "triaged_at": "2026-09-20T15:00:00+00:00",
         "summary": "should never be shown"}]}}

    note = auth_client.get("/incidents").json()["incidents"][0]["triage"]

    assert note == {"status": "invalid_output", "triaged_at": "2026-09-20T15:00:00+00:00"}


def test_incidents_are_served_when_notes_cannot_be_read(auth_client, app_module, fake_table):
    fake_table.scan.return_value = {"Items": [REAL, SAMPLE_EC2]}
    _dynamodb(app_module).batch_get_item.side_effect = RuntimeError("AccessDenied")

    response = auth_client.get("/incidents")

    assert response.status_code == 200
    assert [i["triage"] for i in response.json()["incidents"]] == [None, None]


def test_notes_are_requested_a_hundred_keys_at_a_time(auth_client, app_module, fake_table):
    many = [_incident(f"i{n:03}", "i-0abc", f"2026-09-10T00:00:{n % 60:02}+00:00", ["impact"])
            for n in range(150)]
    fake_table.scan.return_value = {"Items": many}
    batch = _dynamodb(app_module).batch_get_item
    batch.return_value = {"Responses": {}}

    auth_client.get("/incidents?limit=150")

    sizes = [len(c.kwargs["RequestItems"]["cloudsentinel-triage"]["Keys"])
             for c in batch.call_args_list]
    assert sizes == [100, 50]


def test_unprocessed_keys_are_retried_then_given_up_on(auth_client, app_module, fake_table):
    fake_table.scan.return_value = {"Items": [REAL]}
    stuck = {"cloudsentinel-triage": {"Keys": [{"incident_id": "a"}]}}
    batch = _dynamodb(app_module).batch_get_item
    batch.return_value = {"Responses": {}, "UnprocessedKeys": stuck}

    response = auth_client.get("/incidents")

    assert response.status_code == 200
    assert batch.call_count == 3
    assert response.json()["incidents"][0]["triage"] is None


# -------------------------------------------------------------- threat intel
VERDICT = {"indicator": "ip:185.220.101.4", "kind": "ip", "value": "185.220.101.4", "verdict": "malicious",
           "abuseipdb": {"confidence": Decimal(100), "reports": Decimal(412), "country": "DE",
                         "isp": "Example Hosting GmbH", "tor": True, "last_reported_at": "2026-10-02T21:14:09+00:00"},
           "otx": {"pulses": Decimal(7)}, "providers_asked": ["abuseipdb", "otx"], "providers_failed": [],
           "looked_up_at": "2026-10-03T06:00:00+00:00", "expires_at": Decimal(2 ** 40)}


def _with_indicators(incident, ips=(), domains=()):
    return {**incident, "indicators": {"ips": list(ips), "domains": list(domains)}}


def _serve_tables(app_module, notes=(), verdicts=()):
    """The shared BatchGetItem stub answers for whichever table was asked."""
    def answer(RequestItems):
        (table,) = RequestItems
        rows = {"cloudsentinel-triage": notes, "cloudsentinel-intel": verdicts}[table]
        return {"Responses": {table: list(rows)}}
    _dynamodb(app_module).batch_get_item.side_effect = answer


def test_each_incident_carries_the_verdicts_on_its_own_indicators(auth_client, app_module, fake_table):
    fake_table.scan.return_value = {"Items": [
        _with_indicators(REAL, ips=["185.220.101.4", "45.33.32.156"], domains=["evil.example.net"]),
        _with_indicators(SAMPLE_EC2, ips=["45.33.32.156"]),
    ]}
    _serve_tables(app_module, verdicts=[VERDICT])

    incidents = _by_id(auth_client.get("/incidents").json())

    assert set(incidents["a"]["intel"]) == {"185.220.101.4"}  # the others await a lookup
    verdict = incidents["a"]["intel"]["185.220.101.4"]
    assert verdict["verdict"] == "malicious" and verdict["abuseipdb"]["confidence"] == 100
    assert verdict["otx"] == {"pulses": 7}
    assert "expires_at" not in verdict
    assert incidents["b"]["intel"] == {}


def test_an_attacker_s_address_is_read_once_for_all_incidents(auth_client, app_module, fake_table):
    fake_table.scan.return_value = {"Items": [
        _with_indicators(REAL, ips=["185.220.101.4"]), _with_indicators(SAMPLE_EC2, ips=["185.220.101.4"])]}
    _serve_tables(app_module, verdicts=[VERDICT])

    incidents = _by_id(auth_client.get("/incidents").json())

    calls = [c.kwargs["RequestItems"] for c in _dynamodb(app_module).batch_get_item.call_args_list]
    intel_calls = [c["cloudsentinel-intel"]["Keys"] for c in calls if "cloudsentinel-intel" in c]
    assert intel_calls == [[{"indicator": "ip:185.220.101.4"}]]
    assert incidents["a"]["intel"]["185.220.101.4"]["verdict"] == "malicious"
    assert incidents["b"]["intel"]["185.220.101.4"]["verdict"] == "malicious"


def test_incidents_without_indicators_ask_the_intel_table_nothing(auth_client, app_module, fake_table):
    fake_table.scan.return_value = {"Items": [REAL]}
    _serve_tables(app_module)

    body = auth_client.get("/incidents").json()

    assert body["incidents"][0]["intel"] == {}
    tables = [next(iter(c.kwargs["RequestItems"])) for c in _dynamodb(app_module).batch_get_item.call_args_list]
    assert "cloudsentinel-intel" not in tables


def test_incidents_are_served_when_verdicts_cannot_be_read(auth_client, app_module, fake_table):
    fake_table.scan.return_value = {"Items": [_with_indicators(REAL, ips=["185.220.101.4"])]}

    def answer(RequestItems):
        if "cloudsentinel-intel" in RequestItems:
            raise RuntimeError("AccessDenied")
        return {"Responses": {}}
    _dynamodb(app_module).batch_get_item.side_effect = answer

    response = auth_client.get("/incidents")

    assert response.status_code == 200
    assert response.json()["incidents"][0]["intel"] == {}
