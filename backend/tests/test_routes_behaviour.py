"""
Route behaviour with AWS stubbed.

These pin the response contract the dashboard depends on: if a shape changes,
the frontend breaks silently in the browser rather than loudly here.
"""
from decimal import Decimal

SAMPLE_ITEMS = [
    {"pk": "guardduty#111122223333", "sk": "2026-01-01T00:00:00Z#f1",
     "finding_id": "f1", "source": "guardduty", "severity": Decimal("90"),
     "severity_bucket": "CRITICAL", "title": "C&C activity"},
    {"pk": "securityhub#111122223333", "sk": "2026-01-01T00:00:00Z#f2",
     "finding_id": "f2", "source": "securityhub", "severity": Decimal("40"),
     "severity_bucket": "MEDIUM", "title": "Public bucket"},
]


# ------------------------------------------------------------- query helpers
def _matched(kwargs):
    """The value a query's key condition matches on."""
    return kwargs["KeyConditionExpression"].get_expression()["values"][1]


def _answers(by_key, paged=False):
    """A stand-in for Table.query that answers each partition separately.

    With `paged`, every partition's items come back one per page, which is how
    DynamoDB returns a partition larger than a megabyte — and the shape that
    caught /stats summing a single page and calling it the table's total.
    """
    def answer(**kwargs):
        items = by_key.get(_matched(kwargs), [])
        start = kwargs.get("ExclusiveStartKey", {}).get("n", 0) if paged else 0
        page = items[start:start + 1] if paged else items
        resp = {"Count": len(page)} if kwargs.get("Select") == "COUNT" else {"Items": page}
        if paged and start + 1 < len(items):
            resp["LastEvaluatedKey"] = {"n": start + 1}
        return resp
    return answer


def _item(source, created, fid, bucket="HIGH"):
    return {"pk": f"{source}#111122223333", "sk": f"{created}#{fid}",
            "finding_id": fid, "source": source, "severity_bucket": bucket,
            "severity": Decimal("70"), "created_at": created}


# ------------------------------------------------------------------ /findings
def test_findings_returns_count_and_items(auth_client, fake_table):
    fake_table.query.side_effect = _answers({
        "guardduty": [SAMPLE_ITEMS[0]], "securityhub": [SAMPLE_ITEMS[1]],
    })
    body = auth_client.get("/findings").json()
    assert body["count"] == 2
    assert {f["finding_id"] for f in body["findings"]} == {"f1", "f2"}


def test_findings_asks_the_time_index_for_every_source_and_never_scans(auth_client, fake_table):
    """A source left out of the queries is a source missing from the dashboard,
    silently — its findings are in the table and in nobody's list."""
    from app.findings import SOURCES

    fake_table.query.side_effect = _answers({})
    auth_client.get("/findings")

    calls = fake_table.query.call_args_list
    assert {_matched(c.kwargs) for c in calls} == set(SOURCES)
    for call in calls:
        assert call.kwargs["IndexName"] == "source-time-index"
        assert call.kwargs["ScanIndexForward"] is False
    fake_table.scan.assert_not_called()


def test_findings_merges_the_sources_into_one_newest_first_list(auth_client, fake_table):
    """Each query returns one source in time order; the newest overall can be in
    any of them. The newest here belongs to the source queried last, so simply
    concatenating the answers would bury it — which is what the dashboard would
    do with it every time findings from an older source came back first."""
    fake_table.query.side_effect = _answers({
        "guardduty": [_item("guardduty", "2026-08-02T00:00:00Z", "gd2"),
                      _item("guardduty", "2026-08-01T00:00:00Z", "gd1")],
        "securityhub": [_item("securityhub", "2026-09-17T03:57:09Z", "sh1")],
    })
    body = auth_client.get("/findings").json()

    assert [f["finding_id"] for f in body["findings"]] == ["sh1", "gd2", "gd1"]


def test_findings_limit_applies_after_merging(auth_client, fake_table):
    fake_table.query.side_effect = _answers({
        "securityhub": [_item("securityhub", "2026-08-01T00:00:00Z", "old")],
        "guardduty": [_item("guardduty", "2026-09-17T00:00:00Z", "new")],
    })
    body = auth_client.get("/findings?limit=1").json()
    assert [f["finding_id"] for f in body["findings"]] == ["new"]


def test_findings_asks_each_source_for_a_whole_page(auth_client, fake_table):
    """Splitting the limit between the sources would be cheaper and wrong: the
    newest fifty findings can all belong to one source."""
    fake_table.query.side_effect = _answers({})
    auth_client.get("/findings?limit=50")
    assert {c.kwargs["Limit"] for c in fake_table.query.call_args_list} == {50}


def test_findings_severity_filter_uses_the_gsi(auth_client, fake_table):
    """Filtering must query the severity index, not scan the whole table —
    a scan would be correct but would not scale."""
    fake_table.query.return_value = {"Items": [SAMPLE_ITEMS[0]]}
    auth_client.get("/findings?severity_bucket=CRITICAL")
    fake_table.query.assert_called_once()
    assert fake_table.query.call_args.kwargs["IndexName"] == "severity-index"
    fake_table.scan.assert_not_called()


def test_findings_limit_is_bounded(auth_client, fake_table):
    """An unbounded limit would let one request pull the entire table."""
    fake_table.query.side_effect = _answers({})
    assert auth_client.get("/findings?limit=500").status_code == 422
    assert auth_client.get("/findings?limit=0").status_code == 422
    assert auth_client.get("/findings?limit=200").status_code == 200


def test_findings_surfaces_backend_failure_as_500(auth_client, fake_table):
    fake_table.query.side_effect = RuntimeError("dynamo unavailable")
    assert auth_client.get("/findings").status_code == 500


def test_missing_finding_returns_404(auth_client, fake_table):
    fake_table.query.return_value = {"Items": []}
    assert auth_client.get("/findings/nope%23123").status_code == 404


# --------------------------------------------------------------------- /stats
def test_stats_aggregates_by_bucket_and_source(auth_client, fake_table):
    fake_table.query.side_effect = _answers({
        "CRITICAL": [SAMPLE_ITEMS[0]], "MEDIUM": [SAMPLE_ITEMS[1]],
        "guardduty": [SAMPLE_ITEMS[0]], "securityhub": [SAMPLE_ITEMS[1]],
    })
    body = auth_client.get("/stats").json()
    assert body["total"] == 2
    assert body["by_severity_bucket"] == {"CRITICAL": 1, "MEDIUM": 1}
    assert body["by_source"] == {"guardduty": 1, "securityhub": 1}


def test_stats_counts_without_reading_the_findings(auth_client, fake_table):
    """Counting is what this route needs; the findings themselves are the part
    that grew with the table until a summary moved a megabyte to produce two
    numbers."""
    fake_table.query.side_effect = _answers({"HIGH": [SAMPLE_ITEMS[0]]})
    auth_client.get("/stats")

    assert fake_table.query.call_args_list
    for call in fake_table.query.call_args_list:
        assert call.kwargs["Select"] == "COUNT"
    fake_table.scan.assert_not_called()


def test_stats_counts_every_page_of_a_partition(auth_client, fake_table):
    """The regression this route had twice over: a count is paginated like any
    other query, and the first page is not the answer."""
    fake_table.query.side_effect = _answers({
        "MEDIUM": [_item("securityhub", "2026-08-0%d" % i, f"sh{i}", "MEDIUM") for i in (1, 2)],
        "CRITICAL": [_item("guardduty", "2026-09-17", "gd1", "CRITICAL")],
        "securityhub": [_item("securityhub", "2026-08-0%d" % i, f"sh{i}") for i in (1, 2)],
        "guardduty": [_item("guardduty", "2026-09-17", "gd1")],
    }, paged=True)
    body = auth_client.get("/stats").json()

    assert body["total"] == 3
    assert body["by_severity_bucket"] == {"CRITICAL": 1, "MEDIUM": 2}
    assert body["by_source"] == {"securityhub": 2, "guardduty": 1}


def test_stats_counts_every_bucket_and_source_the_normalizer_can_write(auth_client, fake_table):
    from app.findings import BUCKETS, SOURCES

    fake_table.query.side_effect = _answers({})
    auth_client.get("/stats")
    assert {_matched(c.kwargs) for c in fake_table.query.call_args_list} == {*BUCKETS, *SOURCES}


def test_stats_reports_nothing_for_an_empty_bucket_or_source(auth_client, fake_table):
    """The dashboard reads absence as zero and draws no slice for it; a table of
    five zeroes and one number would be new behaviour, not a summary."""
    fake_table.query.side_effect = _answers({"CRITICAL": [SAMPLE_ITEMS[0]],
                                             "guardduty": [SAMPLE_ITEMS[0]]})
    body = auth_client.get("/stats").json()
    assert body == {"total": 1, "by_severity_bucket": {"CRITICAL": 1},
                    "by_source": {"guardduty": 1}}


def test_stats_on_empty_table(auth_client, fake_table):
    fake_table.query.side_effect = _answers({})
    body = auth_client.get("/stats").json()
    assert body == {"total": 0, "by_severity_bucket": {}, "by_source": {}}


def test_stats_surfaces_backend_failure_as_500(auth_client, fake_table):
    fake_table.query.side_effect = RuntimeError("dynamo unavailable")
    assert auth_client.get("/stats").status_code == 500


# -------------------------------------------------------------------- /predict
def test_predict_rejects_wrong_feature_count(auth_client):
    """The model expects 78 CICFlowMeter features; anything else is a client
    error, not a 500."""
    resp = auth_client.post("/predict", json={"features": [0.0] * 40})
    assert resp.status_code in (400, 422, 500)
    assert resp.status_code != 200


def test_predict_rejects_missing_body(auth_client):
    assert auth_client.post("/predict", json={}).status_code == 422
