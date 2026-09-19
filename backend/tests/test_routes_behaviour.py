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


# ------------------------------------------------------------------ /findings
def test_findings_returns_count_and_items(auth_client, fake_table):
    fake_table.scan.return_value = {"Items": SAMPLE_ITEMS}
    body = auth_client.get("/findings").json()
    assert body["count"] == 2
    assert {f["finding_id"] for f in body["findings"]} == {"f1", "f2"}


def _paged(*pages):
    """Scan responses split across pages, as DynamoDB returns them past 1 MB."""
    out = []
    for i, items in enumerate(pages):
        page = {"Items": items}
        if i < len(pages) - 1:
            page["LastEvaluatedKey"] = {"pk": f"page-{i}", "sk": "x"}
        out.append(page)
    return out


def _item(source, created, fid, bucket="HIGH"):
    return {"pk": f"{source}#111122223333", "sk": f"{created}#{fid}",
            "finding_id": fid, "source": source, "severity_bucket": bucket,
            "severity": Decimal("70"), "created_at": created}


def test_findings_reads_every_page_and_returns_most_recent_first(auth_client, fake_table):
    """Findings are partitioned by source, so the first scan page is one source.
    The newest finding sits on the second page and must still come first."""
    fake_table.scan.side_effect = _paged(
        [_item("securityhub", "2026-08-01T00:00:00Z", "sh1"),
         _item("securityhub", "2026-08-02T00:00:00Z", "sh2")],
        [_item("guardduty", "2026-09-17T03:57:09Z", "gd1")],
    )
    body = auth_client.get("/findings").json()

    assert [f["finding_id"] for f in body["findings"]] == ["gd1", "sh2", "sh1"]
    assert fake_table.scan.call_count == 2


def test_findings_limit_applies_after_ordering(auth_client, fake_table):
    fake_table.scan.side_effect = _paged(
        [_item("securityhub", "2026-08-01T00:00:00Z", "old")],
        [_item("guardduty", "2026-09-17T00:00:00Z", "new")],
    )
    body = auth_client.get("/findings?limit=1").json()
    assert [f["finding_id"] for f in body["findings"]] == ["new"]


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
    fake_table.scan.return_value = {"Items": []}
    assert auth_client.get("/findings?limit=500").status_code == 422
    assert auth_client.get("/findings?limit=0").status_code == 422
    assert auth_client.get("/findings?limit=200").status_code == 200


def test_findings_surfaces_backend_failure_as_500(auth_client, fake_table):
    fake_table.scan.side_effect = RuntimeError("dynamo unavailable")
    assert auth_client.get("/findings").status_code == 500


def test_missing_finding_returns_404(auth_client, fake_table):
    fake_table.query.return_value = {"Items": []}
    assert auth_client.get("/findings/nope%23123").status_code == 404


# --------------------------------------------------------------------- /stats
def test_stats_aggregates_by_bucket_and_source(auth_client, fake_table):
    fake_table.scan.return_value = {"Items": SAMPLE_ITEMS}
    body = auth_client.get("/stats").json()
    assert body["total"] == 2
    assert body["by_severity_bucket"] == {"CRITICAL": 1, "MEDIUM": 1}
    assert body["by_source"] == {"guardduty": 1, "securityhub": 1}


def test_stats_counts_every_page_of_the_table(auth_client, fake_table):
    """The regression: one scan call returned only the first 1 MB, so the
    dashboard reported a single page as the table's total."""
    fake_table.scan.side_effect = _paged(
        [_item("securityhub", "2026-08-01T00:00:00Z", "sh1", "MEDIUM"),
         _item("securityhub", "2026-08-02T00:00:00Z", "sh2", "MEDIUM")],
        [_item("guardduty", "2026-09-17T00:00:00Z", "gd1", "CRITICAL")],
    )
    body = auth_client.get("/stats").json()

    assert body["total"] == 3
    assert body["by_source"] == {"securityhub": 2, "guardduty": 1}
    second_call = fake_table.scan.call_args_list[1].kwargs
    assert second_call["ExclusiveStartKey"] == {"pk": "page-0", "sk": "x"}


def test_stats_handles_items_missing_fields(auth_client, fake_table):
    """Malformed rows must not break the dashboard's summary."""
    fake_table.scan.return_value = {"Items": [{"pk": "x"}]}
    body = auth_client.get("/stats").json()
    assert body["by_severity_bucket"] == {"UNKNOWN": 1}
    assert body["by_source"] == {"unknown": 1}


def test_stats_on_empty_table(auth_client, fake_table):
    fake_table.scan.return_value = {"Items": []}
    body = auth_client.get("/stats").json()
    assert body == {"total": 0, "by_severity_bucket": {}, "by_source": {}}


# -------------------------------------------------------------------- /predict
def test_predict_rejects_wrong_feature_count(auth_client):
    """The model expects 78 CICFlowMeter features; anything else is a client
    error, not a 500."""
    resp = auth_client.post("/predict", json={"features": [0.0] * 40})
    assert resp.status_code in (400, 422, 500)
    assert resp.status_code != 200


def test_predict_rejects_missing_body(auth_client):
    assert auth_client.post("/predict", json={}).status_code == 422
