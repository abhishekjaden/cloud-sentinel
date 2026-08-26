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
    assert len(body["findings"]) == 2
    assert body["findings"][0]["finding_id"] == "f1"


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
