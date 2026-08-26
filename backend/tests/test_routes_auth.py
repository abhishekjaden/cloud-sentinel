"""
Route-level authorization.

Frontend authentication is cosmetic unless the API refuses unauthenticated
callers, so every data route is asserted to reject them. /health must stay open
because the load balancer's health check is unauthenticated.
"""
import pytest

DATA_ROUTES = [
    ("get", "/findings"),
    ("get", "/findings/guardduty%23111122223333"),
    ("get", "/stats"),
    ("get", "/remediations"),
]


@pytest.mark.parametrize("method,path", DATA_ROUTES)
def test_data_routes_reject_unauthenticated_callers(client, method, path):
    resp = getattr(client, method)(path)
    assert resp.status_code == 401, f"{path} should require authentication"
    assert "detail" in resp.json()


def test_predict_rejects_unauthenticated_callers(client):
    resp = client.post("/predict", json={"features": [0.0] * 78})
    assert resp.status_code == 401


def test_health_is_open_for_the_load_balancer(client):
    """The ALB health check presents no credentials; requiring auth here would
    take the service permanently out ofrotation."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "healthy", "service": "cloudsentinel-api"}


def test_unauthenticated_response_does_not_leak_data(client):
    """A rejection must not return finding data in the body."""
    body = client.get("/stats").text.lower()
    assert "severity_bucket" not in body
    assert "total" not in body
