"""
Remediation route behaviour.

The dashboard's remediation panel reads this endpoint, and the SOAR loop's
value depends on an operator being able to see executions that are waiting on
their approval. RUNNING executions must therefore always be surfaced.
"""
from datetime import datetime


def _execution(name, status, started="2026-01-01T00:00:00Z"):
    return {
        "name": name,
        "status": status,
        "startDate": datetime.fromisoformat(started.replace("Z", "+00:00")),
        "stopDate": None,
        "executionArn": f"arn:aws:states:us-east-1:111122223333:execution:test:{name}",
        "stateMachineArn": "arn:aws:states:us-east-1:111122223333:stateMachine:test",
    }


def test_remediations_returns_count_summary_and_executions(auth_client, fake_sfn):
    fake_sfn.list_executions.return_value = {"executions": [
        _execution("e1", "RUNNING"),
        _execution("e2", "SUCCEEDED"),
        _execution("e3", "RUNNING"),
    ]}
    body = auth_client.get("/remediations").json()
    assert body["count"] == 3
    assert body["summary"]["RUNNING"] == 2
    assert body["summary"]["SUCCEEDED"] == 1
    assert len(body["executions"]) == 3


def test_running_executions_are_surfaced(auth_client, fake_sfn):
    """A RUNNING execution is one awaiting human approval; if the API hid these
    the approval gate would be invisible to the operator."""
    fake_sfn.list_executions.return_value = {"executions": [_execution("waiting", "RUNNING")]}
    body = auth_client.get("/remediations").json()
    assert body["summary"] == {"RUNNING": 1}
    assert body["executions"][0]["status"] == "RUNNING"


def test_remediations_with_no_executions(auth_client, fake_sfn):
    fake_sfn.list_executions.return_value = {"executions": []}
    body = auth_client.get("/remediations").json()
    assert body["count"] == 0
    assert body["summary"] == {}
    assert body["executions"] == []


def test_remediations_limit_is_bounded(auth_client, fake_sfn):
    fake_sfn.list_executions.return_value = {"executions": []}
    assert auth_client.get("/remediations?limit=500").status_code == 422
    assert auth_client.get("/remediations?limit=0").status_code == 422
    assert auth_client.get("/remediations?limit=100").status_code == 200


def test_remediations_surfaces_backend_failure_as_500(auth_client, fake_sfn):
    fake_sfn.list_executions.side_effect = RuntimeError("step functions unavailable")
    assert auth_client.get("/remediations").status_code == 500
