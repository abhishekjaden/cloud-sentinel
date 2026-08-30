"""
Approval route behaviour.

These tests exist because of a finding in docs/threat-model.md: while the task
token was emailed, anyone with mailbox access could resume a destructive
workflow without authenticating. Routing the decision through the API is only
a fix if the API actually enforces authentication and records who decided.
"""
import pytest

PENDING = {
    "approval_id": "a-1",
    "task_token": "AAAAK-secret-token",
    "status": "pending",
    "created_at": "2026-01-01T00:00:00Z",
    "finding_id": "f-1",
    "playbook": "ec2_compromise",
}


def test_listing_approvals_requires_authentication(client):
    assert client.get("/approvals").status_code == 401


def test_deciding_requires_authentication(client):
    """The central assertion: an unauthenticated caller cannot resume a
    remediation, however well-formed the request."""
    resp = client.post("/approvals/a-1/decide", json={"decision": "approve"})
    assert resp.status_code == 401


def test_task_token_is_never_returned_to_a_client(auth_client, fake_table):
    """Returning the token would reintroduce the exact weakness this design
    removes."""
    fake_table.query.return_value = {"Items": [PENDING]}
    body = auth_client.get("/approvals").json()
    assert body["count"] == 1
    assert "task_token" not in body["approvals"][0]
    assert "AAAAK-secret-token" not in auth_client.get("/approvals").text


def test_approval_records_the_deciding_principal(auth_client, fake_table, fake_sfn):
    """Attribution is the reason this route exists: the audit trail must name a
    principal, not merely record that an approval occurred."""
    fake_table.get_item.return_value = {"Item": dict(PENDING)}
    body = auth_client.post("/approvals/a-1/decide",
                            json={"decision": "approve"}).json()
    assert body["status"] == "approved"
    assert body["decided_by"] == "test-operator"
    fake_sfn.send_task_success.assert_called_once()
    assert fake_sfn.send_task_success.call_args.kwargs["taskToken"] == "AAAAK-secret-token"


def test_rejection_fails_the_workflow(auth_client, fake_table, fake_sfn):
    fake_table.get_item.return_value = {"Item": dict(PENDING)}
    body = auth_client.post("/approvals/a-1/decide",
                            json={"decision": "reject"}).json()
    assert body["status"] == "rejected"
    fake_sfn.send_task_failure.assert_called_once()
    fake_sfn.send_task_success.assert_not_called()


def test_an_already_decided_approval_cannot_be_replayed(auth_client, fake_table, fake_sfn):
    """Without this, a second call could resume a workflow that was rejected."""
    decided = dict(PENDING, status="approved", decided_by="someone-else")
    fake_table.get_item.return_value = {"Item": decided}
    resp = auth_client.post("/approvals/a-1/decide", json={"decision": "approve"})
    assert resp.status_code == 409
    assert "someone-else" in resp.json()["detail"]
    fake_sfn.send_task_success.assert_not_called()


def test_unknown_approval_returns_404(auth_client, fake_table):
    fake_table.get_item.return_value = {}
    assert auth_client.post("/approvals/nope/decide",
                            json={"decision": "approve"}).status_code == 404


@pytest.mark.parametrize("payload", [
    {"decision": "maybe"}, {"decision": ""}, {}, {"decision": "APPROVE; DROP TABLE"},
])
def test_only_approve_or_reject_are_accepted(auth_client, fake_table, payload):
    fake_table.get_item.return_value = {"Item": dict(PENDING)}
    assert auth_client.post("/approvals/a-1/decide", json=payload).status_code == 422
