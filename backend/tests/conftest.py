"""
Shared fixtures.

The route modules build their boto3 clients at import time, so AWS must be
stubbed before app.main is imported. Every test therefore goes through the
`client` fixture rather than importing the app directly.
"""
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("COGNITO_USER_POOL_ID", "us-east-1_testpool")
os.environ.setdefault("COGNITO_CLIENT_ID", "test-client-id")
os.environ.setdefault("AUTH_ENABLED", "true")
os.environ.setdefault("ML_BUCKET", "test-models-bucket")
os.environ.setdefault("STATE_MACHINE_ARN",
                      "arn:aws:states:us-east-1:111122223333:stateMachine:test")


@pytest.fixture
def fake_table():
    """Stands in for the DynamoDB Table the findings routes hold at module scope."""
    return mock.MagicMock()


@pytest.fixture
def fake_sfn():
    """Stands in for the Step Functions client used by the remediations route."""
    return mock.MagicMock()


@pytest.fixture
def app_module(fake_table, fake_sfn):
    """Import the FastAPI app with AWS stubbed out."""
    for mod in list(sys.modules):
        if mod.startswith("app."):
            del sys.modules[mod]

    resource = mock.MagicMock()
    resource.return_value.Table.return_value = fake_table

    with mock.patch("boto3.resource", resource), \
         mock.patch("boto3.client", return_value=fake_sfn):
        import app.main as main
        yield main


@pytest.fixture
def client(app_module):
    """Unauthenticated client — auth is enforced."""
    from fastapi.testclient import TestClient
    return TestClient(app_module.app)


@pytest.fixture
def auth_client(app_module):
    """Client with authentication satisfied, for testing route behaviour."""
    from fastapi.testclient import TestClient
    from app.auth import require_auth
    app_module.app.dependency_overrides[require_auth] = lambda: {"sub": "test-operator"}
    yield TestClient(app_module.app)
    app_module.app.dependency_overrides.clear()
