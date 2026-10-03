"""
/predict, exercised against real but tiny XGBoost models.

The models are trained here, on a few hundred random rows whose labels follow
one feature each, so the route runs the same code path it runs in production:
two boosters and a label map fetched from the bucket, a verdict from one and a
family from the other. What is pinned is the contract — verdict from the binary
model against the threshold, family from the multiclass one with its
probability, the two reported side by side even when they disagree — not the
models' accuracy, which the model card covers.
"""
import json
import shutil

import numpy as np
import pytest
import xgboost as xgb

N_FEATURES = 78
CLASSES = ["BENIGN", "Bot", "BruteForce", "DDoS", "DoS", "Infiltration", "PortScan", "WebAttack"]
KEYS = ("binary_model.json", "multiclass_model.json", "label_classes.json")


@pytest.fixture(scope="module")
def artefacts(tmp_path_factory):
    """The three files the models bucket holds, from one tiny training run.

    The verdict follows feature 0 and the family follows feature 1, so a flow
    can be an attack to one model and benign to the other — the disagreement
    the route has to report rather than hide."""
    rng = np.random.default_rng(0)
    x = rng.random((600, N_FEATURES)).astype(np.float32)
    y_binary = (x[:, 0] > 0.5).astype(int)
    y_family = np.where(x[:, 1] < 0.5, 0, 1 + np.minimum((x[:, 1] - 0.5) * 14, 6).astype(int))

    out = tmp_path_factory.mktemp("models")
    xgb.train({"objective": "binary:logistic", "max_depth": 3, "seed": 0},
              xgb.DMatrix(x, y_binary), 30).save_model(str(out / "binary_model.json"))
    xgb.train({"objective": "multi:softprob", "num_class": len(CLASSES), "max_depth": 3, "seed": 0},
              xgb.DMatrix(x, y_family), 30).save_model(str(out / "multiclass_model.json"))
    (out / "label_classes.json").write_text(json.dumps(CLASSES), encoding="utf-8")
    return out


@pytest.fixture
def bucket(fake_sfn, artefacts):
    """The stubbed boto3 client serves the artefacts as S3 would, by key."""
    fake_sfn.download_file.side_effect = lambda _bucket, key, path: shutil.copy(artefacts / key, path)
    return fake_sfn


def flow(verdict_feature, family_feature):
    features = [0.5] * N_FEATURES
    features[0], features[1] = verdict_feature, family_feature
    return {"features": features}


def test_the_verdict_and_the_family_come_from_different_models(auth_client, bucket):
    body = auth_client.post("/predict", json=flow(0.95, 0.95)).json()
    assert body["prediction"] == "ATTACK"
    assert body["attack_probability"] >= body["threshold"] == 0.5
    assert body["attack_family"] == "WebAttack"
    assert set(body["family_probabilities"]) == set(CLASSES)
    assert body["family_probability"] == max(body["family_probabilities"].values())
    assert body["family_probabilities"]["WebAttack"] == body["family_probability"]
    assert abs(sum(body["family_probabilities"].values()) - 1) < 0.01


def test_a_disagreement_between_the_models_is_reported_not_reconciled(auth_client, bucket):
    """The binary model is the one evaluated for the verdict, so the verdict
    stands; the family model's dissent is visible beside it, not overwritten."""
    body = auth_client.post("/predict", json=flow(0.95, 0.05)).json()
    assert body["prediction"] == "ATTACK"
    assert body["attack_family"] == "BENIGN"

    body = auth_client.post("/predict", json=flow(0.05, 0.95)).json()
    assert body["prediction"] == "BENIGN"
    assert body["attack_family"] == "WebAttack"


def test_the_threshold_decides_the_verdict_not_the_probability(auth_client, bucket):
    strict = auth_client.post("/predict?threshold=1.0", json=flow(0.95, 0.5)).json()
    lax = auth_client.post("/predict?threshold=0.0", json=flow(0.05, 0.5)).json()
    assert strict["prediction"] == "BENIGN" and strict["threshold"] == 1.0
    assert lax["prediction"] == "ATTACK" and lax["threshold"] == 0.0


def test_the_wrong_number_of_features_is_the_caller_s_error(auth_client, bucket):
    resp = auth_client.post("/predict", json={"features": [0.0] * 40})
    assert resp.status_code == 400
    assert resp.json()["detail"] == f"expected {N_FEATURES} features, got 40"


def test_a_missing_body_is_rejected_before_any_model_is_touched(auth_client, bucket):
    assert auth_client.post("/predict", json={}).status_code == 422
    bucket.download_file.assert_not_called()


def test_the_artefacts_are_fetched_once_from_the_configured_bucket(auth_client, bucket):
    for _ in range(3):
        assert auth_client.post("/predict", json=flow(0.5, 0.5)).status_code == 200
    fetched = [(call.args[0], call.args[1]) for call in bucket.download_file.call_args_list]
    assert fetched == [("test-models-bucket", key) for key in KEYS]


def test_models_trained_on_different_features_are_refused(auth_client, fake_sfn, artefacts, tmp_path):
    """One model from a new training run beside one from the old is the easy
    deployment mistake; the models would score different columns as the same
    flow and nothing in the output would show it."""
    x = np.random.default_rng(1).random((100, N_FEATURES - 1)).astype(np.float32)
    narrower = tmp_path / "multiclass_model.json"
    xgb.train({"objective": "multi:softprob", "num_class": len(CLASSES), "seed": 0},
              xgb.DMatrix(x, x[:, 0] * 0), 2).save_model(str(narrower))

    def serve(_bucket, key, path):
        shutil.copy(narrower if key == "multiclass_model.json" else artefacts / key, path)
    fake_sfn.download_file.side_effect = serve

    resp = auth_client.post("/predict", json=flow(0.5, 0.5))
    assert resp.status_code == 500
    assert "disagree on feature count" in resp.json()["detail"]


def test_a_label_map_that_does_not_fit_the_model_fails_loudly(auth_client, fake_sfn, artefacts, tmp_path):
    """Seven names for an eight-class model would silently rename every family
    after the first; the route refuses to answer at all instead."""
    short = tmp_path / "label_classes.json"
    short.write_text(json.dumps(CLASSES[:-1]), encoding="utf-8")

    def serve(_bucket, key, path):
        shutil.copy(short if key == "label_classes.json" else artefacts / key, path)
    fake_sfn.download_file.side_effect = serve

    resp = auth_client.post("/predict", json=flow(0.5, 0.5))
    assert resp.status_code == 500
    assert "8 classes" in resp.json()["detail"] and "names 7" in resp.json()["detail"]
