"""
Prediction route: scores one network flow with both trained XGBoost models.

The binary model gives the verdict, ATTACK or BENIGN against a threshold; it is
the model evaluated for that decision (AUC 0.99996 on the held-out split). The
multiclass model names the most likely attack family and is reported beside the
verdict, never in place of it: its per-class reliability is uneven (Bot
precision 0.648, Infiltration supported by six test rows), so the family is a
second opinion the analyst reads with its probability, and the two models are
allowed to disagree in the response rather than reconciled behind it.

Both models and the multiclass label map are read from the models bucket on the
first request and held for the life of the process.
"""
import json
import os
import tempfile
from dataclasses import dataclass

import boto3
import numpy as np
import xgboost as xgb
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth import require_auth

router = APIRouter()

BUCKET = os.environ.get("ML_BUCKET", "cloudsentinel-models-118821712739")
BINARY_MODEL_KEY = os.environ.get("BINARY_MODEL_KEY", "binary_model.json")
MULTICLASS_MODEL_KEY = os.environ.get("MULTICLASS_MODEL_KEY", "multiclass_model.json")
LABEL_CLASSES_KEY = os.environ.get("LABEL_CLASSES_KEY", "label_classes.json")
REGION = os.environ.get("AWS_REGION", "us-east-1")


@dataclass(frozen=True)
class Models:
    binary: xgb.Booster
    multiclass: xgb.Booster
    classes: list[str]        # multiclass output index -> family name


_models: Models | None = None


def _fetch(s3, key: str) -> str:
    path = os.path.join(tempfile.gettempdir(), os.path.basename(key))
    s3.download_file(BUCKET, key, path)
    return path


def _booster(path: str) -> xgb.Booster:
    b = xgb.Booster()
    b.load_model(path)
    return b


def _num_class(booster: xgb.Booster) -> int:
    return int(json.loads(booster.save_config())["learner"]["learner_model_param"]["num_class"])


def _load_models() -> Models:
    """Both models and the label map, loaded once. The three artefacts were
    written by one training run, and the checks here are what make a mismatch
    between them a deployment error rather than a wrong answer: a label map of
    the wrong length would silently rename every family."""
    global _models
    if _models is None:
        s3 = boto3.client("s3", region_name=REGION)
        binary = _booster(_fetch(s3, BINARY_MODEL_KEY))
        multiclass = _booster(_fetch(s3, MULTICLASS_MODEL_KEY))
        with open(_fetch(s3, LABEL_CLASSES_KEY), encoding="utf-8") as f:
            classes = json.load(f)
        if binary.num_features() != multiclass.num_features():
            raise RuntimeError(
                f"models disagree on feature count: binary {binary.num_features()}, "
                f"multiclass {multiclass.num_features()}")
        if not isinstance(classes, list) or not all(isinstance(c, str) for c in classes):
            raise RuntimeError(f"{LABEL_CLASSES_KEY} must be a JSON list of class names")
        if _num_class(multiclass) != len(classes):
            raise RuntimeError(
                f"multiclass model has {_num_class(multiclass)} classes, "
                f"{LABEL_CLASSES_KEY} names {len(classes)}")
        _models = Models(binary=binary, multiclass=multiclass, classes=classes)
    return _models


class PredictRequest(BaseModel):
    features: list[float]  # the 78 CICFlowMeter features, in training order


class PredictResponse(BaseModel):
    attack_probability: float
    prediction: str                        # "ATTACK" or "BENIGN": the binary model's verdict
    threshold: float
    attack_family: str                     # the multiclass model's most likely class; may be BENIGN
    family_probability: float              # that class's probability
    family_probabilities: dict[str, float]  # every class, so the margin is visible


@router.post("/predict", response_model=PredictResponse, dependencies=[Depends(require_auth)])
def predict(req: PredictRequest, threshold: float = 0.5):
    """Score a single network flow: the binary verdict, and the attack family
    the multiclass model finds most likely."""
    try:
        models = _load_models()
        n_feat = models.binary.num_features()
        if len(req.features) != n_feat:
            raise HTTPException(
                status_code=400,
                detail=f"expected {n_feat} features, got {len(req.features)}",
            )
        x = np.array([req.features], dtype=np.float32)

        binary_in = xgb.DMatrix(x, feature_names=models.binary.feature_names)
        proba = float(models.binary.predict(binary_in)[0])

        family_in = xgb.DMatrix(x, feature_names=models.multiclass.feature_names)
        family_probs = models.multiclass.predict(family_in)[0]
        top = int(np.argmax(family_probs))

        return PredictResponse(
            attack_probability=round(proba, 4),
            prediction="ATTACK" if proba >= threshold else "BENIGN",
            threshold=threshold,
            attack_family=models.classes[top],
            family_probability=round(float(family_probs[top]), 4),
            family_probabilities={
                name: round(float(p), 4) for name, p in zip(models.classes, family_probs)
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"prediction failed: {e}")
