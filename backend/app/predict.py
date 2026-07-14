"""Prediction route — binary intrusion detection via the trained XGBoost model."""
import os
import tempfile
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import boto3
import numpy as np
import xgboost as xgb

from app.auth import require_auth

router = APIRouter()

BUCKET = os.environ.get("ML_BUCKET", "cloudsentinel-models-118821712739")
MODEL_KEY = os.environ.get("MODEL_KEY", "binary_model.json")
REGION = os.environ.get("AWS_REGION", "us-east-1")

# Load the model once at import (cold start). The binary model expects the
# ~78 numeric CICFlowMeter features in the same order used at training time.
_booster = None


def _load_model():
    global _booster
    if _booster is None:
        s3 = boto3.client("s3", region_name=REGION)
        tmp = os.path.join(tempfile.gettempdir(), "binary_model.json")
        s3.download_file(BUCKET, MODEL_KEY, tmp)
        b = xgb.Booster()
        b.load_model(tmp)
        _booster = b
    return _booster


class PredictRequest(BaseModel):
    features: list[float]  # ordered numeric flow features


class PredictResponse(BaseModel):
    attack_probability: float
    prediction: str  # "ATTACK" or "BENIGN"
    threshold: float


@router.post("/predict", response_model=PredictResponse, dependencies=[Depends(require_auth)])
def predict(req: PredictRequest, threshold: float = 0.5):
    """Score a single network flow: returns attack probability + label."""
    try:
        booster = _load_model()
        n_feat = booster.num_features()
        if len(req.features) != n_feat:
            raise HTTPException(
                status_code=400,
                detail=f"expected {n_feat} features, got {len(req.features)}",
            )
        x = np.array([req.features], dtype=np.float32)
        feat_names = booster.feature_names
        dmat = xgb.DMatrix(x, feature_names=feat_names)
        proba = float(booster.predict(dmat)[0])
        return PredictResponse(
            attack_probability=round(proba, 4),
            prediction="ATTACK" if proba >= threshold else "BENIGN",
            threshold=threshold,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"prediction failed: {e}")
