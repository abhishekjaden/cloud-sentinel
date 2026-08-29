"""
CloudSentinel API — FastAPI backend.

Surfaces the live security platform through a REST API:
  /findings      normalized security findings (DynamoDB)
  /stats         dashboard summary aggregates
  /predict       binary intrusion-detection inference (XGBoost model from S3)
  /remediations  recent SOAR remediation executions (Step Functions)
  /health        load-balancer health check

Runs on ECS Fargate behind an ALB (audit account). Reads existing resources;
does not own state beyond the trained model it loads at startup.
"""
from fastapi import FastAPI
import os
from fastapi.middleware.cors import CORSMiddleware

from app.findings import router as findings_router
from app.predict import router as predict_router
from app.remediations import router as remediations_router

app = FastAPI(
    title="CloudSentinel API",
    description="Cloud security operations platform — findings, ML detection, and SOAR remediation",
    version="1.0.0",
)

# CORS: allow the SOC dashboard (added later) to call this API.

# Browser origins permitted to call the API. Defaults to the deployed
# dashboard; override via CORS_ORIGINS (comma-separated) for local work.
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "CORS_ORIGINS",
        "https://d2tb90osqfrb0m.cloudfront.net",
    ).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    # Only the dashboard may call this API from a browser. With allow_origins
    # set to "*", any site an authenticated operator visited could issue
    # credentialed requests here and the JWT check would pass — the request
    # would be authenticated, just not intended.
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(findings_router, tags=["findings"])
app.include_router(predict_router, tags=["prediction"])
app.include_router(remediations_router, tags=["remediation"])


@app.get("/health", tags=["health"])
def health():
    return {"status": "healthy", "service": "cloudsentinel-api"}
