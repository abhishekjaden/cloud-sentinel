# ADR 0004: Decommission the OpenSearch domain

## Status
Accepted

## Context
DataStoresStack provisioned an OpenSearch domain alongside DynamoDB, intended
as a full-text search and analytics layer over normalized findings.

In practice it was never wired up: the normalizer Lambda writes findings only to
DynamoDB, and the API and SOC dashboard read only from DynamoDB. The domain had
no producers and no consumers — it sat idle while costing roughly $25/month,
over half the platform's steady-state baseline.

## Decision
Remove the OpenSearch domain from DataStoresStack. DynamoDB (with a
severity-bucket GSI) remains the single store for normalized findings, which is
what every consumer actually queries.

## Rationale
- Cost discipline: an idle component consuming half the monthly baseline is not
  defensible. That budget is better spent keeping the API and dashboard live
  during the periods when the system is actually being demonstrated.
- No functionality is lost: nothing read from or wrote to the domain. Removing
  it changes no behaviour in the pipeline, API, or dashboard.
- Right-sizing over resume-driven architecture: keeping an unused search cluster
  purely because "a SOC platform should have one" is the wrong instinct. The
  honest position is that DynamoDB serves the current access patterns.

## Consequences
- Steady-state cost drops from ~$45/month to ~$20/month between demo sessions.
- Full-text search over findings is not currently available. If needed, the
  domain is a small CDK addition and the ingestion path would gain a second
  write. Recorded as a deliberate deferral, not an oversight.
- The pipeline continues to ingest into DynamoDB unchanged; verified after the
  removal.
