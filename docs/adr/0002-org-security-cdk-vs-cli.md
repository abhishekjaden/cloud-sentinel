# ADR 0002: CDK for declarative resources, scripts for org-config API calls

## Status
Accepted

## Context
Enabling five security services (GuardDuty, Security Hub, Macie, Inspector,
Detective) org-wide with delegated administration involves two kinds of work:
durable declarative resources, and one-time idempotent organization-level API
calls (delegated-admin registration, member auto-enable toggles).

## Decision
- CDK for durable, declarative infrastructure (e.g. Security Hub cross-region
  finding aggregator). Deployed cross-account to the Audit account via the
  bootstrap trust relationship.
- Committed, idempotent shell scripts for organization-config API calls
  (delegation + member auto-enable). See scripts/enable-org-security.sh.

## Rationale
- Org-level enablement APIs lack clean CDK L2 constructs; wrapping them in
  CloudFormation custom resources adds Lambda + IAM + rollback fragility for
  no durable resource to manage.
- These calls are idempotent and one-time; scripting them is the real-world
  pattern and the committed script is itself the reproducible artifact.
- FSBP standard is intentionally NOT declared in CDK: Security Hub auto-enables
  it on activation, and redeclaring it causes a ResourceConflictException.

## Consequences
- Clear separation: declarative state in CDK, imperative org-config in scripts.
- Both are version-controlled and reproducible.
- Trade-off documented rather than hidden behind a brittle "all-CDK" facade.
