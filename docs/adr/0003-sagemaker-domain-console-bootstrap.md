# ADR 0003: SageMaker Studio domain bootstrapped via console, ML pipelines as code

## Status
Accepted

## Context
The ML workload (intrusion detection on CICIDS2017) runs in SageMaker Studio in
the workload account. Two kinds of setup are involved: one-time environment
provisioning (the Studio domain, user profile, and execution role) and the
repeatable ML work that runs inside it (preprocessing, training, evaluation).

A strict "everything in CDK" stance would push the domain and execution role
into IaC. In practice, SageMaker Studio domain creation via CloudFormation/CDK
is heavyweight (VPC/EFS wiring, IAM, long provisioning) and is a one-time
environment step, not a durable application asset that changes with the system.

## Decision
- The Studio domain, user profile, and execution role are bootstrapped via the
  console as a one-time environment setup. Console steps are recorded in the
  project runbook so the bootstrap is reproducible.
- The execution role's access to the ML data lake IS managed in CDK (MLStack
  grants read/write to the console-created role by name). The durable,
  reviewable permission lives in code even though the role itself is bootstrap.
- The ML pipelines that RUN in the domain are defined as code in ml/ and are the
  production-grade artifact: preprocessing.py + run_processing.py (managed
  Processing job) and train.py + run_training.py (managed training job).

## Rationale
- "The domain is bootstrap; the pipeline is the asset." A reviewer evaluates the
  reproducible pipeline code, not whether the IDE shell was clicked or scripted.
- Managed job launchers (run_processing.py, run_training.py) are the intended
  production execution path. On a new account these were blocked by zero-value
  SageMaker instance quotas (processing and training both denied/pending on
  new-account grounds), so initial runs were executed in-notebook as a
  documented interim, with the managed launchers committed and to be re-run once
  quota clears. This is recorded honestly rather than presented as if managed
  jobs had run.
- Granting data-lake access in CDK (not console) keeps the security-relevant
  permission in code and under review, which is where it matters most.

## Consequences
- One manual bootstrap step, documented and reproducible via the runbook.
- The security-relevant IAM grant remains declarative in CDK.
- Interim in-notebook runs are labelled as such; the managed jobs remain the
  reportable production path and will be re-run on quota approval.
- Trade-off is documented rather than hidden behind an all-CDK facade,
  consistent with ADR 0002.
