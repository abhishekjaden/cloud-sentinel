# CloudSentinel — Well-Architected Review

A self-assessment of CloudSentinel against the six pillars of the
[AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/).
The intent is an honest evaluation — each pillar lists what the design does well
*and* where it falls short, with remediation noted for the gaps. A review that
only records strengths is not a review.

Reviewed at: end of build (~Day 27). Scope: the deployed CloudSentinel platform
across the four-account organization.

---

## 1. Operational Excellence

**Strengths**
- All durable infrastructure is defined in AWS CDK (TypeScript) and version-controlled; environments are reproducible from code.
- Architecture decisions are captured as ADRs, so the *why* behind non-obvious choices is documented, not just the *what*.
- The ingestion pipeline emits structured logs (the normalizer records each `NORMALIZED_FINDING`), and remediation runs are fully traceable through Step Functions execution history.
- Teardown/redeploy is a routine, proven operation — the ephemeral compute stack redeploys from code in ~7 minutes.

**Gaps / remediation**
- No CI/CD pipeline yet; deploys are run manually from the CLI. A CodePipeline or GitHub Actions workflow with `cdk diff` gating would be the next step.
- No automated tests around the Lambda normalizer or the API beyond manual validation. Unit tests on the schema-normalization logic would harden it.
- Runbooks are informal (captured in notes rather than a published operations doc).

---

## 2. Security

**Strengths**
- Multi-account isolation via AWS Organizations and Control Tower: security tooling is centralized in a dedicated Audit account, workloads are separated, and logs are archived in their own account.
- Detection is broad and native: GuardDuty, Security Hub, and Inspector, aggregated organization-wide through delegated administration.
- Least-privilege IAM: the API task role is scoped to exactly the DynamoDB table, model object, and state machine it needs.
- Authentication is enforced at the API, not just the UI — every data route validates a Cognito-issued JWT against the pool's JWKS; unauthenticated calls receive 401. Self sign-up is disabled and the password policy requires 12+ characters.
- The authorization-code + PKCE flow is used rather than the deprecated implicit grant.
- TLS everywhere the platform is reachable: ACM certificate on the ALB, HTTP→HTTPS redirect, CloudFront serving the dashboard over HTTPS.
- Remediation is human-gated — destructive playbooks pause for approval, preventing automated actions from causing damage.

**Gaps / remediation**
- The Cognito user base is a single administrator; there is no role/group separation (e.g. read-only analyst vs. approver). Cognito groups mapped to API scopes would add this.
- MFA is available in the pool configuration but not enforced. It should be required before any real multi-user use.
- Secrets are minimal (no long-lived credentials in the app; the task role supplies AWS access), but there is no formal secrets-rotation posture documented.

---

## 3. Reliability

**Strengths**
- Serverless and managed services (Lambda, Kinesis, DynamoDB, Step Functions, Fargate behind an ALB) carry AWS-managed availability rather than hand-rolled HA.
- The Fargate service runs behind an Application Load Balancer with health checks on `/health`; the ALB spans two Availability Zones.
- DynamoDB and S3 provide durable storage with no single point of failure for the finding data.
- Step Functions gives the remediation workflow built-in retry/catch semantics and durable execution state.

**Gaps / remediation**
- The Fargate service currently runs a single task (desired count 1) — fine for a portfolio demo, but a production posture would run ≥2 tasks across AZs behind the ALB.
- Kinesis runs a single shard; adequate for current volume but would need resharding under real load.
- No disaster-recovery plan or cross-region strategy; the platform is single-region (us-east-1).
- No automated backup/restore drill for DynamoDB (point-in-time recovery could be enabled).

---

## 4. Performance Efficiency

**Strengths**
- Compute is right-sized deliberately (ADR 0001): ECS Fargate rather than EKS, avoiding Kubernetes overhead for a single API service.
- DynamoDB access is index-driven — a severity GSI supports the dashboard's severity queries without table scans on the hot path.
- The dashboard is a static SPA served from CloudFront, so global read latency is low and the origin bucket stays private behind Origin Access Control.
- The ML model is a gradient-boosted tree (fast inference, small footprint) rather than a heavyweight network, matching the tabular-flow problem.

**Gaps / remediation**
- Some dashboard/API queries use `Scan` where a `Query` against an index would be cheaper at scale; the findings table listing is the main candidate to refactor.
- The frontend bundle is above the 500 kB warning threshold (Recharts is heavy); code-splitting would improve first-load performance.
- No load testing has been completed to establish p95/p99 latency under concurrency (planned).

---

## 5. Cost Optimization

**Strengths**
- Teardown discipline is the primary cost lever: the expensive serving layer (ALB, NAT, Fargate) is destroyed when idle and redeployed on demand, keeping the idle baseline near $20/month.
- Cost is actively measured, not assumed — a monthly AWS Budget with alerts at 50/80/100% is in place, and Cost Explorer was used to attribute spend by service.
- An unused OpenSearch domain (~$25/month, no producers or consumers) was identified and decommissioned (ADR 0004) — a measured removal rather than resume-driven retention.
- The persistent DNS/cert stack is separated from ephemeral compute, so redeploys don't re-validate certificates and don't leave costly resources behind.

**Gaps / remediation**
- The NAT gateway is the largest line item when the API is up (~$32/month while running). For a demo-only posture, a VPC endpoint or a NAT-instance alternative could reduce this.
- No use of Savings Plans or Spot — appropriate at this scale, but noted.
- Manual teardown is effective but depends on discipline; a scheduled auto-teardown (EventBridge → Lambda) would make idle-cost control automatic.

---

## 6. Sustainability

**Strengths**
- Serverless and on-demand compute means resources are consumed only when needed; the platform does not run idle server fleets.
- Teardown-when-idle directly reduces energy footprint, not just cost.
- Right-sized compute (small Fargate task, single-shard Kinesis, a lightweight tree model) avoids over-provisioning.

**Gaps / remediation**
- Region selection (us-east-1) was driven by service availability, not carbon intensity; a lower-carbon region could be chosen where latency permits.
- No measurement of the workload's actual resource-utilization efficiency (e.g. right-sizing the Fargate task from observed CPU/memory).

---

## Summary

| Pillar | Posture |
|--------|---------|
| Operational Excellence | Strong IaC + ADRs; missing CI/CD and automated tests |
| Security | Strong multi-account isolation, enforced auth, human-gated remediation; single-user, MFA not enforced |
| Reliability | Managed-service backbone; single-task/single-shard/single-region for demo |
| Performance Efficiency | Right-sized, index-driven; some Scans and a heavy frontend bundle to refactor |
| Cost Optimization | Actively measured and controlled; NAT is the main cost, teardown is manual |
| Sustainability | On-demand and right-sized; region not carbon-optimized |

The recurring theme is deliberate: CloudSentinel is built to production-*grade* standards
(isolation, IaC, enforced auth, human-gated response, measured cost) while making
demo-appropriate simplifications (single task, single region, manual deploys) that are
named here rather than hidden. Each gap has a concrete next step.
