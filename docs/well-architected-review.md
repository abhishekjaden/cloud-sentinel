# CloudSentinel — Well-Architected Review

A self-assessment of CloudSentinel against the six pillars of the
[AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/).
Each pillar lists what the design does well *and* where it falls short, with
the next step for each gap. A review that only records strengths is not a
review.

**Reviewed twice.** The first review was written at the end of the build
(day 27). This second one, on 3 October 2026, records what changed since —
most of the first review's gaps were closed by the hardening that followed it
— and what the gaps are now. Where a v1 gap is closed, it is kept here with
how, because a review that forgets its own history cannot show progress.

Scope: the deployed platform across the four-account organisation, including
the components added since v1: incident correlation, advisory triage by a
language model, threat-intelligence enrichment, the incident report, the
control-change watch and the honeypot.

---

## 1. Operational Excellence

**Strengths**
- All durable infrastructure is AWS CDK in TypeScript, synthesised with
  cdk-nag on every push; every accepted finding carries a written reason in
  `cdk/lib/nag-suppressions.ts`.
- Three test suites run in CI before anything deploys: 297 backend tests at a
  93% coverage floor of 80%, 100 CDK assertion tests, 76 frontend tests. The
  CDK tests pin security properties rather than resource counts: what each
  function may touch, what the API may read and never write, that every
  alarm is documented and every documented alarm exists.
- Deployment is a GitHub Actions workflow under OIDC federation (no stored
  AWS keys), with `cdk diff` printed before `cdk deploy` so each run's log
  records what was about to change. Semgrep and gitleaks run on every push
  and weekly.
- Decisions are ADRs (six so far), objectives are `docs/slos.md` with a
  "when it fires" response under each alarm, the threat model is STRIDE
  across eight boundaries, and the evaluation of the one component whose
  output comes from a model has a written protocol
  (`docs/triage-eval-protocol.md`).
- Every function publishes its own counts as Embedded Metric Format lines;
  the SLO dashboard reads them, and a test checks that every metric the
  dashboard reads is emitted by something deployed.
- A post-deploy smoke test checks the deployed pieces reach each other —
  written after a deploy once shipped a dashboard pointing at localhost
  while every unit test passed.

**Closed since v1**
- *No CI/CD* → the workflows above.
- *No automated tests* → the three suites above.
- *Informal runbooks* → `docs/slos.md` is the runbook, one response per
  alarm.

**Gaps / next step**
- One environment. There is no staging stack; a change is tested by its
  suites and `cdk diff`, then deployed to the only environment there is. A
  second environment is a matter of a second account and a context flag,
  and is deferred on cost.
- The API stack deploys by hand, on demand. That is the cost decision below,
  but it means the API's deploy path is exercised less often than the rest.
- `scripts/measure.py` and `scripts/flood_findings.py` exist to measure
  latency, cost and behaviour under load (`docs/evaluation.md`); the figures
  they produce are not yet in this document.

---

## 2. Security

**Strengths**
- Multi-account isolation under Control Tower: security tooling and the
  platform in the Audit account, training in the Workload account, logs in
  their own account, the organisation root alone in Management.
- Detection is native and organisation-wide — GuardDuty, Security Hub and
  Inspector under delegated administration — and the controls themselves are
  watched: a change to the state machine, a rule, a key, GuardDuty, a
  function, a role, a table or the alarms that did not come through the CDK
  execution role is reported with the caller's identity and recorded for a
  year (SLO 8). The rules cover their own names.
- Least privilege written out action by action and pinned by tests: the API
  reads findings only through named indexes and holds no `Scan` on them,
  reads incidents and never writes them; the triage function can write only
  its own notes; the enricher only its own cache; the remediation executor's
  wildcard is the one accepted risk, recorded at the statement.
- Authentication is enforced at the API (every data route validates a
  Cognito JWT against the pool's JWKS), with authorization-code + PKCE, not
  the deprecated implicit grant. CORS is restricted to the dashboard origin.
- Human-gated remediation with the Step Functions task token held
  server-side: an approval requires an authenticated API call and is
  attributed to the operator who made it. Possession of a mailbox is not
  authority.
- A language model reads attacker-controlled text and is given no authority
  (ADR 0005): finding data is escaped as untrusted, answers must fit one
  validated schema, injection attempts are flagged, and the function's
  permissions make an action impossible whatever the model says. Thirty-three
  of thirty-six evaluation runs at the current prompt, every injection attempt
  flagged on every run; the three misses were one case rated a step above its
  band, adjudicated on the record (ADR 0005).
- Data at rest under a customer-managed KMS key for every table, usable only
  through DynamoDB; TLS enforced on the queue and the topic; the API
  container runs as a non-root user; findings text is escaped before it
  reaches the PDF report, with a test that reads the PDF back.
- The one component that sends anything outside the account — the enricher,
  to two threat-intelligence feeds — sends only the indicator, over TLS with
  verification, to two fixed hosts, and is recorded as a trust boundary
  (B8). The honeypot that invites attack is built to be worthless to whoever
  gets in: no credential, no login, no outbound rule, its own network.

**Closed since v1**
- *No secrets-rotation posture* → the only secret is the pair of
  third-party API keys, in Secrets Manager, rotated at the provider; the
  rotation finding is accepted with its reason.
- *Least privilege asserted, not tested* → tested, per function and per
  table.

**Gaps / next step**
- Single administrator, no roles. Cognito groups mapped to API scopes
  (analyst, approver) would separate reading from approving.
- MFA is not enforced on the user pool. Required before any multi-user use.
- Single-account blast radius: the Audit account's administrator reads every
  finding and can disable the key (threat model, residual risk 1).
- A change pushed *through* the deployment pipeline looks like a deploy; the
  control-change watch does not see it (residual risk 2).
- The normalizer trusts what reaches it; no schema validation at ingestion
  (residual risk 3). No WAF (residual risk 4, accepted on cost).

---

## 3. Reliability

**Strengths**
- Managed services throughout — Lambda, Kinesis, DynamoDB, Step Functions,
  Fargate behind an ALB — carry AWS-managed availability; the ALB spans two
  Availability Zones and health-checks `/health`.
- Nothing is dropped quietly. A finding the normalizer fails on is handed
  back by sequence number and delivered again; only when retries are
  exhausted is it reported to a failure queue, which is what the
  findings-stored objective alarms on. Writes are keyed on the finding, so a
  redelivery overwrites rather than duplicates.
- Every table has point-in-time recovery. The failure queue and the alarm
  topic enforce TLS; the queue is server-side encrypted.
- The triage function asks a malformed answer again once, after measurement
  showed the model malforms roughly one answer in twenty-one; the enricher
  retries a failed provider within the hour rather than caching the failure
  for a week.
- Eight objectives, each with an alarm that notifies on firing and on
  clearing, and a dashboard that graphs recoveries separately from losses.
  Silence from the correlator is treated as a breach.
- The ECS deployment uses a circuit breaker with rollback and never drops
  below the running task count during a deploy.

**Closed since v1**
- *PITR could be enabled* → enabled on every table.
- *No failure handling at ingestion* → partial batch failures, retries, the
  failure queue, and the objective that watches it.

**Gaps / next step**
- Single Fargate task, single Kinesis shard, single Region. Appropriate for
  the volume; named rather than hidden. A second task is a one-line change;
  resharding is a capacity decision the flow metrics would signal.
- No disaster-recovery drill. PITR is enabled but a restore has never been
  rehearsed.
- The chaos experiments in `docs/chaos-experiments.md` — malformed input, a
  function denied its table, a schedule disabled, a flood — are written with
  their expected signals but not yet run; their outcomes belong here.

---

## 4. Performance Efficiency

**Strengths**
- Compute is right-sized (ADR 0001): Fargate rather than EKS for one API
  service; a gradient-boosted tree for tabular flows rather than a network.
- The findings path is entirely index-driven: a severity index and a
  source/time index, each read with a bounded query, `/stats` counting a
  partition at a time. The API holds no `Scan` on findings, which keeps it
  that way.
- Threat-intelligence lookups are cached a week per indicator and bounded
  to ten a run, so a flood of new addresses spreads its lookups over hours.
- The dashboard is a static SPA on CloudFront behind Origin Access Control.
- API latency is an objective (p95 under two seconds) with its own alarm
  while the API is deployed.

**Gaps / next step**
- Two whole-table reads remain: `/incidents` scans the incidents table and
  the correlator scans the findings table each run. Both are aggregates over
  everything, so an index would change how they read rather than how much;
  the correlator's run time is graphed against its timeout for when that
  stops being true.
- The frontend bundle is above the 500 kB warning (Recharts); code-splitting
  would improve first load.
- Latency under load is unmeasured. The flood script drives the pipeline at
  ten times its volume and the measurement script reads the result from the
  tables' timestamps; the numbers are pending (`docs/evaluation.md`).

---

## 5. Cost Optimization

**Strengths**
- Teardown is the primary lever: the serving layer (ALB, NAT, Fargate) is
  destroyed between sessions and redeploys from code in about seven minutes.
  The idle baseline is about $15–20 a month; the API adds about $1.60 a day
  while up.
- Cost is measured, not assumed: a monthly budget with alerts, Cost Explorer
  attribution by service, and `scripts/measure.py` reporting cost per
  thousand findings for a period.
- Spend that bought nothing was removed when measured: an idle OpenSearch
  domain (ADR 0004, ~$25 a month).
- The additions since v1 cost almost nothing: the model triage well under a
  dollar a month at current volume, the threat-intelligence feeds on free
  tiers with a cache that keeps them there, the observability stack within
  CloudWatch's free allowance but for a couple of dollars, the honeypot
  about $3 a month while it exists.

**Gaps / next step**
- The NAT gateway is the largest item while the API is up. VPC endpoints for
  the services the task calls would remove most of its traffic.
- Teardown depends on discipline. A scheduled teardown would make idle-cost
  control automatic.
- No Savings Plans or Spot; appropriate at this scale.

---

## 6. Sustainability

**Strengths**
- Serverless and on-demand: nothing runs idle but the small, persistent
  pieces, and the serving layer exists only while in use.
- Right-sized by default: a small Fargate task, one shard, a tree model, a
  `t4g.nano` honeypot on Graviton.

**Gaps / next step**
- Region chosen for service availability, not carbon intensity.
- Fargate task size is not tuned from observed utilisation; the API's
  metrics would show whether the task is oversized.

---

## Summary

| Pillar | v1 posture | v2 posture |
|--------|-----------|-----------|
| Operational Excellence | IaC + ADRs; no CI/CD, no tests | CI with three suites and cdk-nag, OIDC deploys, SLO runbook; single environment |
| Security | Isolation, enforced auth, gated remediation; single user, no MFA | The above plus tested least privilege, server-side approval tokens, contained model triage, control-change alarms, a bounded egress boundary; single user, no MFA, pipeline-borne changes unseen |
| Reliability | Managed backbone; single task/shard/Region | Retries and a failure queue with an objective on it, PITR everywhere, resampling and retry in the advisory components; single task/shard/Region, chaos experiments written but unrun |
| Performance Efficiency | Right-sized; index-driven findings | The above plus a bounded, cached enrichment path; two whole-table aggregates, load figures pending |
| Cost Optimization | Measured and controlled; NAT, manual teardown | The above with cost per thousand findings measurable; NAT, manual teardown |
| Sustainability | On-demand, right-sized | On-demand, right-sized, Graviton where there is a choice |

The theme has not changed: production-*grade* standards — isolation, IaC,
enforced auth, gated response, tested privilege, measured cost — with
demo-appropriate simplifications named rather than hidden. What changed is
that the first review's largest gaps, no pipeline and no tests, are the parts
of the system a reviewer can now check most easily.
