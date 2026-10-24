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
- Three test suites run in CI before anything deploys: 316 backend tests at a
  93% coverage floor of 80%, 106 CDK assertion tests, 76 frontend tests. The
  CDK tests pin security properties rather than resource counts: what each
  function may touch, what the API may read and never write, that every
  alarm is documented and every documented alarm exists.
- Deployment is a GitHub Actions workflow under OIDC federation (no stored
  AWS keys), with `cdk diff` printed before `cdk deploy` so each run's log
  records what was about to change. Semgrep and gitleaks run inside CI on
  every push, so a finding blocks the deploy that follows CI, and weekly over
  the whole history. They ran beside CI until 19 October 2026, with nothing
  depending on them: a Semgrep finding — an inline suppression naming the
  rule in one of the two forms the scanner reports it under — left the
  Security workflow red from its scheduled run of 12 October (run #95,
  12:35Z) to the gate's first green run on the 19th (after `ce5f4a1`,
  05:44Z): six days and seventeen hours, while deploys went on, noticed only
  from a screenshot of the Actions list. The run before, #94 on the 11th,
  had passed, and nothing was pushed between the two, so what changed was
  the scanner's floating container, not the code. The scanner is now a
  pinned release, and its findings fail CI.
- Decisions are ADRs (seven so far), objectives are `docs/slos.md` with a
  "when it fires" response under each alarm, the threat model is STRIDE
  across eight boundaries, and the evaluation of the one component whose
  output comes from a model has a written protocol
  (`docs/triage-eval-protocol.md`).
- Every function publishes its own counts as Embedded Metric Format lines;
  the SLO dashboard reads them, and a test checks that every metric the
  dashboard reads is emitted by something deployed.
- A post-deploy smoke test checks the deployed pieces reach each other —
  written after a deploy once shipped a dashboard pointing at localhost
  while every unit test passed. Since 18 October the deploy workflow also
  ends by running the correlator once and failing the run if it errors,
  written after a deploy shipped a correlator without the IAM grant its new
  query needed: CloudFormation returned success, and only the
  incidents-current alarm said otherwise, 45 minutes later (`docs/slos.md`,
  objective 3). The role the workflow assumes for it may invoke that one
  function and nothing else.

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
- The post-deploy run covers the correlator because it is the one function
  that runs on demand. The normalizer, the enricher and the triage function
  are driven by data, so a change to what they read that ships without its
  grant is still caught only by their alarms, after the fact.
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
  the deprecated implicit grant, and TOTP multi-factor authentication required
  on the pool — pinned by a CDK test, after this review carried "MFA is not
  enforced" for two versions while the pool required it. CORS is restricted
  to the dashboard origin.
- Human-gated remediation with the Step Functions task token held
  server-side: an approval requires an authenticated API call and is
  attributed to the operator who made it. Possession of a mailbox is not
  authority.
- A language model reads attacker-controlled text and is given no authority
  (ADR 0005): finding data is escaped as untrusted, answers must fit one
  validated schema, injection attempts are flagged, and the function's
  permissions make an action impossible whatever the model says. Thirty-six
  of thirty-six evaluation runs at the current prompt on the adjudicated
  labels, every injection attempt flagged on every run; the run before it
  passed 33, and its three misses — one case rated a step above its band —
  are the adjudication on the record in ADR 0005.
- Data at rest under a customer-managed KMS key for every table, usable only
  through DynamoDB; TLS enforced on the queue and the topic; the API
  container runs as a non-root user; findings text is escaped before it
  reaches the PDF report, with a test that reads the PDF back.
- The one component that sends anything outside the account — the enricher,
  to two threat-intelligence feeds — sends only the indicator, over TLS with
  verification, to two fixed hosts, and is recorded as a trust boundary
  (B8). The honeypot that invites attack is built to be worthless to whoever
  gets in: no credential, no login that can succeed, no outbound rule, its own network.

**Closed since v1**
- *No secrets-rotation posture* → the only secret is the pair of
  third-party API keys, in Secrets Manager, rotated at the provider; the
  rotation finding is accepted with its reason.
- *Least privilege asserted, not tested* → tested, per function and per
  table.
- *Single administrator, no roles* → two Cognito groups, `analysts` and
  `approvers`; the API refuses a decision from any token outside the second,
  the console hides the buttons from the first, and tests pin both the group
  check and the groups' existence (October 2026); checked live with two
  accounts on 21 October (`screenshots/approvals-*-2026-10-21.png`).
- *No WAF, no rate limiting* → a WAF with AWS's managed rule groups and a
  per-address rate rule on the load balancer, created and destroyed with the
  Api stack, and a per-user limit of 120 requests a minute in the API itself,
  both pinned by tests (October 2026).

**Gaps / next step**
- Group membership is one administrator's call, with no second approver and
  no alarm on a change to it.
- Single-account blast radius: the Audit account's administrator reads every
  finding and can disable the key (threat model, residual risk 1).
- A change pushed *through* the deployment pipeline looks like a deploy; the
  control-change watch does not see it (residual risk 2).
- The normalizer trusts what reaches it; no schema validation at ingestion
  (residual risk 3).
- The WAF and the per-user limit were each driven past their limit once, on
  21 October 2026 (`docs/slos.md`), and the two roles checked against a
  staged quarantine the same night; one session, one address, one identity.
  The WAF keeps metrics and sampled requests, not logs, and the rate rule
  admitted about 400 requests past its nominal 2,000 before it caught up.

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
  Silence from the correlator is treated as a breach. Until 13 October the
  notifications were not delivered: the alarm topic's TLS-only policy had
  replaced the default that lets CloudWatch publish to it, and every alarm
  action failed, recorded only in each alarm's history. The policy now
  admits CloudWatch for this account's alarms (`docs/slos.md`).
- The ECS deployment uses a circuit breaker with rollback and never drops
  below the running task count during a deploy.

**Closed since v1**
- *PITR could be enabled* → enabled on every table.
- *No failure handling at ingestion* → partial batch failures, retries, the
  failure queue, and the objective that watches it.
- *No disaster-recovery drill* → a restore rehearsed and timed on 21 October
  2026 (`docs/chaos-experiments.md`, R1): the findings and incidents tables
  restored to one instant as new tables, the incidents copy usable in
  14 min 1 s and the findings copy — 3,728 items, two indexes — in
  18 min 20 s, every item accounted for against the live tables' stamps,
  and the copies' deletion reported by the control watch as the hand-made
  change it was. `scripts/restore_rehearsal.py` runs it again.

**Gaps / next step**
- Single Fargate task, single Kinesis shard, single Region. Appropriate for
  the volume; named rather than hidden. A second task is a one-line change;
  resharding is a capacity decision the flow metrics would signal.
- The restore is rehearsed; the cut-over is not. A restored table has a new
  name and DynamoDB does not rename tables, so a recovery would go on to
  redeploy the stacks against the copy or copy its data back into the live
  table — time on top of the eighteen minutes, not yet measured.
- All five chaos experiments in `docs/chaos-experiments.md` have run.
  E1 (malformed input) behaved as designed under the first retry policy.
  E2 (the normalizer denied its
  table) found that the ingestion retry policy — two immediate retries, then
  the failure queue — loses every finding of a dependency outage to manual
  recovery: sixteen minutes cost 200 of 200, recoverable only by replaying
  the stream by hand. ADR 0007 changed the policy to retry until a record is
  an hour old, which holds the shard and self-heals at the price of a poison
  record blocking its shard for an hour. The same-day re-run verified it: a
  25-minute denial lost nothing, findings-fresh fired at ten and a half minutes,
  and all 50 findings stored when the denial was lifted. E1, re-run under the
  new policy on 12 October, measured that price and found it higher: the
  malformed record held the shard for 60 minutes, nothing behind it was
  delivered until it was dropped, and the finding 4.6 seconds behind it was
  dropped with it — lost, not delayed. ADR 0008 now rejects unreadable records
  before they reach the retry policy, and E1's third run (13 October)
  confirmed it: the record was reported in 11 seconds, and nothing was held
  or lost. E4 (ten
  times the volume) stored all 10,000 findings with a 2.5-minute peak backlog
  and no alarm. E3 (the schedule disabled) found that the incidents-current alarm's
  single 45-minute window, clock-aligned, let a 56-minute gap pass unreported.
  Re-defined as three 15-minute windows, it fired in the 11 October re-run,
  but 77 minutes after the last run, because the default sliding evaluation
  judges on older real data points before missing ones. Judged now on a
  wall-clock window of nine 5-minute periods, it fired 49 minutes 41 seconds
  after the last run in the third run, inside the designed 45 to 50.

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
  The September 2026 invoices put the idle baseline at about $25 a month net
  and the API at about $2.25 a day while up (`docs/evaluation.md`, section
  2) — both higher than the first review's estimates, which this review
  corrects.
- Cost is measured, not assumed: a monthly budget with alerts, Cost Explorer
  attribution by service, `scripts/measure.py` reporting cost per thousand
  findings for a period, and the invoices read service by service.
- Spend that bought nothing was removed when measured: an idle OpenSearch
  domain (ADR 0004, ~$25 a month).
- The additions since v1 cost almost nothing: the model triage well under a
  dollar a month at current volume, the threat-intelligence feeds on free
  tiers with a cache that keeps them there, the observability stack within
  CloudWatch's free allowance but for a couple of dollars, the honeypot
  about $6.70 a month while it exists, half of that its public address.

**Gaps / next step**
- The NAT gateway is half the API's daily cost. ADR 0009 prices its
  replacement — the task in a public subnet with its own address, the
  security group still admitting only the load balancer, $1.08 a day
  saved — and defers it while the stack runs on demand, where the gateway
  costs cents a session.
- The Kinesis shard is the largest idle item — $10.80 a month, over 40% of
  the baseline — for a pipeline moving about a thousand findings a day. ADR
  0010 keeps it through v2.0.0: a queue would do the work for cents, but
  the retry policy, objective 2 and three experiments are statements about
  a shard, and the switch is priced at the measurements a queue would have
  to earn; the record is re-opened after v2.0.0.
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
| Operational Excellence | IaC + ADRs; no CI/CD, no tests | CI with three suites and cdk-nag, the scanners gating the deploy since 19 October, OIDC deploys that end by running the correlator once, SLO runbook; single environment |
| Security | Isolation, enforced auth with required MFA, gated remediation; single user, no roles | The above plus tested least privilege, server-side approval tokens, contained model triage, control-change alarms, a bounded egress boundary; two roles since 17 October and a WAF and per-user limit since the 18th, each driven past its limit once; pipeline-borne changes unseen |
| Reliability | Managed backbone; single task/shard/Region | Retries and a failure queue with an objective on it, PITR everywhere and a restore rehearsed (14 and 18 minutes to a usable copy), resampling and retry in the advisory components; five chaos experiments run and four defects fixed; single task/shard/Region, the cut-over unrehearsed |
| Performance Efficiency | Right-sized; index-driven findings | The above plus a bounded, cached enrichment path; measured — a week of traffic at p50 6.3 s stored, and 10,000 findings at 200 a second with none lost and a 2.5-minute peak backlog |
| Cost Optimization | Measured and controlled; NAT, manual teardown | The above with cost per thousand findings measured ($4.67 to $9.13); the NAT gateway and the shard each decided in an ADR (0009 deferred, 0010 kept); manual teardown |
| Sustainability | On-demand, right-sized | On-demand, right-sized, Graviton where there is a choice |

The theme has not changed: production-*grade* standards — isolation, IaC,
enforced auth, gated response, tested privilege, measured cost — with
demo-appropriate simplifications named rather than hidden. What changed is
that the first review's largest gaps, no pipeline and no tests, are the parts
of the system a reviewer can now check most easily.
