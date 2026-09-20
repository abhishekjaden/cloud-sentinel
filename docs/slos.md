# CloudSentinel — Service Level Objectives

What the platform promises, how each promise is measured, and what to do when
one is broken. Each objective has one CloudWatch alarm; every alarm notifies
the `cloudsentinel-alarms` SNS topic when it fires and again when it clears.

- **Pipeline objectives** (1–5) live in `cdk/lib/stacks/observability-stack.ts`
  and are graphed on the **CloudSentinel-SLOs** dashboard. They are persistent.
- **API objectives** (6–7) live in `cdk/lib/stacks/api-stack.ts` and are graphed
  on the **CloudSentinel-API** dashboard. Both exist only while the on-demand API
  stack is deployed, because the load balancer they measure does.

A test (`cdk/test/observability.test.ts`) fails if an alarm is added without
being documented here, or documented here without existing.

## Receiving alarms

Subscriptions are made outside CDK, so no address is committed to the
repository and a deploy never removes one. Once, from a terminal with the audit
profile:

```bash
aws sns subscribe --profile cs-audit --region us-east-1 \
  --topic-arn arn:aws:sns:us-east-1:118821712739:cloudsentinel-alarms \
  --protocol email --notification-endpoint you@example.com
```

Then confirm from the email AWS sends.

## Summary

| # | Objective | Alarm (`cloudsentinel-slo-…`) | Measured by | Target | Fires when |
|---|---|---|---|---|---|
| 1 | Findings are stored | `findings-stored` | failures between EventBridge and the findings table | 99.9% of findings, 28 days | any failure in 5 minutes |
| 2 | Findings are stored promptly | `findings-fresh` | normalizer iterator age | under 5 minutes in 99% of 5-minute windows | over 5 minutes, two windows running |
| 3 | Incidents stay current | `incidents-current` | completed correlation runs | a run at least every 45 minutes | none in 45 minutes |
| 4 | Remediation steps run | `remediation-runs` | router, recorder and executor errors | no step fails | any error in 5 minutes |
| 5 | Approvals are decided | `approvals-decided` | workflows that timed out | every approval decided within 24 hours | any expiry |
| 6 | The API is available | `api-available` | server errors over requests | 99.5% of requests, 28 days | over 5% failing for 15 minutes |
| 7 | The API is fast | `api-latency` | 95th-percentile response time | 95% of requests within 2 s | p95 over 2 s for 15 minutes |

## 1. Findings are stored — `cloudsentinel-slo-findings-stored`

**Promise.** Every finding GuardDuty, Security Hub or Inspector delivers to
CloudSentinel is written to the findings table.

**Measured by** the sum, per 5 minutes, of three counts — one for each place a
finding can be dropped:

- events EventBridge matched but could not deliver to the stream, after its own
  retries (`FailedInvocations` on the three ingestion rules);
- records the normalizer failed on (`RecordsFailed`). The normalizer catches an
  error per record, so one bad record does not fail its whole batch; the cost is
  that such failures never reach Lambda's `Errors` metric, because the
  invocation succeeds either way. The normalizer counts them itself and
  publishes the count in CloudWatch Embedded Metric Format;
- normalizer invocations that failed outright (Lambda `Errors`).

**Why alarm on the first failure.** At about a thousand findings a day, a 99.9%
objective allows roughly one lost finding a day. A burn-rate alert on an error
budget that small fires on the first failure anyway, so the alarm says so
directly.

**When it fires.** The dashboard's second row shows which of the three failed.
For the normalizer, open log group `/aws/lambda/CloudSentinel-Normalizer` and
search for `Failed to process record`. A record that fails inside the
normalizer is not retried, so the finding is missing from CloudSentinel — it is
still in the console of the service that raised it, which is where to recover
it from.

**Known gap.** Failed records are dropped rather than retried. The fix is for
the normalizer to report partial batch failures, so Lambda retries a failed
record, with an on-failure destination that keeps what still fails.

## 2. Findings are stored promptly — `cloudsentinel-slo-findings-fresh`

**Measured by** the normalizer's iterator age: how long the oldest record in
each batch waited in the stream (the maximum per 5 minutes). Normally under ten
seconds, the batching window.

**Alarm.** Iterator age over 5 minutes in two consecutive windows — a sustained
backlog, not one retried batch. With no records arriving nothing is waiting, so
missing data is not a breach.

**When it fires.** The normalizer is falling behind or failing. Check its errors
and duration, and the stream's write throttling, on the dashboard.

## 3. Incidents stay current — `cloudsentinel-slo-incidents-current`

**Measured by** `CorrelationRunsCompleted`, which the correlator publishes as
the last thing a run does, after every incident has been written.

**Alarm.** No completed run in 45 minutes — three schedule intervals, so one
failed run does not fire it. Missing data *is* a breach: that is what makes the
count a heartbeat. A run that crashes, times out, or never starts because the
schedule was disabled publishes nothing, and nothing has to report the failure
for it to be noticed.

**When it fires.** Check `/aws/lambda/CloudSentinel-Correlator` and that the
`cloudsentinel-correlation` EventBridge rule is enabled. The dashboard graphs
run time against the 5-minute timeout: each run scans the whole findings table,
so run time grows with it.

**On first deploy** the alarm can fire once before the correlator's first run
publishes the metric, then clears within 15 minutes.

## 4. Remediation steps run — `cloudsentinel-slo-remediation-runs`

**Measured by** Lambda errors of the router, the approval recorder and the
executor, plus events the high-severity rule could not deliver to the router.

**Why not failed workflows.** Rejecting an approval fails the workflow — the API
sends `SendTaskFailure` — and a rejection is a decision, not a fault. Counting
failed executions would raise this alarm on every rejection.

**When it fires.** A router error matters most: EventBridge invokes the router
asynchronously, Lambda retries twice, and then the event is dropped, so that
finding never reaches a playbook. Check the state machine's recent executions
and the three functions' logs (`/aws/lambda/CloudSentinel-RemediationRouter`,
`-ApprovalRecorder`, `-RemediationExecutor`).

## 5. Approvals are decided — `cloudsentinel-slo-approvals-decided`

**Measured by** executions of `cloudsentinel-remediation` that timed out. The
workflow's 24-hour timeout is spent almost entirely waiting at the approval
gate, so a timeout means an approval nobody decided — an action judged
necessary that never ran.

**When it fires.** Review the finding and act on it manually if it still
applies. Sample findings injected for a demonstration raise approvals too, and
one left undecided fires this alarm a day later; that is the alarm working.

## 6. The API is available — `cloudsentinel-slo-api-available`

**Measured by** server errors — from the application (target 5xx) and from the
load balancer itself (ELB 5xx: no healthy task, or one that did not answer) —
as a share of requests.

**Alarm.** More than 5% of requests failing in three consecutive 5-minute
windows. At that rate a 28-day budget of 0.5% would be gone in under three days.
Windows with fewer than ten requests count as healthy: with the dashboard as
the only client, one error in a quiet window would otherwise read as an outage.

**When it fires.** If the load balancer is producing the errors, no healthy task
is serving; check the `cloudsentinel-api` service's events and the task logs.

## 7. The API is fast — `cloudsentinel-slo-api-latency`

**Measured by** the load balancer's target response time, 95th percentile.

**Alarm.** p95 over 2 seconds in three consecutive 5-minute windows.

**Caveat.** This target has not yet been checked against real traffic. `GET
/findings` scans the whole findings table on every request, which makes it the
first suspect; revisit the target once that route queries an index instead.

## Tracing

All five functions and the remediation state machine record AWS X-Ray traces.
A remediation is a single trace from the router through the state machine to
each playbook step: the router's call to start the workflow carries the
function's trace header — the AWS SDK adds it to every call made from Lambda —
and Step Functions continues that trace. Open traces from **X-Ray traces → Trace
Map** in the CloudWatch console.

What the traces do not yet show: calls the functions make to DynamoDB, SNS and
other services appear only as time spent inside the function, not as segments
of their own. Recording those needs the X-Ray SDK packaged with each function,
and the functions currently ship as plain source directories. The API on
Fargate is not traced.

## Advisory triage

The triage function ([ADR 0005](adr/0005-advisory-llm-triage.md)) has no
objective: a note helps an analyst but protects nothing, and nothing depends on
it. Its runs — notes written, answers rejected, model errors, throttled runs and
incidents still waiting — are graphed on the last row of the SLO dashboard, which
is where a model quota problem shows.

## Cost

| Item | Count | Free each month |
|---|---|---|
| Alarm metrics (a metric-math alarm is billed per metric it reads) | 12, plus 4 while the API is up | 10 |
| Custom metrics (published by the handlers, 5 of them by triage) | 8 | 10 |
| Dashboards | 2 | 3 |
| X-Ray traces | a few thousand to tens of thousands | 100,000 |

Within CloudWatch's free allowance — which an AWS Organization shares across its
accounts — the objectives cost about $0.20 a month. With none of it available
they would cost about $5 a month, most of it the dashboard.
