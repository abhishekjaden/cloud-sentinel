# CloudSentinel — Service Level Objectives

What the platform promises, how each promise is measured, and what to do when
one is broken. Each objective has one CloudWatch alarm; every alarm notifies
the `cloudsentinel-alarms` SNS topic when it fires and again when it clears.

- **Pipeline objectives** (1–5 and 8) live in `cdk/lib/stacks/observability-stack.ts`
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
| 1 | Findings are stored | `findings-stored` | findings lost between EventBridge and the findings table | 99.9% of findings, 28 days | any loss in 5 minutes |
| 2 | Findings are stored promptly | `findings-fresh` | normalizer iterator age | under 5 minutes in 99% of 5-minute windows | over 5 minutes, two windows running |
| 3 | Incidents stay current | `incidents-current` | completed correlation runs | a run at least every 45 minutes | none in 45 minutes |
| 4 | Remediation steps run | `remediation-runs` | router, recorder and executor errors | no step fails | any error in 5 minutes |
| 5 | Approvals are decided | `approvals-decided` | workflows that timed out | every approval decided within 24 hours | any expiry |
| 6 | The API is available | `api-available` | server errors over requests | 99.5% of requests, 28 days | over 5% failing for 15 minutes |
| 7 | The API is fast | `api-latency` | 95th-percentile response time | 95% of requests within 2 s | p95 over 2 s for 15 minutes |
| 8 | Controls change only through deployment | `controls-unchanged` | CloudTrail calls that change a control, by a caller other than the CDK execution role | none | any in 5 minutes |

## 1. Findings are stored — `cloudsentinel-slo-findings-stored`

**Promise.** Every finding GuardDuty, Security Hub or Inspector delivers to
CloudSentinel is written to the findings table.

**Measured by** the sum, per 5 minutes, of the two counts that mean a finding
is gone:

- events EventBridge matched but could not deliver to the stream, after its own
  retries (`FailedInvocations` on the three ingestion rules);
- batches Lambda gave up on (`NumberOfMessagesSent` on the
  `cloudsentinel-failed-findings` queue). The normalizer hands back the sequence
  number of every record it could not store, and Lambda rewinds the shard and
  delivers those records again; only when the retries are exhausted does it
  report the batch to that queue and move on.

**What is not counted.** A record the normalizer fails on. It is retried, so a
DynamoDB throttle or a slow write costs a retry rather than a finding, and
alarming on it would page somebody for something that fixed itself. The
normalizer publishes the count as `RecordsFailed`, and the dashboard graphs it
under *Retried, not lost*, next to the normalizer's own `Errors`. A rising line
there is the warning that comes before this objective breaks.

**Why alarm on the first loss.** At about a thousand findings a day, a 99.9%
objective allows roughly one lost finding a day. A burn-rate alert on an error
budget that small fires on the first loss anyway, so the alarm says so directly.

**When it fires.** The dashboard's second row shows which of the two happened.
If it was the normalizer, a message is waiting in the queue:

```bash
aws sqs receive-message --profile cs-audit --region us-east-1 \
  --queue-url https://sqs.us-east-1.amazonaws.com/118821712739/cloudsentinel-failed-findings \
  --max-number-of-messages 10 --visibility-timeout 0
```

Its body names the shard and the range of sequence numbers Lambda gave up on —
the findings themselves are not in it. Read the normalizer's own account of why
in `/aws/lambda/CloudSentinel-Normalizer`, where each failure is logged as
`Failed to process record <sequence number>` with the exception that caused it.

To recover the findings, fix the cause first — otherwise the replay fails the
same way — then read the records back out of the stream, which keeps them for 24
hours:

```bash
ITERATOR=$(aws kinesis get-shard-iterator --profile cs-audit --region us-east-1 \
  --stream-name cloudsentinel-findings --shard-id shardId-000000000000 \
  --shard-iterator-type AT_SEQUENCE_NUMBER --starting-sequence-number <from the message> \
  --query ShardIterator --output text)
aws kinesis get-records --profile cs-audit --region us-east-1 --shard-iterator "$ITERATOR"
```

Records are base64-encoded EventBridge events; re-publishing them to the stream
with `kinesis put-record` puts them through the normalizer again, which
overwrites rather than duplicates. Past 24 hours the stream no longer holds
them and the findings have to come from the console of the service that raised
them; the queue keeps its pointers for 14 days either way, so the loss stays on
the record after the records are gone. Delete a message once it is dealt with —
the dashboard's *batches awaiting recovery* line is what is still outstanding.

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

**Caveat.** This target has not yet been checked against real traffic. No route
scans any more — `/findings` merges one indexed query per source and `/stats`
counts a partition at a time — so the work per request no longer grows with the
table, and the target should hold as it fills.

## 8. Controls change only through deployment — `cloudsentinel-slo-controls-unchanged`

Every objective above watches the pipeline doing its job. This one watches
the controls being switched off. An attacker who has reached the audit
account does not need to defeat detection; they need one API call to disable
it — delete the GuardDuty detector or add a filter that archives its findings,
disable the ingestion rule, rewrite the remediation state machine, schedule
the findings key for deletion, replace a function's code, drop a table, or
delete these alarms — and CloudTrail records every one.

**Measured by** CloudTrail management events, as EventBridge delivers them,
matched by eleven rules (`cloudsentinel-control-*`) that cover:

| Area | Calls |
|---|---|
| The remediation state machine | `UpdateStateMachine`, `DeleteStateMachine` |
| The platform's EventBridge rules (`cloudsentinel-*`) | `PutRule`, `DeleteRule`, `DisableRule`, `EnableRule`, `PutTargets`, `RemoveTargets` |
| KMS keys | `DisableKey`, `ScheduleKeyDeletion`, `PutKeyPolicy`, `DisableKeyRotation`, `DeleteAlias` |
| GuardDuty | detector deleted or updated, members or the administrator disassociated, organisation configuration or publishing destination changed, and a trusted-IP set or a filter created or updated — the two ways to silence findings without touching the detector |
| The platform's functions (`CloudSentinel-*`) | code or configuration updated, function deleted, reserved concurrency set (zero disables a function); the normalizer's stream mapping updated or deleted |
| The platform's tables (`cloudsentinel-*`) | `DeleteTable`, `UpdateTable`, `UpdateTimeToLive`, `UpdateContinuousBackups` |
| These alarms and their topic | `DeleteAlarms`, `DisableAlarmActions`, `PutMetricAlarm` on `cloudsentinel-slo-*`; `DeleteTopic`, `SetTopicAttributes`, `RemovePermission`, `Unsubscribe` on `cloudsentinel-alarms` |

Each rule leaves out one caller: a session under the CDK bootstrap execution
role (`cdk-hnb659fds-cfn-exec-role-…`), which is how every legitimate change
reaches these resources, whether from the deploy workflow or from `cdk deploy`
at a terminal. Everything else — a console session, an access key, a role
assumed by hand — is reported. The rules cover their own names, so disabling
the watch is itself reported.

Each matched call goes to two places: the alarm topic, as a message naming the
call, the caller's ARN and type, the source address and user agent, the time,
and the event ID; and the `/cloudsentinel/control-changes` log group, as the
whole event with its request parameters, kept for a year. A metric filter on
that group counts the events, and the alarm fires on any count in five
minutes. The dashboard's last graph row shows the count and the twenty most
recent changes with who made them.

**When it fires.** Read the topic message. If the change was yours — a hotfix
in the console, a key rotated by hand — record why, in the incident log or the
commit that follows. If it was not, treat it as an intrusion in progress and
start from the caller: the ARN says which role or user, and the audit
account's CloudTrail says what else that identity did. The control changed is
the one that would have reported the attacker, so check the others next.

**What it does not catch.** A change made through the execution role by a
compromised deployment pipeline — a malicious commit on `main`, a stolen
GitHub role — arrives looking like a deploy. That is the CI/CD boundary's
residual risk in the threat model, and the deploy workflow's diff in the run
log is the record to check. Nor does it see a call CloudTrail does not
deliver to EventBridge; the organisation trail, managed by Control Tower,
logs management events in every account, and this objective assumes it keeps
doing so.

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
it. Its runs — notes written, answers asked for again, answers given up on, model
errors, throttled runs and incidents still waiting — are graphed on the last row
of the SLO dashboard, which is where a model quota problem shows.

The two rejection lines separate a recovery from a loss, as the ingestion graphs
do. The model malforms a field occasionally — measured at roughly one ask in
twenty-one — and the second ask is normally good, so *answers asked for again*
rising is the prompt or the model drifting, and it moves well before *answers
given up on* does.

## Threat-intelligence enrichment

The enricher ([ADR 0006](adr/0006-threat-intel-enrichment.md)) has no objective
either: a verdict informs an analyst, and an incident without one is still
correlated, triaged and reported. Its runs — indicators looked up, answered
from the cache, provider failures, function errors, indicators still waiting
and providers configured — share the row below triage on the SLO dashboard.

*Providers configured* is the line to glance at after a deploy. The stack
creates the providers' secret with empty keys so it deploys before the operator
has any; until the keys are filled in that line reads zero, every indicator
waits, and no error reports it. *Indicators awaiting a lookup* climbing while
*looked up* stays at ten a run is the per-run budget doing its job during a
flood, not a fault.

## Cost

| Item | Count | Free each month |
|---|---|---|
| Alarm metrics (a metric-math alarm is billed per metric it reads) | 12, plus 4 while the API is up | 10 |
| Custom metrics (published by the handlers, 6 by triage, 6 by the enricher; one by the control-change filter) | 16 | 10 |
| Dashboards | 2 | 3 |
| X-Ray traces | a few thousand to tens of thousands | 100,000 |

Within CloudWatch's free allowance — which an AWS Organization shares across its
accounts — the objectives cost about $2.10 a month, the custom metrics past the
free ten accounting for most of it. With none of it available they would cost
about $7.50 a month, most of it the dashboard. EventBridge delivers CloudTrail
events at no charge, and the control-change log group holds a few events a
month.
