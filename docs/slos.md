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

**No notification was delivered before 13 October.** The topic enforces TLS
through a resource policy, and a topic's policy replaces the default one SNS
creates, which is what lets CloudWatch publish to a topic in its own account.
The only other statement the policy gained was EventBridge's, for the
control-change messages, which did arrive. So from the topic's creation on
20 September every alarm changed state as designed, and every notification was
refused: each alarm's history reads `Failed to execute action … CloudWatch
Alarms is not authorized to perform: SNS:Publish`. Nothing else recorded it,
and every experiment's expected signals checked an alarm's state rather than
its delivery, so every run passed. Found on 13 October, in the history behind
E1's third run. The topic's policy now allows CloudWatch to publish for this
account's alarms (`observability-stack.ts`, and a test).

**Check, expected signals** (written before the check). Deploy the
Observability stack, then force one alarm and let it clear:

```bash
aws cloudwatch set-alarm-state --profile cs-audit --alarm-name cloudsentinel-slo-findings-stored \
  --state-value ALARM --state-reason "Delivery check after the topic-policy fix"
```

1. The alarm's history shows the state change and, in the same second,
   `Successfully executed action arn:aws:sns:…:cloudsentinel-alarms` instead
   of the refusal.
2. One email arrives at each confirmed subscription within a minute.
3. At its next evaluation the alarm returns to OK, as its metric is zero, and
   a second email follows.
4. The forced change is a call that changes no control, so
   controls-unchanged stays OK.

**Observed, 13 October 2026** (times UTC). The Observability stack was
deployed at 14:16:18–14:16:25, changing the topic's policy and nothing else.
Before it, the alarms' histories — the console keeps 30 days, so they reach
back to 13 September, a week before the topic existed — held 49 notification
attempts, every one `Failed to execute action` and none that succeeded, all
of them in the topic's 23 days; the subscribed inbox held 15 messages from
the topic in that time, all of them control-change messages from
EventBridge, and not one alarm notification.

1. At 14:17:43.845 the forced change took findings-stored to ALARM, and at
   14:17:43.884 its history read `Successfully executed action
   arn:aws:sns:us-east-1:118821712739:cloudsentinel-alarms`.
2. The ALARM email reached the inbox at 14:17:43 by Gmail's receipt time,
   within the second: the first alarm notification the platform has
   delivered. (The timestamp in the message body is the alarm event's, which
   the alarm's history already gives; the receipt time is Gmail's own, and
   the inbox view shows it only to the minute, 19:47 IST.)
3. At its next evaluation, at 14:18:08.447, the alarm returned to OK; that
   action succeeded at 14:18:08.493, and the OK email arrived at 14:18:08.
4. No control-change message: nothing else reached the inbox.

Every expected signal held. Since then, every experiment's expected signals
name the notification as well as the state (`docs/chaos-experiments.md`).

What this check shows is delivery, not detection: the alarm was put into
ALARM by an API call, not by a failure the pipeline noticed. The two
notifications were executed within 46 ms of their state changes, and Gmail's
receipt times fall in the same second; the action timestamps are
CloudWatch's and say when SNS was called, not when the mail arrived, so the
inbox latency is the receipt time's and is good to the second. The first run
to check detection and delivery together on an injected failure is E2's
matched re-run (`docs/chaos-experiments.md`), whose expected signals name
each notification.

## Summary

| # | Objective | Alarm (`cloudsentinel-slo-…`) | Measured by | Target | Fires when |
|---|---|---|---|---|---|
| 1 | Findings are stored | `findings-stored` | findings lost between EventBridge and the findings table | 99.9% of findings, 28 days | any loss in 5 minutes |
| 2 | Findings are stored promptly | `findings-fresh` | normalizer iterator age | under 5 minutes in 99% of 5-minute windows | over 5 minutes, two windows running |
| 3 | Incidents stay current | `incidents-current` | completed correlation runs | a run at least every 45 minutes | none in nine consecutive 5-minute windows, on a wall-clock window |
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
- records reported to the `cloudsentinel-failed-findings` queue
  (`NumberOfMessagesSent`), of two kinds. A record the normalizer can never
  store — one it cannot read, or one the table refuses as invalid — it
  reports there itself, at once (ADR 0008). A record whose write failed it
  hands back by sequence number, and Lambda delivers the batch again from it,
  for up to an hour (ADR 0007), reading nothing further from the shard in the
  meantime; only when the record is an hour old does Lambda report it there
  and move on — taking with it anything behind it that has also passed the
  hour (E1 re-run, 12 October 2026).

**What is not counted.** A record whose write the normalizer hands back. It is
retried, so a DynamoDB throttle or a slow write costs a retry rather than a
finding, and alarming on it would page somebody for something that fixed
itself. The normalizer publishes the count as `RecordsFailed`, and the
dashboard graphs it under *Retried, not lost*, next to the normalizer's own
`Errors`. A rising line there is the warning that comes before this objective
breaks.

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

Its body names the shard and the sequence numbers involved — the findings
themselves are not in it — and its `requestContext.condition` says which kind
it is: `RecordRejected`, with the reason, for a record the normalizer refused
at once, or `RecordAgeExceeded` for one Lambda gave up on after the hour. The
normalizer's own account is in `/aws/lambda/CloudSentinel-Normalizer`, where a
refused record is logged as `Rejected record <sequence number>` and a retried
one as `Failed to process record <sequence number>`, each with the exception
that caused it. A rejected record that is not a finding at all has nothing to
recover: something wrote to a stream only EventBridge writes to, and the
question is who.

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
The alarm itself clears after one quiet five-minute window whether or not the
message has been dealt with (E1, 7 October 2026): its state says a loss
happened; the dashboard line says whether it is still unrecovered.

## 2. Findings are stored promptly — `cloudsentinel-slo-findings-fresh`

**Measured by** the normalizer's iterator age: how long the oldest record in
each batch waited in the stream (the maximum per 5 minutes). Normally under ten
seconds, the batching window.

**Alarm.** Iterator age over 5 minutes in two consecutive windows — a sustained
backlog, not one retried batch. With no records arriving nothing is waiting, so
missing data is not a breach.

**When it fires.** The normalizer is falling behind — slow writes, a long
duration, write throttling on the stream. Check those on the dashboard.

**A normalizer that fails rather than slows.** Experiment E2
(`docs/chaos-experiments.md`) denied the normalizer its table for sixteen
minutes under the original two-retry policy: each batch was given up on
within a second, iterator age never passed eleven seconds, this alarm stayed
OK, and every finding of the period went to the failure queue. ADR 0007
changed the policy to retry for an hour so that a failing dependency holds
the shard and is reported here, at ten minutes, while the records wait to be
stored rather than leaving. The E2 re-run of 8 October confirmed it: a 25-minute
denial held every record, iterator age climbed to 24 minutes, this alarm
fired 10 min 30 s after the flood was sent, and all 50 findings were
stored when the denial was lifted (`docs/chaos-experiments.md`).

**A record that can never be stored.** The E1 re-run of 12 October put one
record that is not a finding on the stream under the same policy, and it held
the shard for the whole hour: this alarm fired 12 min 06 s after the record
arrived, the 93 findings that arrived behind it waited up to 13 minutes, and
the finding 4.6 seconds behind it was dropped with it at the hour — a loss
objective 1 reported 2 min 52 s later. The alarm then took 15 min 49 s to
clear rather than one window: with nothing arriving, it went on judging its
last two high samples until they left its evaluation range. ADR 0008 now
rejects such a record on first sight, so it never reaches this alarm: in
E1's third run (13 October) the record was reported to the failure queue 11
seconds after it arrived, the finding behind it was stored by the same
invocation, and this alarm did not change state. Should one ever hold the
shard again, it looks
like this alarm firing while the normalizer's log names the same sequence
number, with the same exception, about once a minute.

## 3. Incidents stay current — `cloudsentinel-slo-incidents-current`

**Measured by** `CorrelationRunsCompleted`, which the correlator publishes as
the last thing a run does, after every incident has been written.

**Alarm.** No completed run in nine consecutive 5-minute windows, judged on
a wall-clock evaluation window. On schedule every 45 minutes holds three
runs, so one failed run does not fire it, and nine empty windows mean no
completed run for 45 to 50 minutes. Missing data *is* a breach: that is what
makes the count a heartbeat. A run that crashes, times out, or never starts
because the schedule was disabled publishes nothing, and nothing has to report
the failure for it to be noticed. The window is wall-clock rather than
CloudWatch's default sliding one because a sliding evaluation retrieves older
data points than the windows it names and judges on the real ones first, so
a run from an hour before kept the alarm OK (the E3 re-run, below); a
wall-clock window retrieves exactly the nine periods and nothing older. It
accepts 5-minute periods but not 15-minute ones, hence nine of five rather
than three of fifteen.

**When it fires.** Check `/aws/lambda/CloudSentinel-Correlator` and that the
`cloudsentinel-correlation` EventBridge rule is enabled. The dashboard graphs
run time against the 5-minute timeout: since 18 October each run queries the
findings table's `source-time-index` for the threat findings in its lookback
rather than scanning the table, so run time grows with the threat findings in
the lookback, not with the table. A run that throws publishes nothing, which
is what this alarm is for — see what it found on 18 October, below.

**On first deploy** the alarm can fire once before the correlator's first run
publishes the metric, then clears once that run's 5-minute window has closed.

**What E3 found (8 October 2026).** With the schedule disabled for 51
minutes and 56 minutes between completed runs, this alarm never fired. It was
defined as one 45-minute period, and CloudWatch aligns a period to the clock,
so it breaches only when a whole aligned window is empty — somewhere between
45 and 90 minutes after the last run, and not at all for a gap that has a
run on each side of a boundary, as that one did. The promise above and the
alarm's arithmetic disagreed. The definition above is the corrected one —
three 15-minute windows, three of three — so that a 45-minute gap would
fire within 60 minutes of the last run whatever the clock says.

**What the re-run found (11 October 2026).** It did not. With the last run at
06:03 UTC and the schedule disabled at 06:05, the three windows after the
run's own were empty by 07:00, but the alarm fired at 07:19:51, 77 minutes
after the last run. On its default sliding window CloudWatch retrieves more
data points than the evaluation periods and judges on the real ones it finds
before treating missing ones as breaching, so the 06:03 run kept the alarm OK
until it left that range. The same rule made the 8 October arithmetic wrong.
The definition above is the second correction.

**What the third run found (11 October 2026).** With the last run at 08:36
UTC, the alarm fired at 09:25:41: 49 min 41 s after it, and 41 seconds after
the ninth empty window closed. It cleared 41 seconds after the first window
holding a run closed. The definition is verified.

**What it caught unprompted (18 October 2026).** The first alarm nobody
arranged. Commit `197e1e7`, pushed at about 10:35 UTC, moved the correlator
from scanning the findings table to querying its `source-time-index`; the
table is imported into the Ingestion stack by name, and `grantReadData()` on
a by-name import grants the table ARN and no index, so the role never held
`dynamodb:Query` on the index the new code read. The last completed run was
at 10:31:39 (12 incidents, 6 multi-stage, 439 findings correlated). The
deploy landed between that run and the next, and from 10:46:39 every
scheduled run died in `_recent_threat_findings` with `AccessDeniedException`
on the index — three times each, EventBridge's asynchronous invocation
retrying at about one and two minutes — at 10:46, 11:01, 11:16, 11:31, 11:46,
12:01 and 12:16. No run completed, so no `CorrelationRunsCompleted` was
published, and the alarm fired at 11:20:14: 48 min 34 s after the last
completed run and 14 s after the ninth empty window closed, as the third E3
run said it would. The email arrived in the inbox at 11:20 (16:50 IST), on a
Sunday afternoon, and the cause was read off the stack code before the log
was pulled; the log confirmed it. Findings kept being stored throughout — the
normalizer was untouched — so nothing was lost; incidents went stale for the
duration and the dashboard showed it.

The fix is `6bb23ff`: the role holds `dynamodb:Query` on the one index, named
rather than `index/*` as the API's role does, and a CDK test now fails on a
template without the grant (`cdk/test/observability.test.ts`). It was
pushed at 12:14 (17:43 IST), 53 minutes after the alarm, and the deploy
landed inside the 12:16 run's retries: that run's first attempt failed at
12:16:39 and its retry at 12:19:24 completed — 12 incidents, 6 multi-stage,
439 findings correlated, the same figures as the last run on the old code,
which is the check that the index query reads what the scan read. The
scheduled run at 12:31:39 completed likewise. The alarm returned to OK at
12:20:14 — 14 s after the 12:15–12:20 window holding the recovered run
closed, and 60 min 00 s after it had gone to ALARM, the two transitions nine
milliseconds apart on the minute. Incident building was down for
1 h 47 min 45 s between completed runs, of which 48 minutes passed before
anyone was told and 59 between the alarm and the recovery.

Two things this is evidence of. The alarm's definition held in anger exactly
as it did in the third E3 run: a change nobody tested against production
permissions was reported within 50 minutes, by email, without anyone
watching. And it was the only control that caught it: 343 backend tests mock
DynamoDB, 111 CDK tests pinned the correlator's permissions nowhere, and the
deploy workflow ends when CloudFormation returns. A post-deploy invocation of
the correlator from the workflow — one `lambda invoke`, failing the run on a
`FunctionError` — would have reported this at deploy time rather than 45
minutes later. It was added the same evening (`6828416`): the workflow
assumes a role in the audit account that may invoke the correlator and
nothing else, runs it once after the stacks are deployed, and fails on an
error. It covers the one function that runs on demand; the data-driven
functions still have only their alarms (`docs/well-architected-review.md`).

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

**The API session of 21 October 2026** (times UTC; the stack was up from
18:50 to 20:04, 1 h 14 min, and destroyed after). The Api stack is deployed
on demand, so the roles, the per-user limit and the WAF that shipped on
17–18 October were first exercised live together, from one laptop in
Chennai, with the outputs kept in the operator's session log.

- *Roles.* A second user was created in the `analysts` group. Against a
  made-up approval id the operator's token (in `approvers`) was answered
  404 — through the gate, nothing to decide — and the analyst's 403,
  "deciding an approval requires membership of the approvers group", while
  the analyst could list the queue (200). A sample
  `Backdoor:EC2/C&CActivity.B!DNS` finding at 19:23:42 staged a quarantine
  of `i-99999999` within three minutes; the operator's console showed
  Reject and Approve, the analyst's the same item with "Awaiting an
  approver's decision" and no buttons (`screenshots/approvals-approver-2026-10-21.png`,
  `screenshots/approvals-analyst-2026-10-21.png`); the operator rejected it
  at 19:29, recorded against his identity. An earlier attempt with a token
  issued more than an hour before was refused outright, 130 of 130 requests
  401: the hour's validity holds.
- *Per-user limit.* 130 sequential requests took longer than a minute from
  Chennai and all 130 were answered — the sliding window never held 120.
  150 requests ten at a time, 19:39:00–19:39:14: 110 answered, 40 refused
  with 429, and a request after the burst answered 429 with `Retry-After:
  13`. The ten short of 120 were the operator's own console, open and
  polling as the same identity.
- *WAF.* 3,000 unauthenticated requests to `/health`, twenty at a time,
  19:46:58–19:50:23: 2,436 answered, 564 refused with the load balancer's
  empty 403. `AWS/WAFV2 BlockedRequests` for the rate rule summed 589 over
  19:49–19:51 — the 564 plus the two console windows, blocked from the same
  address along with the loop. About 400 requests past the nominal 2,000
  were admitted before the rule caught up, which is the rule's evaluation
  interval at the rate the loop ran, not a defect.
- *Neither API alarm fired*: the 403s are the WAF's, not target errors, and
  the loop's latency stayed under the threshold.

What this is evidence of: that the three controls refuse what they are
meant to refuse, once each, with numbers. What it is not: a load test, a
latency measurement, or the API's behaviour under a distributed flood.

## 8. Controls change only through deployment — `cloudsentinel-slo-controls-unchanged`

Every objective above watches the pipeline doing its job. This one watches
the controls being switched off. An attacker who has reached the audit
account does not need to defeat detection; they need one API call to disable
it — delete the GuardDuty detector or add a filter that archives its findings,
disable the ingestion rule, rewrite the remediation state machine, schedule
the findings key for deletion, replace a function's code, drop a table, or
delete these alarms — and CloudTrail records every one.

**Measured by** CloudTrail management events, as EventBridge delivers them,
matched by twelve rules (`cloudsentinel-control-*`) that cover:

| Area | Calls |
|---|---|
| The remediation state machine | `UpdateStateMachine`, `DeleteStateMachine` |
| The platform's EventBridge rules (`cloudsentinel-*`) | `PutRule`, `DeleteRule`, `DisableRule`, `EnableRule`, `PutTargets`, `RemoveTargets` |
| KMS keys | `DisableKey`, `ScheduleKeyDeletion`, `PutKeyPolicy`, `DisableKeyRotation`, `DeleteAlias` |
| GuardDuty | detector deleted or updated, members or the administrator disassociated, organisation configuration or publishing destination changed, and a trusted-IP set or a filter created or updated — the two ways to silence findings without touching the detector |
| The platform's functions (`CloudSentinel-*`) | code or configuration updated, function deleted, reserved concurrency set (zero disables a function); the normalizer's stream mapping updated or deleted |
| The platform's tables (`cloudsentinel-*`) | `DeleteTable`, `UpdateTable`, `UpdateTimeToLive`, `UpdateContinuousBackups` |
| The platform's IAM roles (`CloudSentinel-*`, as CloudFormation names them after their stacks) | `PutRolePolicy`, `DeleteRolePolicy`, `AttachRolePolicy`, `DetachRolePolicy`, `UpdateAssumeRolePolicy`, `PutRolePermissionsBoundary`, `DeleteRole` — the way a function is silenced without touching it: deny its role a write |
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
