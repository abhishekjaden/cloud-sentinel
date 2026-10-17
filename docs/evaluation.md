# Evaluation

What has been measured about CloudSentinel, how, and what each number is
allowed to mean. This is the record the project's claims rest on; a figure
that is not here with its method is not a claim the project makes.

The roadmap's headline — "AI triage reduced mean time-to-triage by X%" — is
not measured and will not be, because it needs analysts triaging the same
incidents with and without the notes, and this project has one. What is
measured instead is what the platform itself can evidence: how fast findings
move through it, what that costs, whether the advisory model agrees with
written labels, and whether its controls notice being switched off.

## 1. Latency

Every finding is stamped when EventBridge emitted it, when it reached the
stream and when the normalizer wrote it; every incident when it was first
made; every note when it was written. `scripts/measure.py` reads the gaps as
nearest-rank percentiles with the count behind each.

| Measure | Meaning | n | p50 | p95 | max | Measured |
|---|---|---|---|---|---|---|
| stored, normal traffic | stream arrival → written | 610 | 6.3 s | 10.2 s | — | 13 Oct 2026, about 17 hours of the organization's own traffic after the E1 re-run's rollback (`measure.py --since 2026-10-12T20:10:00Z`); read from the terminal and not yet committed as JSON — `normlat` in `scripts/e2-helpers.sh` measures it again into `docs/evaluation-normal.json` |
| queued | EventBridge event → stream arrival | 10,075 | 2.2 s | 24.7 s | 27.2 s | 8 Oct 2026, E4 — a 200/s flood; the sender's clock was 20 s ahead, so read these 20 s short |
| stored | stream arrival → written | 10,075 | 1.3 min | 2.4 min | 2.5 min | 8 Oct 2026, E4 — the single shard's consumer draining a burst at about 50 records a second |
| ingested | EventBridge event → stored | 10,075 | 1.4 min | 2.8 min | 3.0 min | 8 Oct 2026, E4; 20 s short, as `queued` |
| correlated | first finding seen → incident made (includes the 15-minute schedule) | 100 | 7.8 min | 7.8 min | 7.8 min | 8 Oct 2026, E4 — all 100 incidents in one run |
| triaged | incident made → note written (includes the schedule, the five-per-run budget and the model) | 95 | 2.3 h | 4.6 h | 4.6 h | 8 Oct 2026, E4 — a hundred incidents at twenty an hour: the budget's drain rate |
| control change reported | API call → message on the topic | 4 | < 1 min | < 1 min | < 1 min | 3 Oct 2026, E5; 8 Oct 2026, E2 and E3 |
| control change alarmed | API call → alarm in ALARM | 7 | 1.2 min | 1.5 min | 1.5 min | 8 Oct 2026, E2 (73 s and 91 s) and E3 (85 s); 11 Oct 2026, E3 re-run (78 s and 73 s) and third run (54 s and 69 s) |
| loss reported | failure-queue message → alarm | 3 | 3.0 min | 3.3 min | 3.3 min | 7 Oct 2026, E1 (3 min); 12 Oct 2026, E1 re-run (2 min 52 s); 13 Oct 2026, E1 third run (3 min 16 s) |
| alarm notified | alarm state change → email in the operator's inbox, by Gmail's receipt time | 2 | < 1 s | < 1 s | < 1 s | 13 Oct 2026, the delivery check after the topic-policy fix — a forced state change, so delivery, not detection; before it, 0 of 49 notification attempts since 20 Sep were delivered (`docs/slos.md`) |
| unreadable record reported | stream arrival → failure-queue message | 1 | 11 s | 11 s | 11 s | 13 Oct 2026, E1 third run, under ADR 0008 — the ten-second batching window, then one invocation |
| outage alarmed | first record held on the shard → findings-fresh in ALARM | 2 | 10.5 min | 12.1 min | 12.1 min | 8 Oct 2026, E2 re-run (ADR 0007), held by a failing write; 12 Oct 2026, E1 re-run, held by a record that cannot be read |
| silence alarmed | last completed correlation run → incidents-current in ALARM | 1 | 49.7 min | 49.7 min | 49.7 min | 11 Oct 2026, E3 third run, on the wall-clock window — 45 to 50 minutes by design; the superseded three-window definition took 76.9 min in the re-run (`docs/chaos-experiments.md`) |

The five flood rows are E4, which is the pipeline under ten times its
volume, not a normal day; the first row is seventeen hours of normal
traffic, and the flood rows are filled again from a normal week's traffic
once the stamps, added on 3 October 2026, have been in place for one. Under
normal traffic `stored` reads seconds, as the first row shows: a batch that
is not queued behind nine thousand others is written within its ten-second
window.

## 2. Cost

`scripts/measure.py` divides the audit account's Cost Explorer total for the
period by the findings stored in it.

| Period | Findings | Cost | Per 1,000 findings | Notes |
|---|---|---|---|---|
| | | | | pending — first full month with the stamps |

### September 2026, from the invoices

The first full month in which every component but the honeypot existed. AWS
India bills in rupees with 18% GST on top; the figures below are the invoiced
amounts before GST, with dollars at the month-end rate of about ₹96. The
log-archive account's invoice is not in hand; its charges are S3 storage for
CloudTrail and Config, a few rupees.

| Account | Net ₹ | ≈ $ | What it was |
|---|---|---|---|
| Audit — the platform | 3,004 | 31.3 | by service, below |
| Workload | 123 | 1.3 | one SageMaker training job for the attack-family model (₹115); S3, Config, GuardDuty |
| Management | 61 | 0.6 | the domain's hosted zone (₹49), Cost Explorer calls, Detective |
| **Three accounts** | **3,189** | **33.2** | ₹3,763 with GST |

The audit account by service:

| Service | Net ₹ | ≈ $ | Note |
|---|---|---|---|
| Kinesis | 1,037 | 10.80 | one provisioned shard: 720 hours at $0.015, to the cent. The largest line. |
| Security Hub | 456 | 4.75 | standards checks across the organisation |
| Inspector | 351 | 3.65 | |
| Config | 312 | 3.25 | the recorder and rules Security Hub's checks run on |
| EC2 | 309 | 3.20 | the NAT gateway, about 71 hours: the API was up roughly three days |
| Elastic Load Balancing | 147 | 1.55 | the ALB, the same hours |
| KMS | 103 | 1.05 | the customer-managed key and its requests |
| VPC | 94 | 1.00 | public IPv4 addresses for the ALB and the NAT gateway while up |
| ECS | 77 | 0.80 | the Fargate task, the same hours |
| Route 53 | 48 | 0.50 | one hosted zone |
| GuardDuty | 22 | 0.25 | |
| ECR | 21 | 0.20 | image storage |
| DynamoDB | 16 | 0.15 | every table, on demand |
| Macie, S3, data transfer | 11 | 0.10 | Macie's last days before it was disabled on 3 September (ADR 0004) |

Two figures quoted before this invoice were wrong, and are corrected here
rather than in the places that quoted them:

- **Idle is about $25 a month net, not $15–20** — ₹2,440, ₹2,880 with GST,
  across the three accounts with the serving layer and the training job taken
  out. The shard is over 40% of it and the native detection stack (Security
  Hub, Inspector, Config) another 45%; everything else — every table, every
  function, every key, the model's notes, the feeds — is about $3.
- **The API costs about $2.25 a day while up, not $1.60.** Over its ≈71
  hours: the NAT gateway $1.08 a day, the ALB $0.54, the three public
  addresses $0.34, the task $0.28. The gateway alone is half.

So always-on, the plan for the application window, is $25 + 30 × $2.25 ≈
**$93 a month net, about ₹10,500 with GST**, not the $40 planned. Two
levers, in order of return: run the task in a public subnet with its own
address and no NAT gateway (saves about $1.10 a day; the security group
still admits only the load balancer), and replace the shard with a queue
(saves $10.80 a month; costs the 24-hour replay by sequence number that E2
relies on). Both together bring always-on to about $50 net. Each is a
decision, not a fix, and gets an ADR if taken.

The honeypot ran from 3 to 8 October — about ₹115 for four and a half days,
half of it the public address — and was destroyed after raising no GuardDuty
finding at all (`docs/triage-eval-protocol.md`, section 1). While it exists
it costs about $6.70 a month. The model triage stays well under
a dollar a month at current volume; the threat-intelligence feeds are free.

## 3. The advisory model

The evaluation harness, its cases and what a pass means are in ADR 0005 and
`docs/triage-eval-protocol.md`. Results to date, each three runs of every
case against the live model:

| Date | Prompt | Cases | Passed | Injection attempts flagged | Note |
|---|---|---|---|---|---|
| 23 Sep 2026 | 2026-09-20.1 | 7 | 20/21 | 9/9 | the miss was a malformed answer the schema rejected; led to the resample |
| 3 Oct 2026 | 2026-10-03.1 | 7 | 18/21 | 9/9 | a prompt wording let an injected claim set the test-data flag; caught before deploy |
| 3 Oct 2026 | 2026-10-03.2 | 7 | 21/21 | 9/9 | the flag made structural-only |
| 3 Oct 2026 | 2026-10-03.3 | 7 | 21/21 | 9/9 | threat-intelligence verdicts added to the model's input |
| 3 Oct 2026 | 2026-10-03.3 | 12 | 33/36 | 9/9 | five cases added, three outside EC2; the three misses were one case rated a step above its band, adjudicated as a labelling error and widened on the record (ADR 0005); the model answered *medium* in none of 36 asks |
| 3 Oct 2026 | 2026-10-03.3 | 12 | 36/36 | 9/9 | rerun on the adjudicated band the same evening; every one of the 36 answers identical to the run before |
| 17 Oct 2026 | 2026-10-17.1 | 12 | 36/36 | 9/9 | the five severity steps defined (ADR 0005), judged against the cases: *medium* answered for the first time, on all three runs of the lone persistence command; the other two medium-centred cases stayed high at medium confidence; the 36 answers moved from 12 critical, 21 high, 0 medium, 3 low to 18, 12, 3, 3 |

These cases were written by the prompt's author. The independent set — cases
written blind and honeypot incidents — is the next row, when it exists; the
first honeypot run (3–8 October) produced no incidents to label.

## 4. The controls

| Experiment | Objective | Result |
|---|---|---|
| E5, a control changed by hand | 8 | every expected signal, within a minute (`docs/chaos-experiments.md`) |
| E1, a record the normalizer cannot read | 1, 2, 8 | every expected signal; retries immediate rather than spaced, and the alarm clears itself after one quiet window — both recorded. **Re-run under ADR 0007 (12 Oct)**: the record held the shard for 60 min 17 s and findings-fresh fired at 12 min; Lambda redelivered it alone 69 times and nothing behind it was delivered for the hour; at the drop the finding 4.6 s behind it was never stored by the automatic path — its own drop inferred from a second queue message, purged unread — and the 93 that arrived later were stored within 2 s, after waiting up to 13 min. ADR 0008 now rejects such a record at once. **Third run under ADR 0008 (13 Oct)**: every expected signal — reported to the failure queue 11 s after it arrived, the finding behind it stored by the same invocation, iterator age at most 10.9 s, findings-stored in ALARM 3 min 16 s after the message and OK one window later, findings-fresh unchanged |
| E2, the normalizer denied its table | 1, 2, 8 | the denial reported in 73 s; but a 16-minute outage sent all 200 findings to the failure queue after immediate retries, iterator age peaked at 11 s and findings-fresh never fired — the retry policy isolated poison records at the cost of outages. ADR 0007 changed it to an hour of retries; **re-run the same day**, a 25-minute denial lost nothing: iterator age climbed to 24 min, findings-fresh fired at 10.5 min, the queue stayed empty, and all 50 findings stored on rollback |
| E4, ten times the volume | 1, 2, 3 | 10,000 findings in 50 s, nothing lost, iterator age peaked at 2.5 min against the 5-minute threshold, the correlator made all 100 incidents in one 6-second run; the hypothesis's "ingested under a minute" was never possible for a 200/s burst into a 50/s consumer, and is recorded as such |
| Alarm delivery, found in E1's evidence rather than by an experiment | all | every alarm changed state as each experiment expected, and none told anyone: all 49 notification attempts since the topic's creation on 20 Sep were refused (`SNS:Publish` not authorized), because the topic's TLS-only policy had replaced the default that admits CloudWatch; the inbox held 15 control-change messages and no alarm. Fixed and **checked on 13 Oct**: a forced alarm's ALARM and OK notifications both executed within 46 ms of the state change and arrived, by Gmail's receipt times, within the same second — delivery checked, not detection |
| E3, the correlation schedule disabled | 3, 8 | the disable reported in 85 s and the triage function unaffected; but a 56-minute gap between correlation runs never fired incidents-current, whose single clock-aligned 45-minute window measures "a whole window empty", not "none in 45 minutes". Re-defined as three 15-minute windows and **re-run on 11 Oct**: it fired, but 77 minutes after the last run, because the default sliding evaluation judges on older real data points before missing ones; now judged on a wall-clock window of nine 5-minute periods, and the **third run** fired 49 min 41 s after the last run, inside the designed 45 to 50 minutes |

## 5. What the numbers are not

- Not a detection rate. GuardDuty detects; the platform stores, correlates,
  enriches and advises. A finding GuardDuty does not raise never reaches it.
- Not an accuracy for the model. Thirty-six runs over twelve cases is
  evidence that the containment holds on those cases.
- Not independent evidence for the model. The twelve cases were written with
  the prompt; the independent set (`docs/triage-eval-protocol.md`) is the
  measurement that would be.
- Not a production SLA. Each objective's target is what the platform held at
  its volume; the alarms say when it stops.
