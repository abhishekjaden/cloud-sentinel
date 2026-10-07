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
| ingested | EventBridge event → stored | | | | | pending |
| correlated | first finding seen → incident made (includes the 15-minute schedule) | | | | | pending |
| triaged | incident made → note written (includes the schedule and the model) | | | | | pending |
| control change reported | API call → message on the topic | 2 | < 1 min | < 1 min | < 1 min | 3 Oct 2026, E5 |
| control change alarmed | API call → alarm in ALARM | 2 | 1.4 min | 1.5 min | 1.5 min | 8 Oct 2026, E2 (73 s and 91 s) |
| loss reported | failure-queue message → alarm | 1 | 3 min | 3 min | 3 min | 7 Oct 2026, E1 |

The first three are filled from a normal week's traffic once the stamps have
been in place for one (they were added on 3 October 2026), and again under
load (E4).

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

The honeypot, deployed 3 October, adds about $6.70 a month: $3.05 for the
instance and $3.65 for its public address. The model triage stays well under
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

These cases were written by the prompt's author. The independent set — cases
written blind and honeypot incidents — is the next row, when it exists.

## 4. The controls

| Experiment | Objective | Result |
|---|---|---|
| E5, a control changed by hand | 8 | every expected signal, within a minute (`docs/chaos-experiments.md`) |
| E1, a record the normalizer cannot read | 1, 8 | every expected signal; retries immediate rather than spaced, and the alarm clears itself after one quiet window — both recorded |
| E2, the normalizer denied its table | 1, 2, 8 | the denial reported in 73 s; but a 16-minute outage sent all 200 findings to the failure queue after immediate retries, iterator age peaked at 11 s and findings-fresh never fired — the retry policy isolates poison records at the cost of outages, now an open decision |
| E3–E4 | 3, 1, 2 | written, not yet run |

## 5. What the numbers are not

- Not a detection rate. GuardDuty detects; the platform stores, correlates,
  enriches and advises. A finding GuardDuty does not raise never reaches it.
- Not an accuracy for the model. Thirty-six runs over twelve cases is
  evidence that the containment holds on those cases.
- Not a production SLA. Each objective's target is what the platform held at
  its volume; the alarms say when it stops.
