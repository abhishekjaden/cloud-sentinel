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
| queued, normal traffic | EventBridge event → stream arrival | 920 | 0.8 s | 7.5 s | 17.1 s | 21 Oct 2026, the 7.8 days of the organization's own traffic from 00:00 UTC on the 14th, after E1's last run (`docs/evaluation-week.json`, `measure.py --since 2026-10-14T00:00Z`). The 4.6-day reading of 17 Oct, 786 findings since the E1 re-run's rollback: 0.8 s, 7.5 s, 15.5 s (`docs/evaluation-normal.json`) |
| stored, normal traffic | stream arrival → written | 920 | 6.3 s | 10.3 s | 12.0 s | 21 Oct 2026, as above. 17 Oct over 4.6 days: 6.1 s, 10.4 s, 11.9 s. First measured 13 Oct over about 17 hours of the same traffic as 610 findings, 6.3 s and 10.2 s, read from the terminal — the figure the paper quotes |
| ingested, normal traffic | EventBridge event → stored | 920 | 7.4 s | 17.0 s | 27.6 s | 21 Oct 2026, as above. 17 Oct: 7.2 s, 13.4 s, 22.4 s |
| correlated, normal traffic | first finding seen → incident made (includes the 15-minute schedule) | 9 | 11.1 min | 16.4 min | 16.4 min | 21 Oct 2026, as above — nine incidents, so a reading, not a distribution. 17 Oct, four incidents: 11.5, 16.4, 16.4 min |
| triaged, normal traffic | incident made → first note written | 4 | 8.6 min | 8.6 min | 8.6 min | 17 Oct 2026, four incidents. The week's figure, n = 9 at 40.6 h, 154.9 h, 154.9 h, is not this latency and is not entered as it: a note is rewritten whenever the prompt changes or the incident gains activity, the table keeps only the latest, and the three revisions of the 17th and 20th rewrote every note in the week, so those nine gaps run to the latest note (`docs/evaluation-week.json` holds them under `triaged`). From the deploy of 21 Oct a note keeps the first note's time (`first_triaged_at`), and the next week's measurement is to it |
| queued | EventBridge event → stream arrival | 10,075 | 2.2 s | 24.7 s | 27.2 s | 8 Oct 2026, E4 — a 200/s flood; the sender's clock was 20 s ahead, so read these 20 s short |
| stored | stream arrival → written | 10,075 | 1.3 min | 2.4 min | 2.5 min | 8 Oct 2026, E4 — the single shard's consumer draining a burst at about 50 records a second |
| ingested | EventBridge event → stored | 10,075 | 1.4 min | 2.8 min | 3.0 min | 8 Oct 2026, E4; 20 s short, as `queued` |
| correlated | first finding seen → incident made (includes the 15-minute schedule) | 100 | 7.8 min | 7.8 min | 7.8 min | 8 Oct 2026, E4 — all 100 incidents in one run |
| triaged | incident made → note written (includes the schedule, the five-per-run budget and the model) | 95 | 2.3 h | 4.6 h | 4.6 h | 8 Oct 2026, E4 — a hundred incidents at twenty an hour: the budget's drain rate |
| control change reported | API call → message on the topic | 6 | < 1 min | < 1 min | < 1 min | 3 Oct 2026, E5; 8 Oct 2026, E2 and E3; 21 Oct 2026, R1 (two `DeleteTable` calls, both in the inbox within the minute) |
| control change alarmed | API call → alarm in ALARM | 8 | 1.2 min | 1.6 min | 1.6 min | 8 Oct 2026, E2 (73 s and 91 s) and E3 (85 s); 11 Oct 2026, E3 re-run (78 s and 73 s) and third run (54 s and 69 s); 21 Oct 2026, R1 (98 s) |
| control change cleared | last change → alarm back to OK | 2 | 15.0 min | 16.0 min | 16.0 min | 11 Oct 2026, E3 third run (16 min); 21 Oct 2026, R1 (15 min 0 s) — the sliding evaluation judges on the last real data point for three periods before silence counts as not breaching; a slow clearing is recorded, not fixed (`docs/chaos-experiments.md`, R1) |
| loss reported | failure-queue message → alarm | 3 | 3.0 min | 3.3 min | 3.3 min | 7 Oct 2026, E1 (3 min); 12 Oct 2026, E1 re-run (2 min 52 s); 13 Oct 2026, E1 third run (3 min 16 s) |
| alarm notified | alarm state change → email in the operator's inbox, by Gmail's receipt time | 2 | < 1 s | < 1 s | < 1 s | 13 Oct 2026, the delivery check after the topic-policy fix — a forced state change, so delivery, not detection; before it, 0 of 49 notification attempts since 20 Sep were delivered (`docs/slos.md`) |
| unreadable record reported | stream arrival → failure-queue message | 1 | 11 s | 11 s | 11 s | 13 Oct 2026, E1 third run, under ADR 0008 — the ten-second batching window, then one invocation |
| outage alarmed | first record held on the shard → findings-fresh in ALARM | 2 | 10.5 min | 12.1 min | 12.1 min | 8 Oct 2026, E2 re-run (ADR 0007), held by a failing write; 12 Oct 2026, E1 re-run, held by a record that cannot be read |
| silence alarmed | last completed correlation run → incidents-current in ALARM | 1 | 49.7 min | 49.7 min | 49.7 min | 11 Oct 2026, E3 third run, on the wall-clock window — 45 to 50 minutes by design; the superseded three-window definition took 76.9 min in the re-run (`docs/chaos-experiments.md`) |

The five `normal traffic` rows are the organization's own findings over a
week — 7.8 days, 920 findings, with the 4.6-day reading of 17 October kept
beside each for comparison — and the five rows after them are E4, the
pipeline under ten times its volume. Under normal traffic `stored` reads
seconds: a batch that is not queued behind nine thousand others is written
within its ten-second window, and the 12.0 s maximum is that window plus the
write. The week moved no median by more than 0.2 s; `ingested`'s 95th
percentile rose from 13.4 s to 17.0 s and its maximum from 22.4 s to 27.6 s,
which is `queued` — EventBridge to the stream — stretching at the tail, not
the normalizer. `measure.py` also reports `detected`, the finding's own
creation time to its write; over this traffic it reads in thousands of hours,
because Security Hub re-emits findings it first created in June, so it is
not a latency of the pipeline and is left out.

## 2. Cost

`scripts/measure.py` divides the audit account's Cost Explorer total for the
period by the findings stored in it.

| Period | Findings | Cost | Per 1,000 findings | Notes |
|---|---|---|---|---|
| 12–17 Oct 2026, 4.6 days | 786 | $3.67 | $4.67 | the audit account's Cost Explorer total for the period (`docs/evaluation-normal.json`): the Kinesis shard $1.80, Security Hub $0.69, Inspector $0.66, KMS $0.19, the rest under a dollar together; not a full month, and the API was not up |
| 14–21 Oct 2026, 7.8 days | 920 | $8.40 | $9.13 | the audit account's Cost Explorer total for the period as posted by the 21st, which lags about a day (`docs/evaluation-week.json`): the Kinesis shard $2.60; Bedrock $2.04 — the three prompt revisions re-noting every open incident, and the evaluation runs of 18 to 20 October, which call the model on this account from the operator's machine; Security Hub $1.15, Inspector $0.93, Config $0.79, KMS $0.27, EC2-Other $0.12, Secrets Manager $0.10. Per thousand findings this is twice the 4.6-day figure, and the difference is the model: without Bedrock the period reads $6.91 per 1,000. The API session of the 21st (IST) is in it at what its hour cost — load balancing $0.05, WAF $0.02, ECS $0.01; the honeypot is not, since it runs in the workload account |
| | | | | pending — the first full month with the stamps |

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
  addresses $0.34, the task $0.28. The gateway alone is half. The WAF added
  in October (one web ACL, four rules) adds about $0.30 a day at list price
  while the stack is up; it is read off the next invoice, not estimated here.

So always-on, the plan for the application window, is $25 + 30 × $2.25 ≈
**$93 a month net, about ₹10,500 with GST**, not the $40 planned. Two
levers, in order of return: run the task in a public subnet with its own
address and no NAT gateway (saves about $1.10 a day; the security group
still admits only the load balancer), and replace the shard with a queue
(saves $10.80 a month; costs the 24-hour replay by sequence number that E2
relies on). Both together bring always-on to about $50 net. Each is a
decision, not a fix: ADR 0009 proposes the first with its numbers, and ADR
0010 prices the second against the measurements a queue would have to earn.

The honeypot ran from 3 to 8 October — about ₹115 for four and a half days,
half of it the public address — and was destroyed after raising no GuardDuty
finding at all (`docs/triage-eval-protocol.md`, section 1). The second run,
12 to 22 October, nine days and nine hours, cost $2.26 before GST on the
workload account's Cost Explorer — the instance $0.94, its volume $0.19,
its public address $1.12 — about ₹217, ₹256 with GST: ₹23 a day, half of it
the address, as the first run was. While it exists it costs about $7 a
month. The model triage stays well under
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
| 17 Oct 2026 | 2026-10-17.1 | 10, independent | 24/30 | 3/3 | the first set the prompt's author did not write — the project author's ten cases, sealed until the prompt was deployed (`docs/triage-eval-protocol.md`, section 6). Two cases failed on every run: the test-data flag set on a real-data case for its made-up-looking bucket and role names, a prompt defect; and a lone suspicious-domain query rated medium against a band of low alone, pending adjudication with the guide. 15 critical, 0 high, 12 medium, 3 low across the thirty answers |
| 18 Oct 2026 | 2026-10-17.1 | 15, independent: 10 written + 5 honeypot | 39/45 — honeypot 15/15, written 24/30 | 3/3 | the honeypot's five single-finding SSH brute-force incidents, the first cases nobody wrote, labelled low–medium by the project's author and the guide before their notes were read (`docs/triage-eval-protocol.md`, section 7): every answer *low*, the model's confidence medium on the two addresses not listed as malicious and high on the three that were. The written ten repeated the 17 October result, the same two cases failing for the same stated reasons. Five cases of one pattern, so one piece of evidence, not five |
| 19 Oct 2026 | 2026-10-17.1 | 15, independent, on the corrected mechanics | 42/45 — honeypot 15/15, written 27/30 | 3/3 | the re-baseline after the converter's severity scale and the correlator's `Behavior` stage were corrected (ADR 0005). Expected 24/30; the bucket-writes case's test-data flag cleared on all three runs with its severities two and six points higher — the flag is sensitive to severity, which the prompt says it should not be. The domain-reputation case unchanged; the honeypot five unchanged. The baseline for the next revision |
| 20 Oct 2026 | 2026-10-20.1 | 13 | 36/39 | 9/9 | the test-data markers named as a closed set and severity as no evidence (ADR 0005), with a thirteenth case as a regression check, which passed. The three misses are one case, the recon chain of 3 October, flagged as test data because the revision listed the documentation range 198.51.100.0/24 as a marker and that case uses 198.51.100.23 for its made-up attacker; `2026-10-20.2` drops the range. One case moved high → medium inside its band with only the flag's wording changed |
| 20 Oct 2026 | 2026-10-20.2 | 13 | 36/39 (39/39 on the widened band) | 9/9 | the documentation range dropped from the marker list; the recon chain clear and critical again. The three misses are the new regression case, flag clear as intended but rated high against low–medium on every run for its payments-ledger bucket name — a step above a band copied from an innocuous twin; widened to low–high on the record with the original kept (ADR 0005). Two cases have now moved one step under changes confined to the flag's paragraph |
| 20 Oct 2026 | 2026-10-20.2 | 15, independent | 42/45 — honeypot 15/15, written 27/30 | 3/3 | exactly as expected, a second time; the flag's defect is closed on this set |
| 20 Oct 2026 | 2026-10-20.1 | 15, independent | 42/45 — honeypot 15/15, written 27/30 | 3/3 | exactly as expected: the bucket-writes case clear, the domain-reputation case medium as on every run (adjudication open), the honeypot five low; no severity moved |
| 22 Oct 2026 | 2026-10-20.2 | 20, independent: 10 written + 10 honeypot | 57/60 — honeypot 30/30, written 27/30 (60/60 on the band widened after the run, ADR 0005) | 3/3 | the honeypot's last five cases — the sixth, labelled on the 20th, and the four that arrived before it was destroyed on the 22nd, labelled that afternoon, all low–medium by the project's author and the guide, each stating no AI tool helped (`docs/triage-eval-protocol.md`, section 7, which also keeps the three label files the four took). Exactly as expected: every honeypot answer *low*, the model's confidence high on the eight addresses listed as malicious and medium on the two not, the five new addresses the most heavily reported the set has seen (1,056 to 4,799 AbuseIPDB reports at confidence 100) and none of them pulling the severity up; the written ten as on the 19th and 20th, the domain-reputation case failing as on every run — adjudicated the same afternoon by the writer and the guide, who widened its band to low–medium with the original kept (`docs/triage-eval-protocol.md`, section 6). Ten honeypot cases of one pattern — a lone SSH brute-force finding, never a chain — so still one piece of evidence, now ten times over |

The rows marked `independent` are the sets the prompt's author did not
write — the project author's ten, partly blind, and the honeypot's ten,
which nobody wrote. The honeypot ran from 12 to 22 October (nine days and
nine hours; the first run, 3–8 October, produced no incidents to label) and
is destroyed; every incident it drew was a lone SSH brute-force finding, so
its ten cases test one thing — that a listed address does not pull a lone
low-severity finding up — and nothing about chains, the test-data flag or
injection, which remain the written sets' evidence. Cases from a second
person are the independent source still to come.

## 4. The intrusion detector

The detector's record is the model card (`ml/MODEL_CARD.md`). Its figures
within one dataset are high and, as the card explains, mostly the dataset's
doing; what it can be trusted with on a network it was not trained on is
measured here.

| Date | Measurement | Result | Record |
|---|---|---|---|
| 13 Oct 2026 | Trained on all of the corrected CICIDS2017 (83 features), scored on all 63,195,088 flows of the corrected CSE-CIC-IDS-2018 | AUC 0.577; F1 0.082 at the served threshold; DoS Hulk 47 of 1,803,160 flows flagged | model card, 6.3 |
| 24 Oct 2026 | Three datasets — both corrected CIC releases and UNSW-NB15 — on fourteen shared features, trained on each and on each pair and tested on the rest; six expectations pushed before any table existed | G1 and G2 met; G3 not met, a model trained on UNSW-NB15 worse than chance on both CIC releases (AUC 0.260 and 0.363); G4 not met in any direction. Trained on two, tested on the third: AUC **0.634, 0.665, 0.884**, F1 0.250, 0.041, 0.069 | model card, 6.4; `docs/generalization-protocol.md` |
| 24 Oct 2026 | The same with the destination port added | five of six cross cells lower, three of them now below chance; leave-one-out 0.686, 0.617, 0.693 | model card, 6.4 |
| from 24 Oct 2026 | The honeypot's own flows, labelled by construction, scored by the model trained on all three (G5, G6) | running; ten days end 3 November | protocol, sections 3 and 6 |

The leave-one-out row is the figure the project quotes. It says a detector
trained on public datasets does not carry to a network it has not seen, and
the protocol's fourth expectation, missed, fixed the conclusion before the
run: a detector for this platform should be trained on this platform's
traffic.

## 5. The controls

| Experiment | Objective | Result |
|---|---|---|
| E5, a control changed by hand | 8 | every expected signal, within a minute (`docs/chaos-experiments.md`) |
| E1, a record the normalizer cannot read | 1, 2, 8 | every expected signal; retries immediate rather than spaced, and the alarm clears itself after one quiet window — both recorded. **Re-run under ADR 0007 (12 Oct)**: the record held the shard for 60 min 17 s and findings-fresh fired at 12 min; Lambda redelivered it alone 69 times and nothing behind it was delivered for the hour; at the drop the finding 4.6 s behind it was never stored by the automatic path — its own drop inferred from a second queue message, purged unread — and the 93 that arrived later were stored within 2 s, after waiting up to 13 min. ADR 0008 now rejects such a record at once. **Third run under ADR 0008 (13 Oct)**: every expected signal — reported to the failure queue 11 s after it arrived, the finding behind it stored by the same invocation, iterator age at most 10.9 s, findings-stored in ALARM 3 min 16 s after the message and OK one window later, findings-fresh unchanged |
| E2, the normalizer denied its table | 1, 2, 8 | the denial reported in 73 s; but a 16-minute outage sent all 200 findings to the failure queue after immediate retries, iterator age peaked at 11 s and findings-fresh never fired — the retry policy isolated poison records at the cost of outages. ADR 0007 changed it to an hour of retries; **re-run the same day**, a 25-minute denial lost nothing: iterator age climbed to 24 min, findings-fresh fired at 10.5 min, the queue stayed empty, and all 50 findings stored on rollback |
| E4, ten times the volume | 1, 2, 3 | 10,000 findings in 50 s, nothing lost, iterator age peaked at 2.5 min against the 5-minute threshold, the correlator made all 100 incidents in one 6-second run; the hypothesis's "ingested under a minute" was never possible for a 200/s burst into a 50/s consumer, and is recorded as such |
| Alarm delivery, found in E1's evidence rather than by an experiment | all | every alarm changed state as each experiment expected, and none told anyone: all 49 notification attempts since the topic's creation on 20 Sep were refused (`SNS:Publish` not authorized), because the topic's TLS-only policy had replaced the default that admits CloudWatch; the inbox held 15 control-change messages and no alarm. Fixed and **checked on 13 Oct**: a forced alarm's ALARM and OK notifications both executed within 46 ms of the state change and arrived, by Gmail's receipt times, within the same second — delivery checked, not detection |
| R1, a restore from point-in-time recovery | 8 (the deletions); the review's open gap | both tables restored to one instant as new tables: the incidents copy usable in 14 min 1 s, the findings copy — 3,728 items, two indexes — in 18 min 20 s; the incidents copy matched the live table exactly, the findings copy held every item the live table held at the instant plus the two rewritten since, as the expectation allowed; the copies' deletion reported in the inbox within the minute and alarmed in 98 s, nothing else firing through a deploy in the same window; the alarm cleared in 15 min against ten expected (`docs/chaos-experiments.md`, R1). The cut-over to a restored table is not rehearsed |
| E3, the correlation schedule disabled | 3, 8 | the disable reported in 85 s and the triage function unaffected; but a 56-minute gap between correlation runs never fired incidents-current, whose single clock-aligned 45-minute window measures "a whole window empty", not "none in 45 minutes". Re-defined as three 15-minute windows and **re-run on 11 Oct**: it fired, but 77 minutes after the last run, because the default sliding evaluation judges on older real data points before missing ones; now judged on a wall-clock window of nine 5-minute periods, and the **third run** fired 49 min 41 s after the last run, inside the designed 45 to 50 minutes |
| A deployment that broke the correlator, found by the alarm rather than by an experiment (18 Oct) | 3 | commit `197e1e7` moved the correlator to an index query without granting the index; every run from 10:46 UTC failed on `AccessDeniedException`, and incidents-current fired at 11:20:14 — 48 min 34 s after the last completed run, 14 s after the ninth empty window — and was delivered. Fixed in `6bb23ff`, pushed 53 min after the alarm, with a CDK test that fails on the template as shipped; the first completed run on the fixed role was at 12:19:24 with the same 12 incidents and 439 findings as before the break, and the alarm cleared at 12:20:14, exactly an hour after it fired. The deploy workflow now runs the correlator once after every deploy and fails if it errors (`6828416`). Nothing was lost; incidents were stale for the duration (`docs/slos.md`, objective 3) |
| The roles, the per-user limit and the WAF, driven past their limits once (21 Oct) | 6, 7 | an analyst's decision refused with 403 and an approver's recorded against a staged quarantine; 150 requests in 14 s from one identity: 110 answered, 40 refused with 429 and a Retry-After; 3,000 requests in 3 min 25 s from one address: 2,436 answered, 564 refused by the WAF, 589 counted blocked, about 400 admitted past the nominal 2,000 before the rule caught up. One session, one address, one identity (`docs/slos.md`, *The API session of 21 October*) |

## 6. What the numbers are not

- Not a detection rate. GuardDuty detects; the platform stores, correlates,
  enriches and advises. A finding GuardDuty does not raise never reaches it.
- Not an accuracy for the model. Thirty-six runs over twelve cases is
  evidence that the containment holds on those cases.
- Thin independent evidence for the model. The twelve cases were written with
  the prompt; the independent sets (`docs/triage-eval-protocol.md`) are the
  measurement that counts, and so far they are ten synthetic cases by the
  project's author and five real incidents of one pattern.
- Not a production SLA. Each objective's target is what the platform held at
  its volume; the alarms say when it stops.
- Not evidence that the intrusion detector works on this platform's traffic.
  Within one dataset it separates attack from benign almost perfectly;
  across three it does not (section 4), and the platform's own flows are
  still being collected.
