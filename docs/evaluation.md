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

The first three are filled from a normal week's traffic once the stamps have
been in place for one (they were added on 3 October 2026), and again under
load (E4).

## 2. Cost

`scripts/measure.py` divides the audit account's Cost Explorer total for the
period by the findings stored in it.

| Period | Findings | Cost | Per 1,000 findings | Notes |
|---|---|---|---|---|
| | | | | pending — first full month with the stamps |

Known standing costs, from billing rather than measurement: about $15–20 a
month idle; the API about $1.60 a day while deployed; the honeypot about $3 a
month while deployed; the model triage well under a dollar a month at current
volume; the threat-intelligence feeds free.

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
| E1–E4 | 1, 2, 3, 8 | written, not yet run |

## 5. What the numbers are not

- Not a detection rate. GuardDuty detects; the platform stores, correlates,
  enriches and advises. A finding GuardDuty does not raise never reaches it.
- Not an accuracy for the model. Thirty-six runs over twelve cases is
  evidence that the containment holds on those cases.
- Not a production SLA. Each objective's target is what the platform held at
  its volume; the alarms say when it stops.
