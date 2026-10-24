# ADR 0010: The Kinesis shard stays, measured against a queue

## Status
Proposed, 2026-10-24, with the numbers; not yet decided. The drafter's
recommendation is to keep the shard through v2.0.0, for the reasons under
Rationale; the author decides, and whichever way it goes is recorded here
with the date.

## Context
Every finding reaches the normalizer through one provisioned Kinesis shard:
EventBridge writes to the stream, the normalizer reads it in batches of up
to 100 within a ten-second window, and the stream keeps 24 hours of records.
The shard is the platform's largest idle cost — 720 hours at $0.015 is
$10.80 a month, ₹1,037 on the September invoice, over 40% of the idle bill
(`docs/evaluation.md`, section 2). The platform stores about 4,000 findings
a day under normal traffic; a shard carries a thousand records a second.

An SQS queue would carry the same traffic for nothing: 120,000 messages a
month is inside the free tier's first million requests, and a FIFO queue,
if ordering mattered, would cost about $0.06. The question is what the
shard buys for $10.80 a month, and the answer is written across three
experiments and two decision records.

What the shard is, in this design, as recorded:

- **Ordering and a replay by sequence number.** The stream is the record of
  what arrived, in order, for 24 hours. E2's first run lost 200 findings of
  a 16-minute outage to manual recovery, and the only recovery would have
  been a replay of three sequence ranges by hand within the day
  (`docs/chaos-experiments.md`, E2; `docs/slos.md`, objective 1's response).
  A queue keeps a failed message only in its dead-letter queue, with no
  order and no range to replay.
- **The retry policy's unit is the shard.** ADR 0007 made a failing write
  retry until a record is an hour old, holding the shard so that an outage
  heals itself; ADR 0008 rejects at once a record that can never be stored,
  because the E1 re-run showed the hold is total — one record held
  everything behind it. Both are statements about a shard. A queue has no
  head of line: each message is retried on its own visibility timeout, so
  a poison message blocks nothing — the E1 defect does not exist on a queue
  — and an outage's messages pile up in the queue rather than on the shard.
- **Objective 2 is defined on the shard.** `findings-fresh` alarms on the
  normalizer's iterator age over five minutes in two windows; it fired at
  10.5 and 12.1 minutes in the two held-shard experiments. A queue's
  equivalent is `ApproximateAgeOfOldestMessage`, a different metric with a
  different meaning, which would need its own threshold and its own
  experiment to earn a number.
- **The flood figure is the shard's.** E4's 10,000 findings at 200 a second
  were drained at about 50 a second by one shard's consumer, backlog peaking
  at 2.5 minutes, none lost. A queue with the normalizer at its default
  concurrency would drain faster and the figure would no longer be the one
  the paper quotes.

## Decision
Proposed: keep the shard through v2.0.0. Re-open this record after v2.0.0,
when a queue can be measured on its own terms: a redefined objective 2, a
re-run of E1, E2 and E4 against it with expectations written first, and a
recovery procedure for a dead-letter queue written and rehearsed, before
the $10.80 a month is taken.

## Rationale
- **The saving is real and small: $10.80 a month, ₹130 a month, 40% of
  idle.** Against the ₹5,000 ceiling it is 2.6%. The NAT gateway in ADR 0009
  saves three times as much per month of always-on serving and changes
  nothing that was measured.
- **The cost of switching is three experiments and an objective.** The
  shard's behaviour under an outage, a poison record and a flood is what
  `docs/chaos-experiments.md` records and what the ICSSS 2026 paper reports;
  ADRs 0007 and 0008 are decisions about a shard. Replacing it does not
  invalidate those records — they stay true of the design they measured —
  but it makes them records of a previous design, and the new one would
  have earned none of its own numbers. A queue's advantages are real (no
  head of line, a 14-day retention, a dead-letter queue instead of a replay
  by hand), and they are the reason to measure it rather than assume it.
- **The replay is the one thing a queue cannot give back.** A dead-letter
  queue holds what failed; the stream holds everything that arrived, failed
  or not, in order, for a day. Objective 1's written response — replay the
  stream from a sequence number — is the recovery the platform has today:
  written down, and never yet performed. E2's lost findings were purged with
  the rest, and the E1 re-run records that a replay could still have stored
  the dropped finding and none was attempted. A queue's recovery would be a
  different procedure that does not exist yet either; neither has been
  rehearsed, and the rehearsal belongs with the decision.

## Consequences
- Idle cost stays at about $25 a month net; always-on serving, with ADR
  0009 taken, at about $61.
- The shard remains the unit of ordering, retry and replay, and objectives
  1 and 2 keep their definitions and their measured figures.
- The decision is dated and bounded: it is re-examined after v2.0.0, with
  the four measurements above as the price of changing it, and the
  Well-Architected review's cost pillar names this record as the reason the
  largest idle line stays.
