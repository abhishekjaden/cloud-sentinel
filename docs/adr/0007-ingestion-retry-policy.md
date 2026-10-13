# ADR 0007: A finding that cannot be stored is retried for an hour, not twice

## Status
Accepted, 2026-10-08, on the evidence of two chaos experiments
(`docs/chaos-experiments.md`, E1 and E2). Verified the same day by a re-run
of E2, recorded there: a 25-minute denial of the table held all 50 findings on
the shard, findings-fresh fired at 10 min 30 s, the failure queue stayed
empty, and all 50 were stored when the denial was lifted. Re-examined
2026-10-13, after a re-run of E1 measured what it costs for a record that can
never be stored: see the last section.

## Context
The normalizer reads the findings stream in batches and reports, per record,
which it could not store; Lambda delivers those again. Until this decision it
delivered them twice more and then reported the batch to the failure queue,
from which the records can be replayed by hand from the stream's 24-hour
retention. That setting was chosen so that a record the normalizer can never
store — one that is not a finding at all — could not block the records behind
it on the shard.

Two experiments measured what the setting actually does.

- **E1, a record that is not a finding.** Three attempts in under a second,
  one queue message, the findings around it unaffected. The isolation works,
  and Lambda's first retries for a stream source are immediate, so "two
  retries" means "two more tries in the same second".
- **E2, the table denied for sixteen minutes.** Every batch of the period was
  given up on within a second of arriving. Iterator age never passed eleven
  seconds; the findings-fresh objective, written for exactly this failure,
  never fired; all 200 findings of the period went to the failure queue, and
  none were stored when the denial was lifted. They were recoverable, but
  only by someone replaying three sequence ranges by hand within 24 hours.

So the policy traded a failure that requires someone to write garbage into a
stream only EventBridge writes to, for a failure that any throttle, key
problem or permission mistake produces — and in the second case it quietly
converts a transient outage into a manual recovery job. For a security
pipeline that is the wrong way round.

## Decision
No retry count. A record that cannot be stored is delivered again until it
is an hour old (`maxRecordAge` of one hour on the event source), and only
then reported to the failure queue. Partial-batch reporting and the queue
stay as they were.

## Rationale
- A dependency outage shorter than an hour now heals itself: the shard holds,
  iterator age climbs, findings-fresh fires after two five-minute windows,
  and when the dependency returns every held record is stored in order. The
  alarm tells someone; nobody has to replay anything.
- A poison record now blocks its shard for up to an hour before it is
  reported. That is a real cost, and the same alarm reports it at ten
  minutes, with the normalizer's log naming the record. The event is rare —
  the stream has one writer, EventBridge, and a non-finding has to be put
  there deliberately — and an hour's delay of findings is recoverable where
  a lost hour is not.
- An hour is the bound on both sides. Longer would hold findings behind a
  poison record for longer; shorter would turn more outages into losses.
  The stream's 24-hour retention and the queue's 14-day pointers are
  unchanged, so recovery past the hour works as before.
- Retrying is cheap. The re-run showed Lambda delivering the failed batch
  again about once a minute after a first burst of immediate attempts, so an
  hour of a denied table is some sixty failed invocations (this decision as
  first written guessed ten thousand, from E1's immediate retries): cents of
  compute, a little log, and a `RecordsFailed` line on the dashboard that
  reads as retries rather than losses — which is what it is.

## Consequences
- Objective 2 (findings fresh) measures what it was written to measure.
  Objective 1 (findings stored) now fires only after an hour of failure, or
  for a loss upstream of the normalizer.
- E1's recorded behaviour changes: the same garbage record will now hold its
  shard for an hour and fire findings-fresh before it reaches the queue. The
  experiment's expectations are updated, and it is to be re-run.
- The dashboard's *Retried, not lost* graph will show sustained
  `RecordsFailed` during an outage rather than a brief spike; that is the
  signal working, not a regression.
- Rejected: `bisectBatchOnError`, which the partial-batch report makes
  redundant; and a larger retry count, which with immediate retries only
  changes how many times a batch fails in the same few seconds.

## Re-examined, 13 October 2026
The re-run of E1 (`docs/chaos-experiments.md`, 12 October) put one record that
is not a finding on the stream under this policy. It cost more than the hour
of delay the rationale above accepted, in two ways.

- **The hold is total.** Lambda delivered the one-record batch it had first
  read 69 times in the hour and read nothing past it, so the handler's
  storing of the good records in a batch never reached the findings behind
  it. Ninety-three findings arrived behind the record and were stored within
  two seconds of its being dropped, having waited up to 13.3 minutes; they
  waited no longer only because none had arrived earlier in the hour.
- **The hold ends in a loss.** The record was dropped 60 min 17 s after it
  arrived. A finding that had arrived 4.6 seconds behind it was past an hour
  old by then too, and was dropped with it, never delivered — the outcome
  this decision exists to prevent, for the findings nearest the poison. The
  window is the gap between the poison turning an hour old and the retry
  that drops it: up to a minute at the retry pacing measured.

The decision stands for what it was made for: a dependency that fails and
recovers still holds the shard and heals without loss (E2). What changes is
that a record which cannot be read must not reach this policy at all. The
normalizer now reports it to the failure queue itself rather than handing it
back: ADR 0008, to be verified by a third run of E1.
