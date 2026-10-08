# ADR 0007: A finding that cannot be stored is retried for an hour, not twice

## Status
Accepted, 2026-10-08, on the evidence of two chaos experiments
(`docs/chaos-experiments.md`, E1 and E2). The re-run of E2 that verifies the
change is recorded there.

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
  and Lambda's retries for a stream source are immediate: there is no
  backoff, so "two retries" means "two more tries in the same second".
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
- Retrying is cheap. Lambda re-invokes immediately on failure, so an hour of
  a denied table is on the order of ten thousand failed invocations: cents
  of compute, a few megabytes of log, and a `RecordsFailed` line on the
  dashboard that reads as retries rather than losses — which is what it is.

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
