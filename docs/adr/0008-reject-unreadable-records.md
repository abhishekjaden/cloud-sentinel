# ADR 0008: A record that can never be stored is rejected at once, not retried

## Status
Accepted, 2026-10-13, on the evidence of experiment E1's re-run under ADR 0007
(`docs/chaos-experiments.md`, 12 October). Verified the same day by E1's
third run, which met every expected signal written there before it ran.

## Context
ADR 0007 made the normalizer's failures retry until a record is an hour old,
so that a dependency outage holds the shard and heals itself; the E2 re-run
confirmed it, storing all 50 findings of a 25-minute denial of the table. The
decision accepted that a record which can never be stored would hold its shard
for the same hour, and argued that a delay is recoverable where a loss is not.

E1's re-run put one such record on the stream and measured the cost. It was
more than a delay.

- **The hold is total.** Lambda delivered the one-record batch it had first
  read 69 times in the hour and read nothing past it. The handler stores every
  good record of a batch before reporting a bad one, but that never reached
  the findings behind this one: 93 that arrived behind it waited up to 13.3
  minutes, and would have waited the whole hour had they arrived early in it.
- **The hold ends in a loss.** When the record was dropped, 60 min 17 s after
  it arrived, the finding that had arrived 4.6 seconds behind it was past an
  hour old as well, and was never stored — dropped with it, by inference from
  a second queue message that minute, purged unread.

And whoever can write to the stream can repeat it every hour (threat model,
B3).

The two kinds of failure need opposite treatment. A failure in *storing* a
record — a throttle, a denied or missing table, a disabled key — can heal, and
the shard should hold while it does. A failure in *reading* one — not base64,
not JSON, not an object, not something the mapping can handle — or a record
the table refuses as invalid will fail the same way on every delivery.
Retrying it only holds back everything behind it, and then loses some of it.

## Decision
The normalizer sorts each failure by where it happened.

- A record it cannot read, or whose write the table refuses because of the
  item itself (`ValidationException` or `SerializationException`, or a value
  boto3 or botocore will not send), is sent to the failure queue by the
  normalizer, on first sight, with the reason. It is not handed back, so the
  checkpoint moves past it.
- Every other failed write is handed back as before, and ADR 0007's hour
  applies.
- If the failure queue cannot be reached, the record is handed back rather
  than dropped: a rejection must never become a silent loss.

The message names the record the way Lambda's own on-failure message names a
batch — shard, sequence number, arrival time, under `KinesisBatchInfo` — with
the condition `RecordRejected` and the exception as the reason, so the runbook
in `docs/slos.md` recovers either kind the same way. Like Lambda's, it is a
pointer into the stream, not a copy of the record; the queue stays on
SQS-managed encryption because no finding content is in it.

## Rationale
- It removes both costs E1 measured: nothing waits behind an unreadable
  record, and nothing is dropped with it.
- It keeps ADR 0007 where ADR 0007 was right. E2's failure, the table denied,
  is a failed write; it still holds the shard and still heals.
- The loss is still reported. A rejected record is not stored, so
  findings-stored counts it exactly as it counts a batch Lambda gives up on.
  That is wanted both ways round: garbage in a stream only EventBridge writes
  to means someone wrote to it who should not have, and a real finding the
  mapping cannot handle needs a fix and a replay within the stream's 24 hours.
- Unknown sources are unchanged. A readable event from a service the
  normalizer does not map is still stored under `unknown`, as the tests pin,
  because it can be read; only what cannot be read or written is rejected.

## Consequences
- The normalizer publishes `RecordsRejected` beside `RecordsReceived` and
  `RecordsFailed`; `RecordsFailed` now counts only records handed back for
  retry. The dashboard shows rejections beside the failure queue.
- A bug in the mapping now sends a real finding to the queue within seconds,
  instead of holding the shard for an hour and then dropping it; replaying it
  works as before.
- E1 is run a third time. Expected: one queue message within a minute,
  condition `RecordRejected`; no hold, so iterator age stays at seconds and
  findings-fresh stays OK; the finding sent behind the garbage stored once;
  findings-stored in ALARM about three minutes after the message. Observed
  on 13 October: one message 11.2 s after the record reached the stream;
  iterator age at most 10.9 s and findings-fresh unchanged; the finding
  behind it stored once, by the same invocation; findings-stored in ALARM
  3 min 16 s after the message and OK one window later.
- Rejected: validating each source's full schema, since the mapping already
  degrades missing fields to defaults and a strict schema would refuse
  findings that are merely new; and `bisectBatchOnError`, which isolates a bad
  record by splitting its batch but still retries it, holding the shard while
  it does.
