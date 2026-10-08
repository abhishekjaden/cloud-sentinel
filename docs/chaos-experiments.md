# Chaos experiments

Each objective in `docs/slos.md` promises that a particular failure will be
noticed. An experiment is the failure, caused on purpose, and the record of
whether it was. The expected signals are written before the experiment runs,
so the outcome is a comparison, not an interpretation; the observed column is
filled in afterwards, with the time each signal took, and left honest when a
signal did not come.

Every experiment is run from a terminal with the audit profile, in the live
environment, and every one is reversible by the step under *Rollback*. The
rule of the exercise is that nothing is fixed in the middle: if an experiment
reveals that an alarm does not fire, that is the result, and the fix is a
separate change with its own test.

| # | Experiment | Objectives exercised | Status |
|---|---|---|---|
| E1 | A record the normalizer cannot read | 1 (stored), 8 (controls) | **run, 7 October 2026** |
| E2 | The normalizer denied its table | 1, 2 (fresh), 8 | **run, 8 October 2026** |
| E3 | The correlation schedule disabled | 3 (current), 8 | not yet run |
| E4 | Ten times the volume | 1, 2, 3 | not yet run |
| E5 | A control changed by hand | 8 | **run, 3 October 2026** |

---

## E1 — A record the normalizer cannot read

**Hypothesis.** A record that is not a finding is retried twice and then
reported to the failure queue; the findings-stored objective fires once it is
there; nothing else in the batch is lost.

**Steps.**
```bash
aws kinesis put-record --profile cs-audit --stream-name cloudsentinel-findings \
  --partition-key chaos --data 'this is not a finding' --cli-binary-format raw-in-base64-out
```
Then, within the same minute, send one real-shaped finding so the batch holds
both: `python scripts/flood_findings.py --count 1 --rate 1`.

**Expected signals, in order.** _(As written before the first run. Under
ADR 0007 the garbage record is retried for an hour instead of twice, so on a
re-run signals 1–3 change: the failures repeat for an hour, the records
behind the garbage wait with it, `cloudsentinel-slo-findings-fresh` fires at
ten minutes, and the queue message and findings-stored follow after the hour.)_
1. The normalizer's log shows `Failed to process record … JSONDecodeError`
   for the garbage three times (the first attempt and two retries), about ten
   seconds apart, and the flood finding stored once.
2. `RecordsFailed` rises on the "Retried, not lost" graph; `RecordsReceived`
   counts the record each time it is delivered.
3. One message appears in `cloudsentinel-failed-findings` with the batch's
   sequence-number range; `cloudsentinel-slo-findings-stored` goes to ALARM
   within five minutes of it.
4. No control-change message: nothing about the platform was changed.

**Observed, 7 October 2026** (times UTC; the run was 00:55–01:15 IST). Two
garbage records were sent rather than one: the first at 19:25:3x on its own —
the sender's venv was inactive, so the finding that should have followed it
failed to send — and the second at 19:26:4x, with the finding ten seconds
behind it.

1. Each record was attempted three times and then given up on — `retryAttempts:
   2`, as configured — but the attempts were **0.2–0.4 s apart within one
   invocation** (19:25:39.47, 39.66, 40.05 under one request ID; 19:26:50.13,
   50.35, 50.81 under another), not ten seconds apart as expected: Lambda
   retries a reported batch failure immediately. The expectation was wrong
   about the spacing and right about the count. The finding
   (`flood-dwbr-000000`) was normalized once, at 19:27:00, by a separate
   invocation, and the table held exactly one record for the flood account
   afterwards — so it was not in the record's batch (the batching window is
   ten seconds; it arrived just outside), and the partial-batch claim is
   evidenced only indirectly: a record being given up on did not hold the
   shard, and the finding behind it was stored once.
2. The failures appear in the log as `Failed to process record <sequence>:
   JSONDecodeError`, six lines in all; `RecordsFailed` was not read from the
   dashboard during the run.
3. Two messages in `cloudsentinel-failed-findings`, one per record, the first
   at about 19:25:40. The alarm went **OK → ALARM at 19:28:37**, three
   minutes after the first message, and **ALARM → OK at 19:34:37** after one
   quiet five-minute window — before the queue was purged, with both messages
   still in it. The alarm counts losses per window, as objective 1 says it
   should; it does not track the queue's depth, so its state says a loss
   happened, and the dashboard's *batches awaiting recovery* line says
   whether it is still unrecovered. The rollback text below, and E2's fifth
   expectation, had this the wrong way round; both are corrected here, before
   E2 runs.
4. No control-change message: the `/cloudsentinel/control-changes` log group
   had no entry for the hour.

Two side findings. The correlator's 19:30 run had already built an incident
from the flood finding before the purge removed both, so the finding was real
to the pipeline, not only to the table. And the sender's clock was about
twelve seconds ahead of AWS's (the script stamped the finding 19:27:09; the
normalizer stored it at 19:27:00) — see the note on E4.

**Rollback** (done 19:40). Purge the queue and remove the flood finding; the
alarm has already cleared on its own by then, and clearing it is not what the
purge is for — the purge is what takes the loss off the dashboard:
```bash
aws sqs purge-queue --profile cs-audit --queue-url "$(aws sqs get-queue-url --profile cs-audit --queue-name cloudsentinel-failed-findings --query QueueUrl --output text)"
python scripts/flood_findings.py --purge
```

---

## E2 — The normalizer denied its table

**Hypothesis.** With its table write denied, the normalizer hands every record
back; nothing is lost while the denial lasts; iterator age climbs and the
findings-fresh objective fires after two five-minute windows; the denial
itself, an IAM change made by hand, is reported by the control-change watch
within a minute; once the denial is removed, every record held in the stream
is stored.

**Steps.**
```bash
ROLE=$(aws lambda get-function-configuration --profile cs-audit --function-name CloudSentinel-Normalizer --query Role --output text | sed 's#.*/##')
aws iam put-role-policy --profile cs-audit --role-name "$ROLE" --policy-name chaos-deny-write \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"dynamodb:PutItem","Resource":"*"}]}'
python scripts/flood_findings.py --count 200 --rate 20
```
Leave the denial in place for twelve minutes, then remove it.

**Expected signals, in order.**
1. A control-change message for `PutRolePolicy` on the normalizer's role,
   naming your session, within a minute; `cloudsentinel-slo-controls-unchanged`
   in ALARM within five.
2. The normalizer's log shows `AccessDeniedException` for every record;
   `RecordsFailed` equals `RecordsReceived` on the "Retried, not lost" graph.
3. Iterator age climbs on the findings-fresh graph; the alarm goes to ALARM
   after two windows above five minutes, about ten to twelve minutes in.
4. Records retried to exhaustion reach the failure queue; findings-stored
   goes to ALARM. (Retries are two per batch, so with a twelve-minute denial
   some batches *will* exhaust: this is expected, and it is the one case in
   which the queue holds findings that can still be recovered by replaying
   the batch's sequence range from the stream, which retains 24 hours.)
5. After rollback, the flood findings written after the denial are stored
   within a minute; findings-fresh and controls-unchanged return to OK on
   their own; findings-stored returns to OK after one quiet window whether or
   not the queue has been purged (corrected after E1 — the queue's depth is
   on the dashboard, not in the alarm).

**Observed, 8 October 2026** (times UTC; 00:35–00:58 IST). The denial lasted
15 min 42 s — `PutRolePolicy` at 19:05:41, `DeleteRolePolicy` at 19:21:23 —
and 200 flood findings (run `klwt`) were sent under it at 19:07:29–19:07:39. A
first 200 (run `56ou`) had gone through at 19:05:03–19:05:13, before the
denial, by mistake; they were stored normally and serve as the control.

1. The watch reported `PutRolePolicy` and the alarm went to ALARM at 19:06:54 —
   **73 seconds** after the API call. The `DeleteRolePolicy` of the rollback
   was reported too, and the alarm, which had returned to OK at 19:21:54,
   went back to ALARM at 19:22:54 — 91 seconds. Both messages carried the
   operator's session identity.
2. The normalizer's log held 603 `AccessDeniedException` lines for the run:
   200 records × 3 immediate attempts, as E1 predicted, plus the odd line.
3. **Iterator age peaked at 11.4 seconds** (one-minute maxima 0.8 s, 3.0 s,
   9.3 s, 11.4 s) and findings-fresh never fired. The hypothesis expected
   the age to climb for ten minutes; it could not, because the poller gave
   each failed batch up within a second and moved on.
4. Every denied record reached the failure queue: **3 messages, one per
   batch**, covering all 200. findings-stored went to ALARM at 19:10:37 —
   about three minutes after the first message — and back to OK at 19:17:37
   after one quiet window, as E1 found.
5. After the rollback, 10 fresh findings (run `3hxr`, 19:23:00) were stored
   within the batching window. The denied 200 were not: the flood account's
   count read 210 = 200 before the denial + 10 after it. The hypothesis's
   "nothing is lost while the denial lasts" was wrong under the current retry
   policy; the records were recoverable only by replaying the three sequence
   ranges from the stream by hand, within its 24-hour retention, and the
   purge below removed them with the rest instead.

The side finding is the important one. The ingestion retry policy — two
immediate retries, then the failure queue — is tuned to isolate a poison
record (E1) at the price of losing every finding during a dependency outage
to manual recovery (E2): a sixteen-minute denial cost 200 of 200. The
alternative, retrying a record until it is an hour old, would hold the shard
instead, so iterator age climbs, findings-fresh fires, and everything stores
itself when the dependency returns — at the price of a poison record blocking
its shard for up to an hour. Neither is free; which to prefer is a decision for
an ADR, not a fix made here. ADR 0007 took it the next day: retry for an
hour. The re-run below is the check.

The correlator's 19:15 run built 50 incidents from the control findings
before the purge removed them, one per flood instance: the pipeline behind
the normalizer was unaffected throughout.

**Rollback** (done 19:21:23 for the policy, 19:28 for the data).
```bash
aws iam delete-role-policy --profile cs-audit --role-name "$ROLE" --policy-name chaos-deny-write
```
This is itself reported by the watch — a second message, `DeleteRolePolicy` —
which is the watch working, not a second incident. Then purge the queue and
the flood findings as in E1.

---

## E3 — The correlation schedule disabled

**Hypothesis.** With its schedule disabled, the correlator publishes nothing;
the incidents-current objective, which treats silence as a breach, fires
after forty-five minutes; the disable is reported within a minute.

**Steps.**
```bash
aws events disable-rule --profile cs-audit --name cloudsentinel-correlation
```
Wait fifty minutes.

**Expected signals, in order.**
1. A control-change message for `DisableRule` within a minute;
   controls-unchanged in ALARM within five.
2. `CorrelationRunsCompleted` stops on the correlation graph.
3. `cloudsentinel-slo-incidents-current` goes to ALARM at forty-five minutes
   after the last completed run — not after the disable, which is the
   difference between measuring the schedule and measuring the work.
4. Notes and verdicts keep being written for incidents that already exist:
   triage and enrichment do not depend on the correlator running.

**Observed.** _(date, each signal's arrival time or "did not arrive")_

**Rollback.**
```bash
aws events enable-rule --profile cs-audit --name cloudsentinel-correlation
```
The next run completes within fifteen minutes and the alarm clears.

---

## E4 — Ten times the volume

**Hypothesis.** At ten times a busy day's findings in under a minute, nothing
is lost, iterator age stays under five minutes, the correlator's next run
completes within its timeout, and every flood incident is triaged within an
hour at the five-per-run budget — or the queue of incidents awaiting a note
climbs on the dashboard, which is the budget doing its job.

**Steps.**
```bash
python scripts/flood_findings.py --count 10000 --rate 200 --resources 100
```
Note the start time it prints. Thirty-five minutes later, so the correlator
and the triage function have each run twice:
```bash
python scripts/measure.py --since <start time> --json docs/evaluation-e4.json
```

Read `stored` (Kinesis arrival → write, both on AWS clocks) as the ingestion
figure for a flood. Synthetic findings carry the sending machine's clock in
`event_time`, and E1 found that clock twelve seconds ahead of AWS's, which
would make `queued` and `ingested` read twelve seconds short — or negative.
Real findings carry AWS's own timestamps and are unaffected.

**Expected signals.**
1. `sent 10000` with few or no resends: one shard takes a thousand records a
   second, and the script holds to two hundred.
2. Iterator age peaks and falls within five minutes; findings-fresh stays OK.
3. `RecordsFailed` stays at zero; the failure queue stays empty; findings-stored
   stays OK.
4. The correlator's next run reports `incidents: 100` (one per instance) and
   its duration on the correlation graph stays well under its timeout.
5. `measure.py` reports `ingested` p95 under a minute for the ten thousand,
   `correlated` under fifteen minutes, and `triaged` for the incidents the
   budget reached; `IncidentsAwaitingTriage` on the dashboard shows the rest.
6. Cost: the triage notes for a hundred incidents, a few tens of cents; the
   table writes, cents.

**Observed.** _(date, the figures)_

**Rollback.**
```bash
python scripts/flood_findings.py --purge
```

---

## E5 — A control changed by hand

**Hypothesis.** Disabling and re-enabling one of the watch's own rules from
an administrator session is reported twice, with the session's identity, and
the controls-unchanged objective fires.

**Steps.** As in `docs/slos.md`, objective 8:
```bash
aws events disable-rule --profile cs-audit --name cloudsentinel-control-keys
aws events enable-rule --profile cs-audit --name cloudsentinel-control-keys
```

**Expected signals.** Two messages to the alarm topic naming `DisableRule`
and `EnableRule`, the SSO administrator role and the source address; both
events in `/cloudsentinel/control-changes`; the alarm in ALARM within five
minutes and OK within ten.

**Observed, 3 October 2026.** `DisableRule` at 08:26:41Z and `EnableRule` at
08:26:44Z were both in the log group and both delivered to the topic within
the same minute (the messages carried the SSO role ARN, the source address
and the AWS CLI user agent), and the alarm was in ALARM when checked three
minutes later. The first message arrived as one quoted string with literal
`\n`; the template was changed to send lines (commit `fix(slo): send the
control-change message as lines`). Every expected signal arrived; nothing
unexpected did.

**Rollback.** None needed; the rule was re-enabled as the second step.
