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
| E1 | A record the normalizer cannot read | 1 (stored), 8 (controls) | not yet run |
| E2 | The normalizer denied its table | 1, 2 (fresh), 8 | not yet run |
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

**Expected signals, in order.**
1. The normalizer's log shows `Failed to process record … JSONDecodeError`
   for the garbage three times (the first attempt and two retries), about ten
   seconds apart, and the flood finding stored once.
2. `RecordsFailed` rises on the "Retried, not lost" graph; `RecordsReceived`
   counts the record each time it is delivered.
3. One message appears in `cloudsentinel-failed-findings` with the batch's
   sequence-number range; `cloudsentinel-slo-findings-stored` goes to ALARM
   within five minutes of it.
4. No control-change message: nothing about the platform was changed.

**Observed.** _(date, each signal's arrival time or "did not arrive")_

**Rollback.** Purge the queue and the alarm clears at the next period:
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
   their own; findings-stored returns to OK once the queue is purged.

**Observed.** _(date, each signal's arrival time or "did not arrive")_

**Rollback.**
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
