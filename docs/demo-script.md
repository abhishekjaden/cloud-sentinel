# The demo: a 12-minute script

A recorded walk through the deployed system, in the order a finding moves
through it, ending on what was measured. Every number spoken is one the
repository records; the script says where. Run it once as a rehearsal
before recording — the live parts depend on timing that is set out below.

## Before recording

Do these in order; the whole set takes about twenty minutes, most of it the
Api stack's deploy.

1. Sign in: `aws sso login --profile cs-audit`, and Docker Desktop running.
2. Deploy the serving layer and wait for it:
   `cd cdk && npx cdk deploy CloudSentinel-Api --profile cs-audit --require-approval never 2>&1 | tee ~/Downloads/api-deploy.log`
   (about six minutes). Then `curl -s https://api.cloudsentinel-soc.com/health`
   must answer `200`.
3. Open two browser windows side by side, both at
   `https://d2tb90osqfrb0m.cloudfront.net`: the left signed in as the
   operator (in `approvers`), the right as the analyst created on 21 October
   (in `analysts`). Sign in fresh — a token is good for an hour.
4. Open three console tabs in the audit account: GuardDuty → Findings;
   CloudWatch → Dashboards → `CloudSentinel-SLOs`; Step Functions →
   `cloudsentinel-remediation`.
5. Have the inbox open on the folder the alarm topic's mail lands in.
6. A terminal at the repository root, font large enough to read on video.
7. Stage the finding the demo will follow, so that it has been correlated
   and triaged by the time the recording reaches it (the schedules run every
   fifteen minutes; allow twenty):
   ```bash
   aws guardduty create-sample-findings --profile cs-audit \
     --detector-id cecf6cd08eefb67a55fd99c961cc728a \
     --finding-types 'Backdoor:EC2/C&CActivity.B!DNS' 'Recon:EC2/PortProbeUnprotectedPort'
   ```
   (Single quotes: in double quotes Bash's history expansion eats the `!`
   and the command never runs.)
   Within three minutes the C&C finding stages an `ec2_compromise` approval
   against the placeholder instance `i-99999999`; leave it pending — it is
   decided on camera in scene 5. Note the time. One thing the generator
   does that the script allows for: a sample finding of a type that already
   exists on the placeholder instance is re-emitted under the *same* finding
   id with its count raised, not created afresh, so the platform updates the
   existing sample incident rather than opening a new one. Scene 3 says so,
   and scene 4 shows a real incident instead.
8. Screen recording at the display's native resolution; microphone checked;
   notifications off.

If anything in scene 3 or 5 has not happened when the recording reaches it,
stop, wait for the next run, and start the scene again. The cuts are at scene
boundaries for that reason.

## The script

Times are cumulative targets. Say less rather than more; the numbers carry it.

### Scene 1 — What it is (0:00–0:45)

*On screen: the README's title and results table.*

CloudSentinel is a security operations platform for an AWS organization. It
takes the findings AWS's own detectors raise — GuardDuty, Security Hub,
Inspector — across four accounts, turns them into incidents, enriches and
triages them, and lets a person approve or refuse a response before anything
destructive happens. It is built as code, deployed from GitHub, and it
measures itself: eight objectives with alarms, five chaos experiments, a
rehearsed restore and an evaluated advisory model. Everything I'll show is
in the repository with its record.

### Scene 2 — The shape of it (0:45–2:00)

*On screen: the architecture block of the README, then the AWS Organizations
page.*

Four accounts under Control Tower. The audit account is the delegated
administrator for the security services and runs the whole platform; the
workload account trains the models and hosted the honeypot. Findings arrive
by EventBridge, go through a Kinesis stream into one normalizer, and land in
DynamoDB under a customer-managed key. Three scheduled functions read that
table every fifteen minutes: the correlator groups findings into incidents
by resource and time, the enricher looks up every address and domain an
incident names, and the triage function asks a language model for a note.
High-severity findings also go to a Step Functions workflow that pauses at a
human approval. Sixteen CDK stacks, 553 tests, and a deploy that only
happens after the tests and the scanners pass.

### Scene 3 — A finding arrives (2:00–3:45)

*On screen: GuardDuty's findings list, then the console's findings table,
then the terminal.*

Here are the two sample findings I generated twenty minutes ago — a
command-and-control callout and a port probe against the placeholder
instance. These are GuardDuty's own samples: its generator re-emits the same
finding each time with the count raised, and the platform stores a finding
by its id, so these two updated the sample incident from September rather
than opening a new one — which is also why the triage model marks that
incident as test data. In the console they are stored, normalized to one
schema, with GuardDuty's severity on a 0–100 scale beside Security Hub's and
Inspector's. How long does that take? The platform stamps every finding three
times — emitted, queued, stored — and this reads the gaps:

```bash
python scripts/measure.py --since 2026-10-14T00:00Z
```

Over a week of the organization's own traffic, 920 findings: the median
finding is written 6.3 seconds after it reaches the stream, the 95th
percentile 10.3; end to end from the event, 7.4 and 17 seconds. Under a flood
of ten thousand findings at two hundred a second, nothing was lost and the
backlog peaked at two and a half minutes. (`docs/evaluation.md`, section 1.)

### Scene 4 — The incident, enriched and triaged (3:45–5:45)

*On screen: the console's incidents panel, the newest honeypot incident
opened, its verdict chip and note; then the PDF report.*

This one is real. For nine days this project ran a honeypot in its workload
account — an instance that holds nothing and admits no login — and it drew
ten SSH brute-force attempts from ten addresses. Here is the last of them.
The correlator made it an incident and placed it at initial access; the chip
is the enricher's verdict on the address — malicious, from AbuseIPDB and OTX
— a fact about the indicator, never about the activity. And this is the
advisory note: what likely happened, what to check next, a severity and a
confidence — low, at high confidence: a brute-force attempt that got nowhere
against a target, with the address's reputation showing in the confidence
and not the severity. All ten were labelled by hand by me and my guide
before anyone read these notes, and the model matched the band thirty times
out of thirty.

Two things about that note. First, the model that wrote it can do nothing
else: it holds no permission that acts, it reads finding text escaped as
untrusted data, and its answer must fit one schema. Second, it was evaluated
before it was trusted to write anything: thirteen cases written with the
prompt, then twenty it could not have been tuned to — ten written blind and
these ten real ones. Fifty-seven of sixty runs inside the band, sixty of
sixty on a band adjudicated afterwards, every injection attempt flagged.
ADR 0005 holds every run, every miss and every adjudication.

The report button builds a PDF from the record alone — nothing generated —
and escapes every attacker-influenced value on the way in; a test reads the
PDF back to prove it. Open this incident's report and show its two pages.

### Scene 5 — Response, with a person in the loop (5:45–7:45)

*On screen: Step Functions, the execution paused at ApproveEc2; then the two
browser windows side by side; then the execution continuing.*

The C&C finding was severity seven or above, so the router sent it to a
playbook: `ec2_compromise`, which isolates the instance and snapshots its
disk. The workflow is paused here, at the approval gate. The task token is
held server-side; nothing in an e-mail can resume it.

On the right, the analyst sees the pending approval and no buttons; if that
account calls the decide route directly, the API answers 403 on the token's
group claim. On the left, the approver sees Reject and Approve. I approve —
a second click confirms — and the decision is recorded against my identity.
The workflow continues: isolate, snapshot. SAFE_MODE is on in this
deployment, so the executor logs what it would do to `i-99999999` rather
than doing it.

On 21 October the three access controls were each driven past their limit
once: an analyst refused, 40 of 150 burst requests answered 429 with a
Retry-After, and 564 of 3,000 unauthenticated requests blocked by the
firewall. The numbers are in `docs/slos.md`, objective 7.

### Scene 6 — It watches itself (7:45–9:30)

*On screen: the `CloudSentinel-SLOs` dashboard; then the terminal; then the
inbox.*

Eight objectives, each one alarm, each with a written response. Findings
stored, stored promptly, correlation running, remediation steps succeeding,
approvals decided, the API available and fast, and the eighth: that the
controls themselves change only through deployment. Watch it work. This
disables one of the platform's own rules from my terminal, as an intruder
with my credentials would:

```bash
aws events disable-rule --profile cs-audit --name cloudsentinel-control-keys
aws events enable-rule  --profile cs-audit --name cloudsentinel-control-keys
```

*(Switch to the inbox. The two messages arrive within the minute; the alarm
follows in about seventy seconds — the recorded median is 73 s over eight
changes. Keep talking over the wait.)*

Both calls are reported with who made them, from where, and with what tool;
and the alarm fires. The rules cover their own names, so switching the watch
off is itself reported. This caught something real on 18 October: a deploy
shipped a correlator without a permission it needed, every run failed, and
the silence alarm fired 48 minutes later on a Sunday afternoon — the only
control that noticed. The deploy now runs the correlator once before it is
called done.

### Scene 7 — Breaking it on purpose (9:30–11:00)

*On screen: `docs/chaos-experiments.md`, the summary table; then the R1
section.*

Five experiments broke the live platform on purpose, with the expected
signals committed to the repository before each run. Three found defects
that tests and review had passed — the retry policy that sent a whole
outage's findings to manual recovery, an alarm that measured the wrong thing
twice, a poison record that held its shard for an hour — and the evidence of
the first runs found a fourth: no alarm had ever notified anyone, because the
topic's policy refused CloudWatch. Each was fixed and verified by a re-run.
The fourth is why every expected signal since 13 October names its e-mail.

And on 21 October the restore was rehearsed: both record tables restored
from point-in-time recovery to one instant, the incidents copy usable in 14
minutes and the findings copy — 3,728 items and two indexes — in 18, every
item accounted for, the copies deleted, and the deletions reported by the
watch, as they should be. What is not rehearsed is the cut-over, and the
record says so.

### Scene 8 — What it costs, and what it is not (11:00–12:00)

*On screen: the cost chart in `docs/evaluation.md`; then the Limits section
of the README's Status.*

The whole organization cost ₹3,763 in September — about $33 — with the
Kinesis shard and the native detection services most of it. Idle, about $25
a month; the API is deployed on demand because always on it would cost $93.

What this is not: it is not a detection rate — GuardDuty detects, the
platform stores, correlates and advises. The classifier's near-perfect score
on CICIDS2017 is a documented artefact of that dataset; on another network it
is barely better than chance, and the model card says so. The triage
evidence is one person's cases and one honeypot pattern; cases from a second
person are still to come. One Region, one shard, one operator who holds both
roles. The production standards are met; the simplifications are named.

The repository is tagged v1.3.0. Thank you.

## After recording

Tear the serving layer down: `cd cdk && npx cdk destroy CloudSentinel-Api --profile cs-audit`.
The approval decided on camera and the two sample findings stay in the tables as
what they are — sample data, flagged as such by the triage model — and the
control-change messages of scene 6 are recorded here as the reason for those
two calls.
