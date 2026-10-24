# Changelog

Each release is a tag on `main`; its notes say what the repository holds at
that tag and what it does not. Dates are the tag's.

## v2.0.0 — Evaluated and shown (24 October 2026)

The final release of the project as a final-year work: the platform as
built, every planned measurement made and recorded, and the results shown
in the README with the record each comes from. The four gates the project
set itself — a live pipeline, chaos-tested and evaluated, hardened, and
evaluated and shown — are closed, the last with two items the author chose
to leave outside the tag (below).

Since v1.3.0:

- **The honeypot's record closed.** Its second run ended on 22 October
  after nine days and nine hours (short of the ten planned, recorded as
  such) and ten lone SSH brute-force incidents from ten addresses, at a
  cost of $2.26. The last five were labelled by hand by the author and the
  guide, each with a statement that no AI tool helped, and the three label
  files the last four took are kept; the twenty independent cases ran
  57 of 60 at prompt `2026-10-20.2`, exactly as expected before the run
  (ADR 0005, `docs/triage-eval-protocol.md` sections 1 and 7).
- **The last adjudication.** The domain-reputation case's band widened to
  low–medium by its writer and the guide, their reasoning recorded
  verbatim and the original band kept; the recorded runs stand as run and
  read 60 of 60 on the widened band. No adjudication remains open.
- **The README** opens with a results table — latency, the flood, the
  experiments, the restore, the alarms, the triage runs, the access
  controls, the detector, the cost, the defect count — each row naming its
  record; live badges; a corrected architecture; tests and gates; the
  status at the tag.
- **A 12-minute demo script** (`docs/demo-script.md`) with its pre-flight
  list and two live parts, corrected after one evidence session: the
  sample finding types single-quoted, and scene 4 on a real honeypot
  incident, since GuardDuty's generator re-emits existing sample ids
  rather than creating new findings.
- **Two cost decisions as ADRs.** 0009: the API task's NAT gateway — half
  the serving layer's daily cost — replaced by the task's own address
  behind the same security group; *deferred* while the stack runs on
  demand, where the gateway costs cents a session, and taken up if
  always-on serving is wanted. 0010: the Kinesis shard kept through
  v2.0.0 against a queue that would be free, priced at the measurements a
  queue would have to earn; it also records that the stream replay has
  never been performed.
- **Evidence from 24 October:** the SLO dashboard with six objectives in
  OK, a real incident with its malicious verdict and its note, and an
  analyst's 403 beside the 200 the same token gets for reading the queue
  (`screenshots/*2026-10-24.png`).
- **The Security workflow's red span dated:** from its scheduled run of
  12 October to the gate's first green run on the 19th, six days and
  seventeen hours, on a tree the previous run had passed.

What the tag holds in all: 16 CDK stacks, 553 tests (358 backend at 94%
coverage, 116 infrastructure, 79 console), ten ADRs, eight objectives with
alarms, five chaos experiments and one rehearsal with their expected
signals committed before each run, 26 defects found by the project's own
tooling and closed with a test or a re-run, 33 evaluated triage cases, and
a cost measured to the rupee.

Outside the tag, by the author's decision on 24 October: the demo video,
to be recorded from the script when he chooses, and the college's second
review, whose date is not set. Open beyond it, named rather than hidden:
cases from a second person for the triage evaluation, the matched E2
re-run (expectations committed), the restore cut-over, a staging
environment and a second Region, schema validation at ingestion, and the
apex domain. The ICSSS 2026 paper's decision is due on 25 October; if
accepted, its camera-ready adds the acknowledgment the submitted text
lacks.

## v1.3.0 — Hardened (21 October 2026)

Ingestion under ADRs 0007 and 0008; analysts and approvers as two Cognito
groups with the decision refused to the first (403) and recorded for the
second; a WAF and a per-user rate limit, each driven past its limit once;
a restore of both record tables rehearsed and timed (R1: 14 min 1 s and
18 min 20 s to a usable copy, every item accounted for); prompt
`2026-10-20.2` passing the authored cases on their widened bands; a week of
latency measured on the organization's own traffic.

## v1.2.0 — Phase 4 closed (11 October 2026)

Five chaos experiments run; three defects found and fixed — the ingestion
retry policy, the incidents-current alarm twice — each verified by a
re-run; and a fourth found in their evidence, that no alarm notification
had ever been delivered, fixed on 13 October.

## v1.1.0 — Phase 3 (19 September 2026)

Incident correlation end to end, surfaced through the API and the console;
findings pagination and Inspector normalization fixed.

## v1.0.0 — Baseline (1 August 2026)

The multi-account detection pipeline (GuardDuty, Security Hub and Inspector
→ EventBridge → Kinesis → Lambda → DynamoDB), XGBoost intrusion
classification, human-gated SOAR remediation on Step Functions, an
authenticated React console, and FastAPI on ECS Fargate behind an HTTPS
load balancer on a custom domain; documented (README, ADRs 0001–0004, a
Well-Architected review) and evidenced with fifteen screenshots.
