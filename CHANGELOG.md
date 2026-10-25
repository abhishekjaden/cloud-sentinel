# Changelog

Each release is a tag on `main`; its notes say what the repository holds at
that tag and what it does not. Dates are the tag's.

## Unreleased — towards v2.1.0, *Generalization and benefit*

On `main` since v2.0.0; the tag waits for the honeypot's third run and the
second-person cases (`docs/generalization-protocol.md`,
`docs/triage-eval-protocol.md`).

- **The detector across three networks.** CICIDS2017, CSE-CIC-IDS-2018 and
  UNSW-NB15 on fourteen shared features, with six expectations pushed before
  any table existed. G1 and G2 met, G3 and G4 not: trained on two networks
  and tested on the third, AUC 0.634, 0.665 and 0.884, never better than the
  better single network, and a model trained on UNSW-NB15 worse than chance
  on both CIC releases. With the destination port, five of six cross cells
  fall (model card, 6.4).
- **The honeypot's third run** (generation 4), from 24 October to 3
  November: packet headers, never payload, captured to a retained bucket
  through the VPC's S3 endpoint, the instance's one credential write-only;
  flows extracted by `scripts/pcap_flows.py`, the operator's visits logged as
  the benign side. Its flows decide G5 and G6.
- **Triage runs kept as records**, another model asked through the same
  prompt (`eval_triage.py --out`, `--model`), and what the model's confidence
  is worth read from the record (`scripts/triage_calibration.py`). The
  second-person case form, with a statement on AI assistance in every row,
  which the converter refuses a row without.
- **Every published advisory with a fix cleared** (25 October). The
  manifests carried 28 in the infrastructure's lockfile (two critical), 42 in
  the console's (three critical) and 51 in the backend's pins (37 of them
  Pillow's, 11 pypdf's), with no security pull request raised for any. Fixed
  by aws-cdk-lib 2.274.0, axios 1.20.0, vite 8.3.5, vitest 5.0.5,
  cryptography 50.0.2, Pillow 13.0.0, pypdf 6.21.2 and lockfile updates;
  every existing test passes unchanged, and the synthesized templates differ only in
  the dashboard's deployment function and a trust condition the new library
  adds to the remediation role. Two advisories had no fixed release
  (python-jose, ecdsa) and were unreachable; python-jose was replaced by
  PyJWT later the same day, and ecdsa left with it, after Dependabot's first
  scan raised both as critical and high. A new test pins the path the first
  concerned — a token HMAC-signed with the pool's own public key is refused.
  A dependency audit now runs in the Security workflow on
  every push and weekly. The three Dependabot pull requests open since
  September, which mixed these fixes with major upgrades that break the
  build (TypeScript 7, cdk-nag 3, jsdom 30), are superseded.
- **A claim corrected.** The threat model credited the dashboard's CloudFront
  distribution with a TLS 1.2 floor. On CloudFront's default certificate the
  floor cannot apply, as the stack's own cdk-nag suppression had said since
  it was written; the upgraded library began warning about the setting, and
  the row now says what holds and what does not.

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
