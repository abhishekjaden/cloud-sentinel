# The ICSSS 2026 paper: where each figure comes from

*CloudSentinel: A Chaos Engineering Case Study of Failure Alarms in a
Serverless Cloud Security Pipeline*, submitted to the IEEE 11th International
Conference on Smart Structures and Systems (ICSSS 2026, Saveetha Engineering
College, 20–21 November 2026). The tag `icsss-2026` marks the repository as
the paper describes it. This index goes from each table, figure and number in
the paper to the record it was taken from, so that a reader can check the
one against the other.

Figure and table numbers are those of the authors' draft of 13 October
(Figs. 1–3, Tables I–III). The reworded manuscript of 15 October adds the
state machine and the console as its Figs. 2 and 3, so its Fig. 4 is the
draft's Fig. 2 and its Fig. 5 the draft's Fig. 3; the records are the same.

## Dates

The paper's Table II gives dates in UTC, as the records' timestamps are.
`docs/chaos-experiments.md` heads each run by the local (IST) date on which
it was run, and gives the UTC times beneath. Two runs therefore carry
different dates in the two places: E1's first run is headed 7 October and ran
at 19:25 UTC on the 6th; E2's first run is headed 8 October and ran at 19:05
UTC on the 7th. Every other run falls on the same date either way.

## Sections III and IV: the system and the method

| Claim | Record |
|---|---|
| Four-account organization; the audit account the delegated administrator | `README.md`, Architecture; `scripts/enable-org-security.sh` |
| 316 back-end, 106 infrastructure and 76 front-end tests; cdk-nag and static analysis before any deployment | the suites under `backend/tests`, `cdk/test` and `frontend/src/__tests__`; `.github/workflows/ci.yml`; counts as CI reported them on 13 October |
| One shard, 24-hour retention; batches of up to 100 within a 10-second window; Python 3.12, 256 MB; an hour's `maxRecordAge` | `cdk/lib/stacks/ingestion-stack.ts` |
| Partial-batch reporting; the failure queue holds metadata, not records | `cdk/lambda/normalizer/handler.py`; `docs/slos.md`, objective 1 |
| The three retry policies, in order | ADR 0007 (`docs/adr/0007-ingestion-retry-policy.md`), ADR 0008 (`docs/adr/0008-reject-unreadable-records.md`) |
| Correlation every 15 minutes, findings at most 30 minutes apart | `cdk/lambda/correlator/handler.py` (`WINDOW_MINUTES`); its schedule in `cdk/lib/stacks/ingestion-stack.ts` |
| Claude Haiku 4.5 on Bedrock; finding text as untrusted data | `cdk/lambda/triage/handler.py`; ADR 0005 |
| Idle cost about US$25 a month, September 2026 | `docs/evaluation.md`, section 2 |
| Table I, the four objectives exercised, their measures and alarm conditions | `docs/slos.md`, objectives 1, 2, 3 and 8; `cdk/lib/stacks/observability-stack.ts` |
| Expectations committed before each run; the two exceptions | `docs/chaos-experiments.md`, introduction; `git log` dates each section. E5 was written up after it ran; the E2 re-run's expectations are ADR 0007's predictions, commit `c3aa0b5` at 11:55 UTC on 8 October, five minutes before the denial |
| The operator's clock 12 to 21 s fast | `docs/chaos-experiments.md`, E1 (7 October, side findings) and E1 re-run (side finding) |

## Section V and Table II: the experiments

Every row of Table II is one dated run in `docs/chaos-experiments.md`, and
the observed column is that run's numbered signals.

| Run | Record |
|---|---|
| E5, 3 Oct | `docs/chaos-experiments.md`, E5. Expectations recorded after the run |
| E1, 6 Oct (UTC) | E1, *Observed, 7 October*: three attempts 0.2–0.4 s apart, one queue message per record, findings-stored to ALARM at 19:28:37, three minutes after the first message |
| E2, 7 Oct (UTC) | E2, *Observed, 8 October*: denial 15 min 42 s, 200 findings, 603 `AccessDeniedException` lines, three queue messages covering all 200, iterator age at most 11.4 s, findings-fresh never fired, 0 of 200 stored |
| E2 re-run, 8 Oct | E2, *Re-run under ADR 0007*: denial 25 min 17 s, 50 findings, iterator age to 1,425 s (23 min 45 s), findings-fresh to ALARM at 12:14:15 (10 min 30 s after the flood), queue empty, 50 of 50 stored, a failed delivery about once a minute |
| E4, 8 Oct | E4: 10,000 findings at 200/s, iterator age peak 149 s, 100 incidents in one 6.1 s run, notes up to 4.6 h; the two expectations that were arithmetically impossible. Percentiles in `docs/evaluation.md`, section 1, from `docs/evaluation-e4.json` |
| E3, 8 Oct | E3, *Observed, 8 October*: a 56-minute gap, incidents-current silent |
| E3 re-run, 11 Oct | E3, re-run: fired 76 min 51 s after the last run, on three 15-minute periods |
| E3 third run, 11 Oct | E3, third run: fired 49 min 41 s after the last run, 4 min 41 s into the breach, on nine 5-minute wall-clock periods |
| E1 re-run, 12 Oct | E1, *Re-run under ADR 0007*: 69 deliveries in 60 min 17 s, the finding 4.6 s behind the record not delivered in the hour and never stored (its own drop inferred; see signal 3), 93 later findings stored 0.4 s after the drop, findings-fresh at 12 min 06 s, findings-stored 2 min 52 s after the drop, findings-fresh cleared 15 min 49 s after it |
| E1 third run, 13 Oct | E1, *Third run under ADR 0008*: the message in the queue 11.2 s after the record reached the stream, the finding behind it stored by the same invocation 0.15 s later, iterator age at most 10.9 s, findings-stored to ALARM 3 min 16 s after the message |
| Every run: 0 of 49 delivered | `docs/slos.md`, *Receiving alarms*; `screenshots/alarm-history-2026-10-13.png` |
| Fix check, 13 Oct | `docs/slos.md`, *Receiving alarms*, observed: actions executed within 46 ms of each state change; Gmail's receipt times in the same second; `screenshots/alarm-email-2026-10-13.png` |

Other figures in Section V:

| Claim | Record |
|---|---|
| 15 control-change messages; O8 fired in a median of 73 s, n = 7, maximum 91 s | `docs/evaluation.md`, section 1, rows *control change reported* and *control change alarmed*, with each run's figure |
| 49 notification attempts in the topic's 23 days, none delivered; the topic created 20 September; the policy that refused CloudWatch | `docs/slos.md`, *Receiving alarms*; `cdk/lib/stacks/observability-stack.ts` and its test |
| Under normal traffic, 610 findings over 17 hours, median 6.3 s, 95th percentile 10.2 s | measured on 13 October with `scripts/measure.py --since 2026-10-12T20:10:00Z` and read from the terminal; the same traffic measured again on 17 October over 4.6 days — 786 findings, 6.1 s and 10.4 s — is `docs/evaluation-normal.json` and the `normal traffic` rows of `docs/evaluation.md`, section 1 |
| The sliding evaluation and the wall-clock window | `docs/slos.md`, objective 3; `docs/chaos-experiments.md`, E3; AWS's documentation, reference [17] |

## Figures

| Figure | Record |
|---|---|
| Fig. 1, the ingestion and correlation path with the measures behind O1–O3 | drawn from `cdk/lib/stacks/ingestion-stack.ts` and `observability-stack.ts`; the dashed path is ADR 0008's |
| Fig. 2(a), E1 re-run: 69 deliveries, the hold, the alarms | `docs/chaos-experiments.md`, E1 re-run, signals 1–5: the per-minute delivery counts from the normalizer's `JSONDecodeError` lines (seven in the first 22 seconds, then about one a minute, 69 in all), the alarm times from the alarm histories |
| Fig. 2(b), E1 third run: rejected at once | `docs/chaos-experiments.md`, E1 third run, signals 1–4 |
| Fig. 3(a), the findings-stored alarm's history | `screenshots/alarm-history-2026-10-13.png`, captured 13 October; the two refusals at 13:18 and 13:23 UTC are E1's third run, the two successes at 14:17 and 14:18 the delivery check |
| Fig. 3(b), the ALARM email | `screenshots/alarm-email-2026-10-13.png`; the receipt time in `docs/slos.md` is Gmail's, the time in the body the alarm event's |

## Section VI and Table III: the detector

| Claim | Record |
|---|---|
| Original CICIDS2017: AUC 0.99996, binary F1 0.9977, macro-F1 0.9586, Bot F1 0.779 on 293 test flows | `ml/MODEL_CARD.md`, section 3; `ml/models/test_metrics.json`, `binary_metrics.json`, `holdout_metrics.json` |
| Corrected release: binary F1 0.9999, macro-F1 0.9797, Bot F1 0.996 on 110; 83 features; 11,979 attempted attacks, 4,067 of 4,803 botnet flows; the 71,767-flow port scan | `ml/MODEL_CARD.md`, sections 6 and 6.1; `ml/models/corrected_metrics.json`; `ml/evaluation/retrain_corrected.py` |
| Friday held out: 99.5% of 95,144 DDoS flows, 99.0% of 159,066 port-scan flows, 0.0% of 736 botnet flows; F1 0.9945, AUC 0.99988 | `ml/MODEL_CARD.md`, section 6.2 |
| CSE-CIC-IDS-2018: 63,195,088 flows, AUC 0.577, F1 0.082, 2.27% of benign-labelled flows flagged, 1.78% of truly benign, 298,874 attempted FTP connections every one flagged; DoS Hulk 47 of 1,803,160; Slowloris 97.0%, port scan 79.1%, LOIC-HTTP 41.5%, HOIC 0.0%, Botnet Ares 0.6% | `ml/MODEL_CARD.md`, section 6.3; `ml/models/cross_dataset_2018.json` holds every label's counts; `ml/evaluation/cross_dataset.py --report` prints the tables from it |

## Section VII: the triage model

| Claim | Record |
|---|---|
| Twelve synthetic cases written with the prompt; 33 of 36, then 36 of 36 after one disputed label was widened | ADR 0005, consequences; `docs/evaluation.md`, section 3; `scripts/triage_eval_cases.json`; `scripts/eval_triage.py` |
| Who wrote the cases | `docs/triage-eval-protocol.md`, section 5: the prompt's author wrote the scenarios and labels, and for the last five the project's author picked the finding types in the GuardDuty console. The prompt's author is the AI assistant named in the paper's acknowledgment |
| The independent evaluation is pending | true when the paper was submitted; the first independent set was run on 17 October and the honeypot's first five cases on 18 October, both after submission — `scripts/triage_eval_cases_independent.json`, ADR 0005, `docs/evaluation.md` section 3 |

## What is not in the repository

The paper's claims rest on the records above and on nothing else. Two things
a reader may look for are deliberately absent: the operator's inbox, of which
only the two screenshots are kept, and the raw CloudWatch metric samples,
which the records quote by value and which the console holds for fifteen
months. Nobody outside the project has reproduced the experiments; the
commit times that order expectations before results are the author's
machine's.
