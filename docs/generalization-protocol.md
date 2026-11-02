# Generalization protocol: the detector across three networks and its own

The model card's section 6.3 ends on one number: a detector trained on
CICIDS2017 scores AUC 0.577 on CSE-CIC-IDS-2018, barely better than chance.
That number could mean the model learned the 2017 network rather than the
attacks in it, or that 83 CICFlowMeter features carry a network's fingerprint
whatever the model does, or both. One pair of datasets cannot separate those
readings. This protocol adds a third dataset extracted by a different tool,
UNSW-NB15, puts all three on one small schema, trains on each and tests on
every other, and then scores flows from the one network the platform
serves: the honeypot's own, captured in its third run. The expectations
below were written before any table was built, in the manner of
`docs/chaos-experiments.md`: the result is a comparison with them, not an
interpretation after the fact.

Drafted 24 October 2026 with the tooling, before any data was read, and
adopted by the author at commit. Edits before the first run are allowed and
dated here; edits after it are not. A changed schema, a changed label rule or
a changed split starts version 2 of this protocol, run again from the start.

## 1. The schema

Fourteen features every source can produce (`ml/evaluation/harmonize.py`,
`FEATURES`): the flow's duration in seconds; packets and IP-layer bytes in each
direction; mean packet length in each direction; mean inter-arrival time in
each direction, in seconds; packets and bytes a second; the ratio of backward
to forward packets; and whether the protocol is TCP or UDP. A fifteenth, the
destination port, is added only for the secondary run (section 4).

Left out on purpose, because at least one source cannot supply them or
supplies something else under the same name: TTL values (UNSW-NB15's
`sttl`/`dttl`, which separate its attack generator from its normal traffic
almost on their own); TCP window and sequence fields; flag counts (Argus does
not count them); CICFlowMeter's bulk, subflow, active and idle statistics;
and every source's own derived rates and means, which are recomputed from
the counts here so that one definition holds everywhere.

The harmonization is approximate in four named places:

1. **Bytes.** CICFlowMeter's "Total Length of Fwd Packet" is payload; Argus's
   `sbytes` is what went over the wire, framing included. The schema's
   `fwd_bytes` is IP-layer bytes: CICFlowMeter's payload total plus its header
   total, and Argus's wire total less 14 bytes of Ethernet framing a packet
   (`--unsw-ethernet`, which can be set to 0 to see how much the assumption
   matters). The honeypot extractor counts IP total length directly.
2. **Flow boundaries.** CICFlowMeter ends a flow at a FIN or after 120 s;
   Argus's status interval differs; the honeypot extractor follows
   CICFlowMeter's rule. A long connection is one flow in one tool and
   several in another.
3. **Direction.** Forward is the direction of the first packet seen, in all
   three; for the honeypot that is also what decides the label (section 3).
4. **Rates on one-packet flows.** Duration 0 would make the rates infinite;
   the schema floors the duration at one microsecond, in every source alike,
   so a lone probe has a packet rate of a million and the models see the same
   constant everywhere.

## 2. The datasets and their labels

| Table | Source | Rows read | Label rule |
|---|---|---|---|
| `cic2017` | the corrected CICIDS2017 (Engelen, Rimmer and Joosen, 2021), all five days | all, about 2.1 million | `Label`; attempted attacks count as benign, as in `retrain_corrected.py` |
| `cic2018` | the corrected CSE-CIC-IDS-2018 (Liu, Engelen et al., 2022), all ten days | one row in thirty, in file order — about 2.1 million of 63 million | the same |
| `unsw` | UNSW-NB15 (Moustafa and Slay, 2015), the four raw files `UNSW-NB15_1.csv` to `_4.csv` with their header from `NUSW-NB15_features.csv` | all, about 2.5 million | `Label` 0/1; `attack_cat` kept as the raw label, blank read as Normal |

Rows with a missing or infinite value in any schema feature are dropped and
counted, as the served pipeline drops them. Labels are the datasets' own and
are never re-adjudicated. The raw label (CIC's finer label, UNSW's category)
rides along with every row so that each cell can be read per family.

## 3. The honeypot's flows

The honeypot's third run captures packet headers on the instance
(`cdk/lib/stacks/honeypot-stack.ts`, generation 4), and
`scripts/pcap_flows.py` turns them into flows on the schema with a label
each flow earns by construction:

- **attack** — a flow initiated by an address on the internet toward the
  honeypot. Nothing on the honeypot invites traffic, so every such flow is
  unsolicited: a probe, a scan, a brute-force attempt, a web crawler's fetch.
  (A crawler is unsolicited too; whether a model should flag it is a question
  the per-label table can answer, because the extractor records the port.)
- **benign** — a flow the honeypot itself initiated (its uploads to S3, DNS,
  NTP and the metadata service: the only traffic it can originate), or a
  flow from an address the operator names at extraction (`--benign-source`),
  the addresses from which `scripts/honeypot_visit.py` fetched the lure page
  during the run. The visit log is committed with the flows.

The honeypot therefore gives a real recall figure and a narrow
false-positive figure: the benign side is the platform's own traffic and the
operators' visits, not a population of users, and the record says so wherever
the number appears.

How the run is made, from a terminal with the workload profile:

1. `cd cdk && npx cdk deploy CloudSentinel-Honeypot --profile cs-workload --require-approval never`
   — the outputs give the instance id, its public address and the bucket.
2. Ten minutes later, `aws ec2 get-console-output --profile cs-workload
   --instance-id ID --output text | grep honeypot-` must show the sshd
   settings and `honeypot-capture: active` twice (the service and the timer).
   On Windows the CLI fails to print the boot log (a character in it that the
   console code page cannot encode, before `grep` runs); the same lines come
   from boto3 in the venv:
   `python -c "import boto3; print('\n'.join(l for l in boto3.Session(profile_name='cs-workload', region_name='us-east-1').client('ec2').get_console_output(InstanceId='ID').get('Output', '').splitlines() if 'honeypot-' in l))"`.
3. Within about twenty minutes the first file is in the bucket — the capture
   closes a file every fifteen minutes and the uploader runs five minutes
   after boot and every five minutes after, so the first upload is the first
   timer tick after the first file closes:
   `aws s3 ls s3://BUCKET/captures/ --recursive --profile cs-workload`. If
   nothing arrives in an hour, the capture or the upload is broken and the run
   is not started: destroy, read the console output, fix, redeploy.
4. Start `python scripts/honeypot_visit.py http://ADDRESS/ --log
   docs/honeypot-visits-<month>.jsonl` on the laptop whenever it is on, and
   commit the log at the end.
5. Run for ten days or more. At the end, in this order: `aws ec2
   stop-instances --profile cs-workload --instance-ids ID` and wait until it
   is stopped (the capture service's stop step sends the last file), then
   `aws s3 sync s3://BUCKET/captures/ ~/Downloads/honeypot-captures/
   --profile cs-workload`, then `npx cdk destroy CloudSentinel-Honeypot
   --profile cs-workload`. The bucket stays; `aws s3 sync` again after the
   destroy picks up nothing new, which is the check that the stop flushed it.
6. `python scripts/pcap_flows.py ~/Downloads/honeypot-captures --host
   10.99.0.8 --visits docs/honeypot-visits-<month>.jsonl --out
   ml/harmonized/honeypot-flows.csv`, then the harmonizer's `flows` source
   and the matrix's `--extra`; the summary the extractor prints goes in the
   record with the GuardDuty incident count for the same days, which should
   be a small fraction of the flows (GuardDuty reports a brute-force
   campaign once; the capture holds every attempt).

## 4. The runs

```bash
python ml/evaluation/harmonize.py cic2017 --data PATH/cicids2017-corrected --out ml/harmonized/cic2017.npz
python ml/evaluation/harmonize.py cic2018 --data PATH/CSECICIDS2018_improved.zip --keep-every 30 --out ml/harmonized/cic2018.npz
python ml/evaluation/harmonize.py unsw --data PATH/unsw-nb15 --out ml/harmonized/unsw.npz
python ml/evaluation/cross_matrix.py --data ml/harmonized/cic2017.npz ml/harmonized/cic2018.npz ml/harmonized/unsw.npz \
    --out ml/models/harmonized_matrix.json
```

The primary run is the matrix above: ten models at the served settings
(300 trees, depth 8, learning rate 0.1, the class weight from the training
rows), a stratified 70/30 split with seed 42 for the diagonal, and the
whole of each other dataset for the off-diagonal cells. The secondary run
adds the destination port (`--with-port` on every table, `--out
ml/models/harmonized_matrix_port.json`) and is read beside the primary, not
instead of it: a port is a strong feature and a brittle one, and the gap
between the two runs is the measure of how much of the result is "port 22".
The honeypot run passes the honeypot table as `--extra` once its flows exist;
it is scored by every model and trained on by none. Nothing is tuned on any
test set: no threshold, no feature choice, no re-weighting after a cell is
seen. The decision threshold is the served route's, a probability of 0.5;
AUC is reported beside it because it needs no threshold.

The harmonized tables and the result files are committed
(`ml/harmonized/*.json` always; the `.npz` tables when they are under a few
megabytes, otherwise their `.json` provenance alone), and the figures go to
the model card as section 6.4 and to `docs/evaluation.md`.

## 5. Expectations, written before the first run

Each is a number the result either meets or does not; the reading beside it
is what the project will conclude in each case, decided now.

| # | Expectation | If met | If not |
|---|---|---|---|
| G1 | **The schema keeps the within-dataset signal.** Each diagonal cell's AUC is at least 0.95. | Fourteen features are enough to separate attack from benign inside one capture, so the off-diagonal cells measure transfer, not a crippled model. | The schema loses too much; the off-diagonal cells cannot be read as transfer, and version 2 of the protocol must widen the schema first. |
| G2 | **Harmonizing does not make the known pair worse.** The `cic2017` → `cic2018` cell's AUC is at least 0.577, the figure from section 6.3 with 83 features. | The dataset-specific features carried the network's fingerprint rather than the attacks; removing them did not cost transfer. | The 83 features carried signal that does transfer, and the fingerprint lies elsewhere — in the distributions of the quantities themselves. |
| G3 | **Every cross cell is better than chance by a margin.** All six off-diagonal cells have AUC of at least 0.55. | Something of what "attack traffic" looks like carries across networks and extraction tools. | At least one pair shares nothing the schema can see; which pair, and which families (the per-label tables), is the finding. |
| G4 | **More networks do not hurt.** Each leave-one-out cell's AUC is at least the better of the two cross cells into the same dataset. | Variety in training helps a detector meet a network it has not seen. | Two networks' idiosyncrasies pull against each other; a detector for this platform should be trained on this platform's traffic and nothing else. |
| G5 | **The honeypot's attackers are recognizable.** The all-three model flags at least 80% of the honeypot's unsolicited inbound flows. | What the public datasets call brute force and reconnaissance is what this platform receives, and a detector trained on them has a place in its pipeline. | The public datasets' attacks are not this platform's; the detector earns its place only from the platform's own labelled flows, and the model card's intended use narrows accordingly. |
| G6 | **The honeypot's own traffic is not an attack.** The same model flags at most 10% of the benign flows (the honeypot's uploads and the operators' visits). | The false-positive side, narrow as it is, is tolerable. | The detector's false alarms on the platform's own traffic would swamp the real findings, and it cannot be put on the pipeline as it stands. |

Secondary, read beside the primary: with the port added, the diagonal rises
and the off-diagonal cells rise less, or fall — the port names the service,
not the behaviour, and the datasets' attacks sit on different services. A
result the other way round is a finding about the schema.

Two things these runs cannot show, stated now: a cell is about the labels
the dataset carries, which the model card's section 4 and the corrected
releases' authors have shown to be imperfect; and an AUC on a random split
within a capture (the diagonal) is a ceiling, not a detection rate, for the
reason section 6.1 gives. The number the project will quote from this work
is the leave-one-out row, and G5 and G6 when the honeypot's flows exist.

## 6. Record

| Date | Step | Result |
|---|---|---|
| 2026-10-24 | Protocol drafted and committed; `harmonize.py`, `cross_matrix.py` and their tests written against synthetic rows. No dataset read. | — |
| 2026-10-24 | Expectations G1–G6 adopted: pushed to `main` in `80cfb39` at 14:20Z, before any table existed. | — |
| 2026-10-24 | Tables built with `harmonize.py` (provenance in `ml/harmonized/*.json`, `03b7791`): `unsw` 14:52Z, `cic2017` 14:58Z, `cic2018` 15:05Z. | `cic2017`: 2,099,976 rows, 505,431 attack (the corrected release's 517,410 less the 11,979 attempted, counted benign), 27 raw labels. `cic2018`: one row in thirty of 63,195,088 → 2,106,505 rows, 117,771 attack, 22 raw labels. `unsw`: 2,540,047 rows, 321,283 attack, 10 raw labels; the nine attack categories at their published counts to the flow (Generic 215,481 … Worms 174), the first three raw files holding 700,001 rows each rather than the published 700,000. Nothing dropped for missing or infinite values in any table. |
| 2026-10-24 | Honeypot third run started (generation 4). `CloudSentinel-Honeypot` deployed in the workload account, `CREATE_COMPLETE` 14:46:56Z: instance `i-0c271a8622a6d09d7` at 3.218.249.58, bucket `cloudsentinel-honeypot-capturesde857d5d-pnhs7xjbinfc`. Console at 15:02Z: `permitrootlogin no`, `pubkeyauthentication no`, `passwordauthentication yes`, `allowusers honeypot-no-such-user`, `honeypot-capture: active` twice. | Capture open 14:46:54Z; first file `capture-20261024T144654Z.pcap`, 125,398 bytes, in the bucket at 15:06:17Z. Visit logger started 14:49:31Z (`docs/honeypot-visits-2026-11.jsonl`, committed at the end). Ten days end 3 November 14:46Z. |
| 2026-10-24 | Primary run: `cross_matrix.py` on the three tables, 15:20–15:24Z (`ml/models/harmonized_matrix.json`, committed in `4592fdf`). | G1 met: diagonals 1.000, 1.000, 0.9996. G2 met: 0.771. G3 not met: UNSW-NB15 → CICIDS2017 0.260 and → CSE-CIC-IDS-2018 0.363, both inverted rather than near chance; CSE-CIC-IDS-2018 → UNSW-NB15 0.556, 0.006 above the line. G4 not met in any direction: 0.634 against 0.954, 0.665 against 0.771, 0.884 against 0.902. Read in the model card, section 6.4, with the conclusions section 5 fixed. |
| 2026-10-24 | Secondary run: the three tables rebuilt with `--with-port` (seven UNSW-NB15 rows dropped, their port not readable as a number), the matrix in 4.9 min (`ml/models/harmonized_matrix_port.json`). | Diagonals at 1.000 as before. Five of six cross cells fell — CSE-CIC-IDS-2018 → UNSW-NB15 from 0.556 to 0.324, below chance like both UNSW-NB15 cells; CICIDS2017 → UNSW-NB15 from 0.902 to 0.735 — and one rose (CSE-CIC-IDS-2018 → CICIDS2017, 0.954 to 0.971). Leave-one-out 0.686, 0.617, 0.693. The secondary expectation held but for those two; SSH-Patator into 2017 flagged at 0.07% with the port against 9.3% without. |
| 2026-10-25 | The extractor checked on the third run's first 19 hours, summary only and nothing scored: 77 capture files, 6.9 MB, packets from 14:46:54Z on 24 October to 10:03:56Z on 25 October. The first try was given the instructions' placeholder, `PRIVATE-IP`, as `--host`; the extractor accepted it, matched no packet to it, and labelled every flow the honeypot began as an attack. `--host` is now refused unless it is the commonest address in the capture, which the honeypot's own always is. | With `--host 10.99.0.8` (the instance's private address): 17,989 flows — 7,142 unsolicited inbound from 622 addresses (port 22: 5,064; 80: 468; 23: 377; 443: 176; 3389: 143), 10,790 self-initiated (the time service and the metadata service, DNS, DHCP, the uploads to S3), 57 the operator's visits. Inbound flows ended by a new SYN on the same ports 3,787, an RST 1,774, the end of the capture 1,277 (idle ones, flushed at the end as CICFlowMeter flushes them), both FINs 212, the 120-second limit 92. |
| 2026-11-01 | The third run stopped by the author's decision after 8 days 3 hours 42 minutes, short of the ten days section 3 set, before any flow was scored: `StopInstances` at 18:29:02Z (CloudTrail), the captures synced (782 files), the stack deleted at 18:37:32Z with the bucket retained. GuardDuty raised 2 incidents on the instance over the same days (27 October 02:07Z and 28 October 11:47Z, one finding each). | `pcap_flows.py --host 10.99.0.8 --visits docs/honeypot-visits-2026-11.jsonl`: 919,619 records, 60,651 of them not IPv4; 177,478 flows from 14:46:54.588Z on 24 October to 18:28:51.255Z on 1 November — 100,288 self-initiated, 522 the operator's, 76,668 unsolicited inbound from 4,412 addresses (port 22: 54,411; 80: 6,525; 23: 3,597; 443: 2,874; 3389: 1,786; 8080: 1,063; 5900: 630; 3306: 342; 17 to four high ports). Inbound flows ended by a new SYN 42,690, an RST 15,495, the end of the capture 10,586, both FINs 4,266, the 120-second limit 3,631. Harmonized at 18:39Z with nothing dropped (`ml/harmonized/honeypot.json`). The visit log is committed with the operator's addresses replaced by labels — 474 visits from three addresses, one of them timed out, and one with no address learned — and the unmasked log is kept with the captures, outside the repository. |
| 2026-11-01 | The honeypot scored: the matrix again with `--extra ml/harmonized/honeypot.npz`, 18:39–18:45Z (`ml/models/harmonized_matrix_honeypot.json`). | **G5 not met**: the all-three model flags 8,948 of the 76,668 unsolicited inbound flows, 11.67% (AUC 0.824). **G6 met**: 438 of the 100,810 benign, 0.43% — 394 of the honeypot's own 100,288 and 44 of the operator's 522 visits. Beside them, the single-dataset models: CICIDS2017 60.6% of inbound at 3.26% of benign, CSE-CIC-IDS-2018 15.8% at 0.05%, UNSW-NB15 3.4% at 0.21%. The nine models trained again for this run did not reproduce the 24 October cells to the digit: cross cells up to 0.036 apart (CSE-CIC-IDS-2018 → UNSW-NB15 0.520 against 0.556), leave-one-out 0.651, 0.639 and 0.884. The venv's XGBoost 3.3.0 and NumPy 2.5.1 were installed on 25 October, after the first run, which recorded no versions; at those versions the models are identical run to run (checked on synthetic data). G1, G2 and G4 read the same in both runs; G3 fails on three cells here and two in the first, since the 0.006 by which CSE-CIC-IDS-2018 → UNSW-NB15 passed is smaller than the difference between the runs. The first run's figures stand as recorded. |
| 2026-11-01 | Section 7 added and expectations G7–G10 adopted: pushed to `main` in `f47c3d4` at about 19:20Z, before the split was run. | — |
| 2026-11-01 | Section 7's run, 19:28–19:29Z (`ml/models/honeypot_timesplit.json`; XGBoost 3.3.0, NumPy 2.5.1, pandas 3.1.0). Training: the 113,865 flows begun before the cut, 46,553 of them unsolicited inbound from 3,179 addresses; test: the 63,613 begun from it on, 30,115 inbound. | **G7 met**: H flags 30,099 of 30,115, 99.95% (AUC 0.9997). **G8 met**: 8,393 of the 8,400 from 1,233 addresses that began no unsolicited flow before the cut, 99.92%. **G9 not met**: 618 of the 33,498 benign, 1.84% — 612 of the honeypot's own 33,398 and 6 of the operator's 100. **G10 met**: P+H flags 99.65%, 0.30 points below H. B, `fwd_mean_len` ≤ 67.6 bytes: 96.41% of inbound, 91.50% from new addresses, 3.11% of benign and 10 of the operator's 100 — at G7's level, not at G9's, so H is quoted with B beside it as the section fixed. |

## 7. Trained on the platform's own traffic (added 2 November 2026)

Added after G1–G6 had been read, as a new experiment with its own
expectations, written and pushed before it is run. It changes nothing
above: the schema, the label rule and the earlier runs stand as recorded.

G4 and G5 point one way: the public datasets' attacks are not this
platform's, and a detector for it has to learn from its own traffic. The
model trained on all three public datasets flagged 11.7% of the honeypot's
unsolicited inbound flows. This section asks what the honeypot's own flows
can teach a detector about the flows that reach it next.

**The split.** The third run's flows, `scripts/pcap_flows.py`'s CSV, are
split by the time each began: every flow that began before 30 October 2026
00:00 UTC trains (the run's first five days and nine hours); every flow that
began at or after it is tested (the last two days and about eighteen
hours). The cut is a date, not a fraction, so that every test flow is later
than the training flows, as it would be for a detector in use. Rows the
harmonizer drops, a feature that is not a finite number, are dropped here
too and counted.

**The models**, each at the served settings and the served threshold of 0.5,
with nothing tuned on the test days:

- **H**, trained on the training days alone, on the fourteen features of
  section 1, without the port.
- **P+H**, trained on the three public tables of section 2 and the training
  days together.
- **B**, a baseline: the single feature and threshold that best separate
  the training days' attack and benign flows (highest balanced accuracy,
  either direction), applied to the test days unchanged. It says how hard
  the task is; what one feature does, a model can claim no credit for.

`ml/evaluation/honeypot_timesplit.py` fits all three and prints every
figure below; the result goes to `ml/models/honeypot_timesplit.json`, with
the library versions it ran under. The CSV holds addresses and is not
committed; the result holds counts and fractions only.

**Measured on the test days:** the fraction of unsolicited inbound flows
flagged; the same for flows from addresses that began no unsolicited flow
in the training days, attackers the model has not met; the fraction of
benign flows flagged, with the operator's visits apart, since they are the
only benign traffic that comes in from outside; and AUC beside each, which
needs no threshold.

| # | Expectation | If met | If not |
|---|---|---|---|
| G7 | **The platform's attackers are recognizable from its own traffic.** H flags at least 93% of the test days' unsolicited inbound flows. | Trained on the platform's own traffic, the detector recognizes what reaches the platform next. | Even its own traffic does not carry from five days to the next three; what arrives changes faster than that. |
| G8 | **New attackers too.** H flags at least 93% of the test days' unsolicited inbound flows from addresses that began no unsolicited flow in the training days. | What it learned is how the traffic behaves, not which addresses sent it that week. | It recognizes returning attackers better than attack traffic; the G7 figure leans on repetition. |
| G9 | **The platform's own traffic stays quiet.** H flags at most 1% of the test days' benign flows, and at most 10% of the operator's visits among them. | The detector could sit on the platform without its own traffic drowning the findings. | It cannot separate the honeypot's own traffic from attacks at the served threshold; flagging the operator's visits means it flags inbound traffic as such. |
| G10 | **The public datasets add nothing once the platform's own traffic is in.** P+H flags no more than one percentage point more of the test days' unsolicited inbound flows than H. | The public datasets' attacks are not this platform's (G5), and adding them to its own traffic does not help. | The public datasets carry something about these attackers that five days of the platform's own traffic do not. |

**How B is read, fixed now.** If B alone reaches G7's and G9's levels, the
record says the task is easy on a honeypot: one feature separates its own
traffic from what comes in, and H's figures show what the platform's flows
allow, not what a model adds. H is then never quoted without B beside it.

**What this cannot show, stated now.** The benign side is the instance's
own traffic and one operator's scripted visits, not a population of users,
so G9 is a false-alarm figure for this honeypot and nothing wider. Training
and test days come from one instance and one address, eight days in all. A
model that meets G7–G9 here is evidence that a detector for the platform
must learn from the platform's own labelled traffic, the conclusion G4 and
G5 point to; it is not a detection rate. The figure quoted from this
section is H's on the test days, with B's beside it.

## 8. The detector at work (added 2 November 2026)

Added after G7–G10 had been read, as a new experiment with its own rule and
expectations, written and pushed before the rule is computed or the run
begins. It changes nothing above: section 7's verdicts stand as recorded.

Section 7 ended on a model, H, that flags 99.95% of the honeypot's later
unsolicited inbound flows and 1.84% of its own traffic, and said its figures
were not a detection rate: they come from days chosen for a test, at a
threshold nobody had chosen for the purpose, from a model nothing served.
The author decided on 2 November that the detector is a feature of the
platform; this section is what that takes. It puts H to work — scoring the
honeypot's traffic as it is captured and reporting what it flags as findings
— and measures it at work on days nobody has seen (ADR 0011).

**The model.** H as section 7 trained it: the same flows, cut, features and
settings. `ml/evaluation/platform_detector.py` trains it again and goes no
further unless it reproduces section 7's record exactly — every count
flagged on the test days at a probability of 0.5, in every category, and the
AUC to six places — so that the model put to work is the one whose G7–G9
are recorded. P+H is not served: G10 found nothing gained from the public
datasets.

**Its threshold, by a rule fixed now.** Section 7's test days are spent as a
test. Their verdicts stand and are not read again as evidence; from here
they are the days the threshold is chosen on. The threshold is the lowest at
which H flags at most 0.5% of those days' benign flows and at most 5% of the
operator's visits among them: half of G9's limits, the other half left for
days the model has not seen. The rule fails if, at that threshold, H flags
less than 95% of those days' unsolicited inbound flows, or of those from
addresses new to the training days; the detector is then not put to work at
these limits, the record says so, and different limits would be a new
section, not an edit to this one. The script writes the model to a file git
ignores, and its SHA-256, the threshold, the figures it was chosen on and
the library versions to `ml/models/platform_detector.json`.

**At work.** The honeypot runs a fourth time (generation 5), and each capture
file is scored as it lands in the bucket: turned into flows by section 3's
extractor, one file at a time; scored by H at the chosen threshold; and each
address that began a flagged flow is reported once a UTC day as a finding of
the platform's own source, `detector`, updated as the day goes on. Flows the
honeypot began are scored and counted but never reported: an address the
honeypot chose to talk to did not come at it. The run lasts at least seven
days, with the operator's visits logged by `scripts/honeypot_visit.py` as in
the third run, and is stopped by the author's decision, recorded with its
time, before any of its flows is scored offline. Edits to this section are
allowed, and dated here, until the run begins; none after.

*Edit, 2 November 2026, before the run.* Only addresses on the internet are
reported. A flow begun by one of the VPC's own services — its DHCP server
answering the instance at boot, say — is labelled unsolicited inbound by
section 3's extractor, but section 3's rule is about someone on the internet,
and the detector does not report the VPC's own addresses, link-local ones or
loopback. D3 and D4 count addresses on the internet; D1 and D2 count flows as
section 3 labels them, unchanged.

**Measured on the fourth run.** Its captures are turned into flows by
`scripts/pcap_flows.py` over the whole capture, as in the third run, and
scored by H at the chosen threshold for D1 and D2. The detector's findings
and the function's own record are read beside them for D3–D5. Days are UTC
days, and a flow belongs to the day it began.

| # | Expectation | If met | If not |
|---|---|---|---|
| D1 | **It catches what comes in, on days nobody has seen.** H flags at least 93% of the run's unsolicited inbound flows, and at least 93% of those from addresses that began no unsolicited flow in the third run. | The detector recognizes the platform's attackers a week after its training days, newcomers included, at the threshold it serves. | What reaches the honeypot changed between the runs faster than its training days can follow; the ports and kinds of flow it misses are the finding. |
| D2 | **Its own traffic stays quiet at the served threshold.** H flags at most 1% of the run's benign flows and at most 10% of the operator's visits among them: G9's limits, on new days. | The threshold chosen on spent days holds on new ones, and G9, not met at a probability of 0.5, is met at the threshold chosen for it. | Half of G9's limits was not margin enough: the honeypot's own traffic varies between runs more than the rule allowed for. |
| D3 | **What it reports is right, address by address.** On each day, at least 93% of the addresses that began an unsolicited inbound flow are named by a detector finding for that day; and at most 1% of the run's detector findings name an address that began none, the operator's. | An analyst reading the detector's findings sees nearly every source that came at the platform, and almost nothing else. | Reporting by address undoes what the flow figures promise — one flagged visit names the operator for a day, one missed probe hides a source — and the unit of a finding has to change. |
| D4 | **The pipeline carries every report and invents none.** For every day, the addresses named by detector findings in the findings table are exactly those the same code reports when run offline on the same capture files, one file at a time. | The live path is the offline computation, delivered. | Where the two part — which files, which addresses, why — is a defect in the live path. |
| D5 | **Promptly.** For at least 95% of capture files, the last finding the file causes is stored within two minutes of the file's arrival in the bucket. | A source that comes at the platform is in the console within one capture interval and two minutes. | Where the time goes — the function, the event bus, the stream — is the finding. |

**How B is read, fixed now.** Section 7's B, `fwd_mean_len` at or below
67.6 bytes, is applied unchanged to the fourth run's flows beside H. If it
reaches D1's and D2's levels, the record says the task is easy on this
honeypot, and H is never quoted without B beside it.

**What this cannot show, stated now.** Section 7's limits stand: one
instance and one address, and a benign side made of the honeypot's own
traffic and one operator's scripted visits, not users. Met, D1–D5 say that
the platform runs a detector trained on its own traffic which reports what
comes at its exposed host — nearly all of it, with few false reports, within
minutes, on days it never saw. They say nothing of a host whose inbound
traffic includes users. The figures quoted from this section are D1's and
D2's, with B's beside them, and D3's.
