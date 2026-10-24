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
   PRIVATE-IP --visits docs/honeypot-visits-<month>.jsonl --out
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
