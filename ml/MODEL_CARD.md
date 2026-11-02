# Model Card — CloudSentinel Intrusion Detection

Two XGBoost classifiers trained on CICIDS2017. The CloudSentinel API's
`/predict` route serves both: the binary model's verdict against a threshold,
and the family the multiclass model finds most likely, with its probability and
the full class distribution. The two are reported side by side and may
disagree; the verdict is always the binary model's, because it is the one
evaluated for that decision. This document records what they do, how well they
do it, and — at greater length — the reasons the headline figures should not be
read as real-world detection accuracy.

---

## 1. Models

| | Binary | Multiclass |
|---|---|---|
| Task | BENIGN vs ATTACK | Attack family, 8 classes |
| Objective | `binary:logistic` | `multi:softprob` |
| Imbalance handling | `scale_pos_weight` 4.081 | Inverse-frequency sample weights |
| Artefact | `binary_model.json` | `multiclass_model.json` |

**Shared configuration:** 300 estimators, max depth 8, learning rate 0.1,
subsample 0.8, colsample_bytree 0.8, `tree_method="hist"`, seed 42.

**Classes:** BENIGN, Bot, BruteForce, DDoS, DoS, Infiltration, PortScan,
WebAttack. The original CICIDS2017 labels are collapsed into these families —
`DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest` and
`Heartbleed` all map to `DoS`; the three `Web Attack` variants map to
`WebAttack`; `FTP-Patator` and `SSH-Patator` map to `BruteForce`.

Folding Heartbleed into DoS is worth naming: it has roughly eleven instances in
the full dataset, far too few to learn as a class of its own.

---

## 2. Data

CICIDS2017, five days of captured traffic, 78 CICFlowMeter features after
cleaning.

| Split | Rows |
|---|---|
| Train | 1,979,509 |
| Validation | 424,182 |
| Test | 424,185 |

**Cleaning applied:** column names stripped of whitespace; infinite values in
`Flow Bytes/s` and `Flow Packets/s` (division by zero) replaced; NaN rows
dropped; non-UTF8 label strings normalised. Flow identifiers, IP addresses and
timestamps are dropped before training so the model cannot key on them.

**Class distribution (test split):**

| Class | Count | Share |
|---|---|---|
| BENIGN | 340,701 | 80.32% |
| DoS | 37,758 | 8.90% |
| PortScan | 23,821 | 5.62% |
| DDoS | 19,204 | 4.53% |
| BruteForce | 2,075 | 0.49% |
| WebAttack | 327 | 0.08% |
| Bot | 293 | 0.07% |
| Infiltration | 6 | 0.001% |

---

## 3. Results on the held-out test split

Validation guided training decisions, so only the test split — unseen by any
training or tuning choice — is reported here.

### Binary

| Metric | Value |
|---|---|
| AUC | 0.999963 |
| F1 | 0.9977 |
| Precision | 0.9959 |
| Recall | 0.9996 |

### Multiclass

| Metric | Value | Reading |
|---|---|---|
| **Macro F1** | **0.9586** | Every class weighted equally — the figure to quote |
| Weighted F1 | 0.9990 | Dominated by BENIGN at 80% of the data |
| Accuracy | 0.9990 | Near-meaningless at this imbalance |

Accuracy deserves the caution. Predicting BENIGN for every row scores 80%
without learning anything at all.

### Per class

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| BENIGN | 1.000 | 0.999 | 0.999 | 340,701 |
| DoS | 0.998 | 1.000 | 0.999 | 37,758 |
| PortScan | 0.993 | 1.000 | 0.996 | 23,821 |
| DDoS | 1.000 | 1.000 | 1.000 | 19,204 |
| BruteForce | 1.000 | 1.000 | 1.000 | 2,075 |
| WebAttack | 0.979 | 0.994 | 0.986 | 327 |
| **Bot** | **0.648** | 0.976 | 0.779 | 293 |
| Infiltration | 1.000 | 0.833 | 0.909 | **6** |

### Confusion matrix

Rows are actual, columns predicted.

| | BENIGN | Bot | BruteF | DDoS | DoS | Infil | PortSc | WebAtt |
|---|---|---|---|---|---|---|---|---|
| **BENIGN** | 340,306 | 155 | 0 | 8 | 71 | 0 | 157 | 4 |
| **Bot** | 7 | 286 | 0 | 0 | 0 | 0 | 0 | 0 |
| **BruteForce** | 0 | 0 | 2,075 | 0 | 0 | 0 | 0 | 0 |
| **DDoS** | 2 | 0 | 0 | 19,202 | 0 | 0 | 0 | 0 |
| **DoS** | 5 | 0 | 0 | 0 | 37,749 | 0 | 2 | 2 |
| **Infiltration** | 1 | 0 | 0 | 0 | 0 | 5 | 0 | 0 |
| **PortScan** | 2 | 0 | 0 | 0 | 9 | 0 | 23,809 | 1 |
| **WebAttack** | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 325 |

---

## 4. Reading these numbers honestly

### The high scores are largely the dataset, not the model

Five of eight classes exceed 0.99 F1. That is not evidence of an exceptional
classifier. Engelen, Rimmer and Joosen (*Troubleshooting an Intrusion Detection
Dataset: the CICIDS2017 Case Study*, IEEE Security and Privacy Workshops, 2021)
audited this dataset and found labelling errors and artefacts in the
CICFlowMeter feature generation that make several attack classes trivially
separable. Results on the uncorrected data are optimistically biased, and these
are results on the uncorrected data.

The figures here establish that the training and serving pipeline is correct end
to end. They do not establish how the model would perform on live traffic.

### Bot precision of 0.648 is the informative result

Bot is the one class the dataset does not hand over. The model recovers 286 of
293 instances, but 155 benign flows are misclassified as Bot — roughly one false
alarm for every two correct detections. At the test split's scale that is 155
spurious alerts against 340,000 benign flows.

This is the number worth discussing, because it is the only one not inflated by
leakage.

*October 2026: on the corrected release Bot's F1 is 0.996 (Section 6.1).
The likeliest reason is the labels, but labels, extraction and test flows
changed together, so how much each contributed is not separated.*

### Infiltration is six samples

Precision 1.000 and recall 0.833 describe five correct predictions and one miss.
A confidence interval on six observations spans nearly the entire range. The
class is reported for completeness and should never be quoted without its
support count.

### The errors fall in the safer direction

Of 395 misclassifications involving BENIGN, almost all are benign traffic
flagged as an attack rather than attacks passed as benign. For a detection
system this is the preferable failure: false alarms consume analyst time,
missed attacks do not get investigated at all. CloudSentinel's human approval
gate compounds this advantage — a false positive costs an operator a rejected
approval, not an isolated production instance.

---

## 5. Intended use and limitations

**Intended:** prioritisation support inside CloudSentinel. The models score
network flows to help an analyst decide what to look at first. The family is a
second opinion read with its probability, not a classification to act on: Bot
precision of 0.648 means roughly one Bot call in three is wrong. Neither model triggers
remediation on its own; the SOAR layer routes on finding severity, and
destructive actions require authenticated human approval.

**Not intended:** autonomous blocking, evidence in an incident report, or any
use where a false positive carries direct cost without human review. Nor
detection on CloudSentinel's own traffic: a model trained on the public
datasets flags 11.7% of the attacks on the platform's own honeypot (Section
6.5), so a detector for the platform has to be trained on the platform's
traffic, and none trained on it is served.

**Known limitations**

- Trained on 2017 traffic. Attack techniques have moved on.
- Network-flow features only. No cloud control-plane signal — API calls, IAM
  activity and storage misconfiguration are invisible to it.
- The served models were trained and evaluated on the uncorrected CICIDS2017,
  with the leakage described above. Retrained on the corrected release they
  score higher on a random split, but miss an attack family absent from
  training entirely (Section 6.2), and on a second network they are barely
  better than chance (AUC 0.58, Section 6.3). On fourteen features shared
  by three networks, a model trained on two of them scores AUC 0.63 to 0.88
  on the third, never better than the better single network, and one
  trained on UNSW-NB15 is worse than chance on both CIC releases (Section
  6.4). A detector for this platform should be trained on its own traffic,
  and the platform's honeypot says so from both sides (Section 6.5): the
  model trained on all three datasets flags 11.7% of the attacks on it,
  while one trained on the honeypot's own first five days flags 99.95% of
  the next days' attacks — and 1.84% of the honeypot's own traffic, above
  the 1% set for it in advance.
- Bot and Infiltration are supported by too little data to be relied on.
- No drift monitoring. Performance on traffic unlike the training distribution
  is unmeasured.

---

## 6. Re-evaluation on corrected data (October 2026)

The served models are unchanged; this section is a measurement. Engelen, Rimmer
and Joosen's corrected CICIDS2017, released alongside a corrected
CSE-CIC-IDS-2018 (Liu, Engelen, Lynar, Essam and Joosen, *Error Prevalence in
NIDS Datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018*, IEEE CNS
2022), re-extracts every flow with a fixed CICFlowMeter and relabels it:
2,099,976 flows and 83 features once identifiers are removed. Two of its labels
need a decision, and both follow its authors:

- **Attempted attacks** — 11,979 flows from an attack tool that carried no
  attack, among them 4,067 of the 4,803 botnet flows and 1,952 of the 2,056
  web-attack flows — are counted as BENIGN.
- **The infiltrated host's port scan** — 71,767 flows the original release
  labelled benign — is counted as PortScan.

`ml/evaluation/retrain_corrected.py` uses the served models' families,
stratified 70/15/15 split, settings and seed, and drops the five rows with
missing or infinite values, as serving does.

### 6.1 Same split and settings

| | Original (served) | Corrected |
|---|---|---|
| Binary AUC | 0.999963 | > 0.99999 |
| Binary F1 | 0.9977 | 0.9999 |
| Binary precision | 0.9959 | 0.9999 |
| Binary recall | 0.9996 | 0.9999 |
| Multiclass macro-F1 | 0.9586 | 0.9797 |
| Multiclass weighted F1 | 0.9990 | 0.9999 |

| Class | F1 original (test flows) | F1 corrected (test flows) |
|---|---|---|
| BENIGN | 0.999 (340,701) | 1.000 (239,181) |
| Bot | 0.779 (293) | 0.996 (110) |
| BruteForce | 1.000 (2,075) | 1.000 (1,040) |
| DDoS | 1.000 (19,204) | 1.000 (14,271) |
| DoS | 0.999 (37,758) | 1.000 (25,747) |
| Infiltration | 0.909 (6) | 0.909 (6) |
| PortScan | 0.996 (23,821) | 1.000 (34,625) |
| WebAttack | 0.986 (327) | 0.933 (16) |

Retraining on the corrected release raised the scores. Section 4 called
Bot's precision of 0.648 the one result the dataset does not make trivial,
and the likeliest reason it rose is the labels: most flows the original
release called botnet were attempted connections that carried no botnet
traffic and look benign, so a model taught to call them Bot called benign
flows Bot too, and counted as benign they leave Bot with an F1 of 0.996. But
the labels, the extraction, the feature set and the test flows all changed
together between the two columns, so the rise cannot be credited to the
labels alone; separating relabelling from re-extraction is future work.
WebAttack fell to 0.933, on 16 test flows — too few to read. A random split puts flows of the same attack session on both sides of it,
so scores this close to 1 show that the classes are separable within one
capture, not that the model generalises.

### 6.2 A day held out of training

The binary model, trained on Monday to Thursday (85% of them; the rest for
validation) and tested on all of Friday, whose botnet and DDoS traffic occur on
no other day:

| Friday | Flows | Flagged as attack | In training |
|---|---|---|---|
| BENIGN | 292,611 | 0.002% | yes |
| DDoS | 95,144 | 99.5% | no |
| PortScan | 159,066 | 99.0% | only the infiltrated host's scan |
| Bot | 736 | **0.0%** | no |

AUC 0.999876, F1 0.9945, precision 1.0000, recall 0.9891. The detector found
the DDoS flows, close to the denial-of-service traffic it had seen, and missed
every botnet flow. Botnet traffic is 0.3% of Friday's attack flows, so the
aggregate F1 hides a complete miss on the one family unlike anything in
training.

### 6.3 Another dataset: CSE-CIC-IDS-2018

The binary model, trained on all five corrected 2017 days, scored on all
63,195,088 flows of the corrected CSE-CIC-IDS-2018: the same fixed
CICFlowMeter, a different network, built on AWS in 2018. All 83 features
matched; 57 benign flows with missing or infinite values were dropped, as in
serving. Attempted attacks count as benign, as above.

| | Value |
|---|---|
| Flows (attack) | 63,195,088 (3,535,422) |
| AUC | 0.577 |
| F1 / precision / recall | 0.082 / 0.133 / 0.059 |
| False-positive rate | 2.27% (1,355,578 of 59,659,666 benign) |

| Attack (2018 label) | Flows | Flagged as attack |
|---|---|---|
| DoS Hulk | 1,803,160 | 0.003% |
| DDoS HOIC | 1,082,293 | 0.0% |
| DDoS LOIC-HTTP | 289,328 | 41.5% |
| Botnet Ares | 142,921 | 0.6% |
| SSH brute force | 94,197 | 4.2% |
| Infiltration: nmap port scan | 89,374 | 79.1% |
| DoS GoldenEye | 22,560 | 16.5% |
| DoS Slowloris | 8,490 | 97.0% |
| DDoS LOIC-UDP | 2,527 | 0.0% |
| Infiltration: other | 289 | 0.0% |
| Web attacks | 283 | 0.0% |

Barely better than chance. DoS Hulk, which the model separated almost
perfectly within 2017 (DoS F1 1.000 in 6.1), is missed almost entirely on the
new network — 47 of 1,803,160 flows flagged; Slowloris and the nmap scan,
whose flows look alike on any network, mostly carry over. Of the false
positives, 298,874 are attempted FTP brute-force connections, counted as
benign and flagged, every one; flows labelled benign alone are flagged at 1.78%, which on this
dataset is still about a million false alerts. The model learned the 2017
network as much as the attacks in it. `ml/models/cross_dataset_2018.json`
holds every label's counts and score histogram; `cross_dataset.py --report`
prints the tables again, under another label mapping if need be, without
reading the data.

### 6.4 Three networks on one schema

Section 6.3 could not say whether the model learned the 2017 network or
whether CICFlowMeter's 83 features carry any network's fingerprint.
`docs/generalization-protocol.md` adds a third dataset made by different
tools — UNSW-NB15 (Moustafa and Slay, *UNSW-NB15: a comprehensive data set
for network intrusion detection systems*, MilCIS 2015), extracted by Argus
and Bro — and puts all three on
fourteen features every source can produce: duration, packets and IP-layer
bytes each way, mean packet length and inter-arrival time each way, packet
and byte rates, the ratio of reply to request packets, and TCP or UDP. One
model at the served settings is trained on each dataset and tested on every
other, one on each pair and tested on the third (leave one dataset out), and
the diagonal is a held-out 30% of the same dataset. The datasets' own labels
are used, attempted attacks counted benign; the threshold is the served 0.5,
and nothing is tuned on a test set. The six expectations were pushed at 14:20
UTC on 24 October, before any table existed; the tables were built that
afternoon — the corrected CICIDS2017, 2,099,976 flows; the corrected
CSE-CIC-IDS-2018, one flow in thirty, 2,106,505; UNSW-NB15, 2,540,047 — and
the matrix was run at 15:20.

AUC, with F1 at the served threshold in brackets:

| Trained on ↓ / tested on → | CICIDS2017 | CSE-CIC-IDS-2018 | UNSW-NB15 |
|---|---|---|---|
| CICIDS2017 | 1.000 (1.000) | 0.771 (0.044) | 0.902 (0.078) |
| CSE-CIC-IDS-2018 | 0.954 (0.326) | 1.000 (0.999) | 0.556 (0.018) |
| UNSW-NB15 | 0.260 (0.039) | 0.363 (0.057) | 1.000 (0.957) |
| The other two | **0.634** (0.250) | **0.665** (0.041) | **0.884** (0.069) |

| | Expectation, written before the run | Result | |
|---|---|---|---|
| G1 | Every diagonal AUC at least 0.95 | 1.000, 1.000, 0.9996 | Met |
| G2 | CICIDS2017 → CSE-CIC-IDS-2018 at least 0.577, the 83-feature figure of 6.3 | 0.771 | Met |
| G3 | All six cross cells at least 0.55 | UNSW-NB15 → CICIDS2017 0.260; UNSW-NB15 → CSE-CIC-IDS-2018 0.363 | Not met |
| G4 | Each leave-one-out cell at least the better cross cell into the same dataset | 0.634 against 0.954; 0.665 against 0.771; 0.884 against 0.902 | Not met |

Each reading below is the one the protocol fixed before the run.

**G1.** Fourteen features are enough to separate attack from benign inside
one capture, so the other cells measure transfer, not a crippled model.

**G2.** Dropping the dataset-specific features raised the known pair from
0.577 to 0.771: the 83 features carried the 2017 network's fingerprint rather
than the attacks. (The 2018 figure is on one flow in thirty, 117,771 of them
attacks; the AUC's sampling error at that size is far below the difference.)
The gain is in ranking only. At the served threshold the fourteen-feature
model flags 2.5% of the 2018 attacks, against 5.9% with 83 features, and
0.64% of the flows counted benign, against 2.27%: across networks it is no
more usable as a detector than before.

**G3.** Not met, and the two failing cells are not near chance but inverted.
A model trained on UNSW-NB15 flags 49.4% of the flows CICIDS2017 counts
benign and 41.6% of CSE-CIC-IDS-2018's, while the families that make up most
of their attacks score below that: Portscan 0.02%, DoS Hulk 2.9% and DDoS
10.0% in 2017; DDoS-HOIC 0.1% and the nmap scan 4.0% in 2018. Inside that
flood it does flag brute force and HTTP floods — SSH-Patator 99.9%,
FTP-Patator 74.3%, and in 2018 LOIC-HTTP 99.8% and GoldenEye 99.0%. The pair
the schema cannot bridge is UNSW-NB15 to either CIC release. The third weak
cell, CSE-CIC-IDS-2018 → UNSW-NB15, passes the line by 0.006: it flags 10.2%
of UNSW-NB15's normal traffic and no attack family above 7.2%. Its margin
is smaller than the difference between two runs: trained again on the same
tables on 1 November, under library versions installed after this run, the
cell read 0.520, and G3 failed on three cells rather than two (Section 6.5,
reproducibility). The verdict is the same either way.

**G4.** Not met in any direction: a model trained on two networks never
matched the better of the two single-network models on the third. The
protocol's conclusion, fixed in advance: two networks' idiosyncrasies pull
against each other, and a detector for this platform should be trained on
this platform's traffic and nothing else. The shortfall is large where
UNSW-NB15 is one of the two (0.634 against 0.954; 0.665 against 0.771) and
small where it is not (0.884 against 0.902) — an observation beside G4, not
a revision of it.

By family, in the leave-one-out cells, the row the protocol quotes:

- **Never carries**: volume denial of service — DoS Hulk 0.0% into both CIC
  releases, as in 6.3; DDoS 0.0%; DDoS-HOIC 0.0% — and UNSW-NB15's Generic
  class, two-thirds of its attacks, 0.3%.
- **Carries**: slow denial of service (Slowloris 90.3% and 97.8%,
  Slowhttptest 70.9%), FTP and web-login brute force (FTP-Patator 96.7%, web
  brute force 98.6% of 73 flows) and scans (Portscan 45.2%, the nmap scan
  83.2%, UNSW-NB15's Reconnaissance 34.1%) — traffic that looks alike on any
  network.
- **SSH brute force**, which the honeypot mostly receives: 9.3% into 2017 and
  0.0% into 2018, though each training pair held the other CIC release's SSH
  brute force. Of the six cells that test an SSH family, one flags it above
  10%: the UNSW-NB15 model on 2017 (99.9%), which flags half of 2017's benign
  traffic with it.
- **Flows counted benign** and flagged: 11.1% into 2017 (about 177,000),
  0.9% into 2018, 1.5% into UNSW-NB15. Into 2018 the 9,980 attempted FTP
  brute-force connections in the sample, benign by the label rule, are
  flagged every one, as in 6.3.

With the destination port as a fifteenth feature — the protocol's secondary
run, read beside the primary; seven UNSW-NB15 rows whose port could not be
read as a number are dropped from its tables:

| Trained on ↓ / tested on → | CICIDS2017 | CSE-CIC-IDS-2018 | UNSW-NB15 |
|---|---|---|---|
| CICIDS2017 | 1.000 (1.000) | 0.756 (0.105) | 0.735 (0.066) |
| CSE-CIC-IDS-2018 | 0.971 (0.329) | 1.000 (0.999) | 0.324 (0.117) |
| UNSW-NB15 | 0.223 (0.030) | 0.333 (0.055) | 1.000 (0.959) |
| The other two | 0.686 (0.256) | 0.617 (0.038) | 0.693 (0.083) |

The protocol expected the diagonal to rise and the cross cells to rise less
or fall. The diagonals had no room to rise. Five of the six cross cells fell:
CSE-CIC-IDS-2018 → UNSW-NB15 from 0.556 to 0.324, below chance like both
UNSW-NB15 cells, and CICIDS2017 → UNSW-NB15 furthest of the rest, from 0.902
to 0.735. One rose (CSE-CIC-IDS-2018 → CICIDS2017, 0.954 to 0.971), and
leave-one-out fell into 2018 and UNSW-NB15 and rose into 2017 (0.634 to
0.686). The expectation held
with those two exceptions: the port names the service, not the behaviour,
and the three datasets' attacks sit on different services. SSH-Patator,
flagged at 9.3% into 2017 without the port, is flagged at 0.07% with it.

The figure to quote from this section is the leave-one-out row: AUC 0.634,
0.665 and 0.884 on a network the model never saw, with F1 0.250, 0.041 and
0.069 at the served threshold. A detector trained on public datasets does
not carry to a new network, on 83 features or on 14, and the platform's
detector should be trained on the platform's own traffic (G4). The
honeypot's third run, from 24 October, records flows from the platform's own
network, labelled by construction, for the protocol's last two expectations:
whether the model trained on all three datasets recognises the platform's
attackers (G5) and leaves the platform's own traffic alone (G6). Shared
feature sets across these datasets were proposed before, to make exactly
this comparison possible (Sarhan, Layeghy and Portmann, *Towards a Standard
Feature Set for Network Intrusion Detection System Datasets*,
arXiv:2101.11315, 2021); this section does not claim the first
cross-dataset result, only one on the corrected releases with its
expectations fixed first. `ml/models/harmonized_matrix.json` and
`harmonized_matrix_port.json` hold every cell with each raw label's count
and flagged fraction; `cross_matrix.py --report FILE --verbose` prints every
table again without the data.


### 6.5 The platform's own traffic

The honeypot's third run kept the packet headers of everything the instance
exchanged from 14:46 UTC on 24 October to 18:29 UTC on 1 November 2026,
eight days and four hours, stopped short of the ten the protocol set by the
author's decision before any flow was scored. `scripts/pcap_flows.py` made
177,478 flows of them on the schema, each labelled by who began it: 76,668
unsolicited inbound from 4,412 addresses, 71% of them to port 22, attack by
construction; 100,288 begun by the instance itself (its uploads to S3, DNS,
NTP, the metadata service); and 522 from the operator's visits to the lure
page. GuardDuty raised 2 incidents on the instance over the same days.

**The public datasets' models on it (G5, G6).** Every model of Section 6.4
scored the flows; G5 and G6 read the one trained on all three:

| Trained on | AUC | Unsolicited inbound flagged (76,668) | Benign flagged (100,810) |
|---|---|---|---|
| CICIDS2017 | 0.792 | 60.6% | 3.26% |
| CSE-CIC-IDS-2018 | 0.790 | 15.8% | 0.05% |
| UNSW-NB15 | 0.519 | 3.4% | 0.21% |
| All three (G5, G6) | 0.824 | **11.7%** | **0.43%** |

G5 not met, G6 met. The reading the protocol fixed in advance: the public
datasets' attacks are not this platform's, the detector earns its place
only from the platform's own labelled flows, and the intended use (Section
5) narrows accordingly. The all-three model ranks the flows better than
chance, but at the served threshold it is quiet and nearly blind. The
single-dataset rows are read beside G5, not instead of it: choosing the
CICIDS2017 model for its 60.6% would be choosing a model on the test set.

**Trained on the platform's own traffic (G7–G10).** The protocol's section
7, pushed before the run: the flows begun before 30 October 00:00 UTC train
(113,865), those begun from it on test (63,613), every model at the served
settings and threshold, nothing tuned on the test days.

| Model | AUC | Inbound flagged (30,115) | From new addresses (8,400; 1,233 addresses) | Benign flagged (33,498) | Operator's visits flagged (100) |
|---|---|---|---|---|---|
| H, the honeypot's first days | 0.9997 | **99.95%** | **99.92%** | **1.84%** | 6 |
| P+H, the three public tables and the first days | 0.9996 | 99.65% | 99.04% | 1.85% | 10 |
| B, `fwd_mean_len` ≤ 67.6 bytes | 0.946 | 96.41% | 91.50% | 3.11% | 10 |

G7, G8 and G10 met; G9 not met: H flags 612 of the honeypot's own 33,398
flows, 1.84% against a limit of 1%, and 6 of the operator's 100 visits,
inside the limit of 10. The baseline reaches G7's level on one feature —
an unsolicited flow's packets are small — but not G9's; what the model adds
over it is 3.5 points of recall, 8.4 points on addresses it had not met,
and 40% fewer false alarms. Adding the public datasets cost 0.3 points
(G10).

Read with the limits the protocol states: the benign side is the instance's
own traffic and one operator's scripted visits, not a population of users,
so 1.84% is a false-alarm figure for this honeypot and nothing wider, about
220 of its own flows a day at the served threshold; and both halves come
from one instance and one address over eight days. The result supports the
conclusion G4 and G5 point to — a detector for this platform must learn
from the platform's own labelled traffic — and is not a detection rate. No
model from it is served.

**Reproducibility.** The run of 1 November trained the nine models of
Section 6.4 again on the same tables, and its cells differ from 24
October's by up to 0.036 AUC (CSE-CIC-IDS-2018 → UNSW-NB15 0.520 against
0.556), the leave-one-out cells by up to 0.026 (0.651, 0.639, 0.884). The
venv's XGBoost 3.3.0 and NumPy 2.5.1 were installed on 25 October, after
the first run, which recorded no versions; at those versions the models are
identical run to run (checked on synthetic data). G1, G2 and G4 read the
same in both runs, and G3 fails in both. The figures quoted in Section 6.4
are the first run's, as recorded; every result file now records the
versions it ran under.

`ml/models/harmonized_matrix_honeypot.json` and
`ml/models/honeypot_timesplit.json` hold every figure above; their scripts'
`--report` prints them again without the data.

---

## 7. Future work

- A benign population. The honeypot gave the platform's attack side by
  construction, and a model trained on five days of it recognises the next
  days' attacks (Section 6.5); its benign side is the instance's own traffic
  and the operator's visits. A detector the platform could use needs
  labelled normal traffic from a service with users, and a threshold chosen
  on data held apart from its test, before its false-alarm rate means
  anything outside a honeypot.
- Separate relabelling from re-extraction (Section 6.1). The two CICIDS2017
  releases share no row-level key — the flows themselves were re-extracted —
  so this means applying the corrected release's labelling to the original
  flows by address, port and time, not a join.
- Add drift monitoring so degradation is detected rather than assumed absent.
- Serve a model trained on the corrected data. Its 83 features are not the
  served models' 78, so `/predict`'s input changes with it.

---

## 8. Reproducing

```bash
# Preprocess the raw CSVs into stratified splits. run_processing.py launches a
# managed SageMaker Processing job and is the intended path; the account's
# processing quota has not cleared, so the splits behind the figures below were
# made by run_local.py in the notebook (ADR 0003).
python ml/processing/run_local.py

# Train both models (SageMaker Training, ml.m5.2xlarge, ~10 minutes)
python ml/training/run_training.py

# Evaluate on the held-out test split (local)
python ml/evaluation/evaluate.py
```

Training job `cicids-xgb-2026-09-13-17-36-23-826`: 616 billable seconds.
Full metrics in `ml/models/test_metrics.json`.

The re-evaluation in Section 6 runs on a laptop, from the corrected releases at
`https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/`:
`CICIDS2017_improved.zip` (328 MB) unzipped into PATH, and
`CSECICIDS2018_improved.zip` (9.7 GB), which is read straight from the zip.

```bash
# 6.1, about 5 minutes; and 6.2, about 2 minutes
python ml/evaluation/retrain_corrected.py --data PATH --out ml/models/corrected_metrics.json
python ml/evaluation/retrain_corrected.py --data PATH --holdout-day friday --out ml/models/holdout_metrics.json

# 6.3: train on all of the 2017 release, score the 2018 release
python ml/evaluation/cross_dataset.py --train PATH --test CSECICIDS2018_improved.zip \
    --model ml/models/cross_model.ubj --workers 2 --out ml/models/cross_dataset_2018.json

# 6.4: the three tables (UNSW-NB15_1.csv to _4.csv and NUSW-NB15_features.csv
# in UNSW), about 8 minutes, then the matrix, about 5; --with-port on all three
# tables, written to other names, for the secondary run
python ml/evaluation/harmonize.py cic2017 --data PATH --out ml/harmonized/cic2017.npz
python ml/evaluation/harmonize.py cic2018 --data CSECICIDS2018_improved.zip --keep-every 30 --out ml/harmonized/cic2018.npz
python ml/evaluation/harmonize.py unsw --data UNSW --out ml/harmonized/unsw.npz
python ml/evaluation/cross_matrix.py --data ml/harmonized/cic2017.npz ml/harmonized/cic2018.npz \
    ml/harmonized/unsw.npz --out ml/models/harmonized_matrix.json

# 6.5: the honeypot's captures to flows and a table, the matrix again with them
# scored by every model (about 6 minutes), then the time split (about 2)
python scripts/pcap_flows.py ~/Downloads/honeypot-captures --host 10.99.0.8 \
    --visits docs/honeypot-visits-2026-11.jsonl --out ml/harmonized/honeypot-flows.csv
python ml/evaluation/harmonize.py flows --data ml/harmonized/honeypot-flows.csv --out ml/harmonized/honeypot.npz
python ml/evaluation/cross_matrix.py --data ml/harmonized/cic2017.npz ml/harmonized/cic2018.npz \
    ml/harmonized/unsw.npz --extra ml/harmonized/honeypot.npz --out ml/models/harmonized_matrix_honeypot.json
python ml/evaluation/honeypot_timesplit.py --flows ml/harmonized/honeypot-flows.csv \
    --public ml/harmonized/cic2017.npz ml/harmonized/cic2018.npz ml/harmonized/unsw.npz \
    --out ml/models/honeypot_timesplit.json
```

The committed visit log has the operator's addresses replaced by labels, so
the extractor's operator flows are reproduced from the unmasked log kept with
the captures; the committed results are the run's own.
