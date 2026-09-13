# Model Card — CloudSentinel Intrusion Detection

Two XGBoost classifiers trained on CICIDS2017 and served by the CloudSentinel
API. This document records what they do, how well they do it, and — at greater
length — the reasons the headline figures should not be read as real-world
detection accuracy.

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

**Intended:** prioritisation support inside CloudSentinel. The model scores
network flows to help an analyst decide what to look at first. It does not
trigger remediation on its own; the SOAR layer routes on finding severity, and
destructive actions require authenticated human approval.

**Not intended:** autonomous blocking, evidence in an incident report, or any
use where a false positive carries direct cost without human review.

**Known limitations**

- Trained on 2017 traffic. Attack techniques have moved on.
- Network-flow features only. No cloud control-plane signal — API calls, IAM
  activity and storage misconfiguration are invisible to it.
- Evaluated on the uncorrected CICIDS2017, with the leakage described above.
- Bot and Infiltration are supported by too little data to be relied on.
- No drift monitoring. Performance on traffic unlike the training distribution
  is unmeasured.

---

## 6. Future work

- Retrain and re-evaluate on Engelen et al.'s corrected dataset, and report the
  difference. That difference is itself a result worth publishing.
- Evaluate against UNSW-NB15 as an independent dataset, to separate what the
  model learned from what CICIDS2017 leaked.
- Collect labelled flows from the platform's own environment for a small
  in-domain evaluation set.
- Add drift monitoring so degradation is detected rather than assumed absent.

---

## 7. Reproducing

```bash
# Preprocess the raw CSVs into stratified splits (SageMaker Processing)
python ml/processing/run_processing.py

# Train both models (SageMaker Training, ml.m5.2xlarge, ~10 minutes)
python ml/training/run_training.py

# Evaluate on the held-out test split (local)
python ml/evaluation/evaluate.py
```

Training job `cicids-xgb-2026-09-13-17-36-23-826`: 616 billable seconds.
Full metrics in `ml/models/test_metrics.json`.
