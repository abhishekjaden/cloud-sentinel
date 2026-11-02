# ADR 0011: The platform's own detector, at work on the honeypot

## Status
Accepted, 2026-11-02, by the author: the intrusion detector stays a feature
of the platform, and is made one by serving the model trained on the
platform's own traffic, in the platform's own pipeline. Its figures wait on
the run in `docs/generalization-protocol.md`, section 8, whose rule and
expectations were pushed with this record.

## Context
The platform's detection has been AWS's. The two XGBoost models `/predict`
serves were trained on CICIDS2017. The model card rules them out for the
platform's own traffic (section 5) — the public-data model flags 11.7% of
the attacks on the honeypot (G5) — and nothing in the pipeline calls them:
the route answers the console's prediction panel and nothing else. Over the
honeypot's third run GuardDuty raised 2 incidents on it, while 4,412
addresses began 76,668 unsolicited flows to it. That is by design:
GuardDuty reports what it judges worth an analyst's time, not who comes at
an exposed host.

Section 7 of the protocol trained H on the honeypot's first five days and
nine hours: it flags 99.95% of the next days' unsolicited inbound flows,
99.92% of those from addresses it had not met, and 1.84% of the honeypot's
own traffic, above the 1% set for it (G9, not met at a probability of 0.5).
One feature alone reaches 96.41% at 3.11%.

On 2 November the README's "What it does" was found to lead with the
CICIDS2017 model's AUC of 0.999963, which its own results table calls an
artefact of the dataset. Presenting the detector as a study rather than a
capability was recommended, and declined by the author: the detector is a
feature. This record is what that takes.

## Decision
1. **The model** is H, reproduced exactly from section 7's record, at a
   threshold chosen by section 8's rule on section 7's spent test days
   (`ml/evaluation/platform_detector.py`). The model file travels with the
   deployment, and the function that serves it refuses a file whose
   SHA-256 is not the one in `ml/models/platform_detector.json`.
2. **It runs in the honeypot stack**, in the workload account, deployed and
   destroyed with the honeypot: a capture file landing in the bucket invokes
   it. No honeypot, no detector, and nothing to pay for between runs.
3. **It computes what the offline record computes.** The file's flows by
   `scripts/pcap_flows.py`'s extractor, copied into the image unchanged with
   the schema's code, one file at a time; H's verdict on each; and, for each
   address on the internet that began a flagged flow, that day's count of
   flagged flows, the ports, and when they were first and last seen, kept in
   a small table of the stack's own so that later files update the day's
   figures. The honeypot's own address is the commonest in the file, as the
   extractor decides it, and a file whose commonest address is not in the
   honeypot's subnet is refused; the instance's id comes from the file's
   key, under which the uploader files it. A flow that crosses a file's
   fifteen-minute boundary is two flows here and one in the whole-capture
   record; D4 compares the live findings with the same per-file computation,
   so the difference is measured, not hidden.
4. **It reports one finding per address per UTC day.** Each file's update
   to an address's day is conditional on that file not having been counted,
   so an invocation retried after a partial run counts nothing twice, and
   every address a file reports is sent again with the day's figures as they
   stand: onto the workload account's bus as source `cloudsentinel.detector`,
   forwarded by a rule there to the audit account's, whose policy admits the
   workload account's events with that source and detail type and nothing
   else. From there the existing path — a rule, the stream, the normalizer —
   stores each copy over the last under the source `detector`, beside
   GuardDuty's, Security Hub's and Inspector's, where the console shows it.
   Each event carries its capture file's arrival time, so that D5 is
   measured from the record. Severity low: a hostile source reaching a host
   that holds nothing.
5. **It never names an address the honeypot began a flow to**, nor one
   that is not on the internet. The honeypot's own flows are scored and
   counted — they are section 8's false-alarm side — but an address the
   honeypot chose to talk to did not come at it, and the VPC's own services
   come at nothing.
6. **No reserved concurrency.** A new account's concurrency quota can be
   ten, and Lambda keeps ten unreserved, so reserving one could fail the
   deployment; the day's tally needs none, every update being conditional
   and additive. A file the function cannot score after two retries, and an
   event the forwarding rule cannot deliver, go to one queue in the workload
   account.
7. **Not yet correlated, not yet triaged.** The correlator joins a
   resource's findings when they are less than 30 minutes apart; a source
   reporting on the honeypot every fifteen minutes would chain every
   GuardDuty finding on it into one incident lasting the whole run. And the
   triage model has never been evaluated on this source. Both wait for a
   design argued from the fourth run's record.

## Alternatives considered
- **The detector as a study, not a feature.** Recommended on 2 November and
  declined by the author.
- **VPC flow logs instead of the captures.** Flow logs carry packets and
  bytes per direction per aggregation interval, not the inter-arrival times
  and lengths H reads; H could not be applied without a schema nothing has
  measured.
- **Report by direction alone.** On a honeypot every address that begins a
  flow, the operator apart, is hostile by construction, so a rule on
  direction is exact here — and useless on any host with users. H judges a
  conversation by its shape, which is what such a host needs, and the
  honeypot is the one place that judgement can be checked against a known
  truth.
- **Retrain on all eight days.** It would leave no unseen days to choose the
  threshold on, and serve a model whose G7–G9 are not recorded.
- **Serve P+H.** G10 found nothing gained from the public datasets.
- **Replace `/predict`'s models.** The route takes CICIDS2017's 78 features,
  and the console's panel stays what it is, the public benchmark's models
  for comparison; the detector's verdicts reach the console as findings.

## Consequences
- The platform runs a detector trained on its own traffic, in its own
  pipeline, measured where it runs. The claim is bounded by the honeypot:
  hostile traffic reaching an exposed host whose only legitimate inbound
  traffic is its operator's (protocol, section 8).
- Volume: several hundred findings a day at the third run's rate, against
  the 920 the platform stored in the whole measured week of 14–21 October.
  Writes and storage cost cents; the console's counts by source will be the
  detector's while the honeypot runs.
- The capture bucket gains one reader, the detector's function, limited to
  the capture prefix. The instance's one credential is unchanged.
- The findings routes and the findings-stored objective count a fifth
  source. A failure in the workload account — a file not scored, an event
  not forwarded — lands in the detector's failure queue there, which no
  alarm watches; the run's D4 counts what it costs.
- Cost: one function call per capture file, 96 a day, seconds each, and a
  few hundred events a day: small beside the instance's ₹25 a day.
- The model card's section 5 now names the detector as the one place a
  model trained on the platform's traffic is served, and the README's
  "What it does" describes both; when the fourth run is read, the model card
  gains the detector's section and the README's results their row, at the
  figures section 8 fixes.
