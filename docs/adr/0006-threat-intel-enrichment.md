# ADR 0006: Threat-intelligence enrichment is cached, bounded and advisory

## Status
Accepted, 2026-10-03. The enricher deploys with empty provider keys and does
nothing until they are filled in; the date the first verdict was written will
be the earliest row in the intel table.

## Context
An incident names the other end of what GuardDuty saw: the address that
brute-forced an instance, the domain it then queried, the address an API call
came from. An analyst's first move on any of these is to look it up — has
this address been reported before, is this domain in anyone's indicator
list — and until now the platform kept neither the indicator nor the answer.
The normalizer stored a finding's resource block and dropped its action
block, where GuardDuty puts the remote party.

Two public feeds answer those questions on free tiers. AbuseIPDB scores an
address from 0 to 100 by abuse reports and allows about a thousand checks a
day. AlienVault OTX holds community-curated "pulses" naming addresses and
domains, with a looser limit. Both are reputation, not proof: a mass scanner
is reported thousands of times and a targeted attacker never.

Three constraints shaped the design. The free tiers are small and shared by
every incident. The platform's cost ceiling is a few tens of dollars a month.
And an indicator sent to a provider discloses something: it tells a third
party what this organisation is seeing, which is a trust boundary the threat
model did not have before.

## Decision
A scheduled function asks the providers about the indicators on open
incidents and keeps the answers in a cache table, where the dashboard, the
report and the triage model read them.

- **The indicator is extracted once, at ingestion.** The normalizer keeps the
  public addresses and domains a GuardDuty finding names under
  `service.action`; the correlator merges them onto the incident. Private,
  loopback, link-local and documentation addresses are left out: they name
  the victim's own network or GuardDuty's sample generator, and a lookup on
  them spends quota on nothing. Ten of each kind per finding, twenty per
  incident.
- **One lookup a week per indicator.** Each verdict is a row in
  `cloudsentinel-intel`, keyed by the indicator, with a seven-day expiry. The
  same attacker appears across many incidents; the cache means the feeds are
  asked once.
- **Ten lookups a run.** The function runs every fifteen minutes and looks up
  at most ten indicators it has no fresh row for, newest incident first.
  Ninety-six runs of ten stay under AbuseIPDB's thousand even on a day when
  every run finds something new. A flood of new addresses spreads its lookups
  over hours rather than exhausting the day in one.
- **Only the indicator leaves.** A public address or a plain hostname becomes
  part of a path on a fixed host — never a host or a scheme — and nothing
  about the incident goes with it. The handler repeats the normalizer's
  validation rather than trusting it.
- **Counts, not prose.** From AbuseIPDB the function keeps the confidence
  score, report count, country, network operator and Tor flag; from OTX the
  number of pulses. Pulse names and descriptions are community text and are
  not stored: a count is evidence and prose is another untrusted input.
- **One word of verdict, with thresholds written down.** Malicious at
  AbuseIPDB confidence 75 or five OTX pulses; suspicious at confidence 25 or
  one pulse; not listed when every provider answered and found nothing;
  unknown when none answered. The thresholds are constants in the handler and
  pinned by tests, so the meaning of "malicious" is a decision in the code,
  not an impression.
- **Failure is tried again, not cached.** A provider that is down, throttled
  or unconfigured leaves its part of the row empty and the row expires within
  the hour instead of the week, so the indicator is asked about again soon.
  A provider whose key is not filled in is skipped, not failed, and a
  dashboard metric shows how many providers are configured — zero means every
  indicator waits forever, which no error would report.
- **Keys in Secrets Manager, filled in by hand.** The stack creates the
  secret with empty keys so it deploys before the operator has any, and the
  function reads the secret again every run until a key is present, so the
  keys take effect on the run after they are filled in. The providers issue
  the keys and only they can rotate them, which is recorded as an accepted
  cdk-nag finding; a rotated key takes effect at the next cold start.
- **Nothing acts on a verdict.** The enricher can read incidents, read and
  write its own table, and read one secret; it cannot write an incident, a
  finding or a note, and holds nothing that starts, approves or stops a
  remediation. A verdict is shown beside the incident, printed in the report,
  and given to the triage model as a fact about the indicator — the prompt
  says it is not a fact about this activity, and that an unlisted indicator
  is not evidence of anything.

## Alternatives considered
- **Enrich in the normalizer, per finding.** Synchronous, and the obvious
  place. Rejected because every finding would spend a lookup — a port probe
  with thirty remote addresses would spend thirty — and ingestion would wait
  on a third party. Enriching per incident, from a cache, asks about each
  attacker once.
- **A paid feed.** More signal and a real SLA, at a cost that would double the
  platform's run rate for a portfolio project. The design makes the provider
  a detail of one function; a paid feed would be a change to `lookup`, not to
  the architecture.
- **GuardDuty's own threat lists.** Already applied: a finding that matched
  one says so in its type. They do not answer the analyst's question about an
  address that did not match.
- **Writing the verdict onto the incident.** One fewer table and no join.
  Rejected because it would make the enricher a second writer of the record
  of an attack, and because a verdict is about an indicator, not an incident:
  one row serves every incident that names the address.

## Consequences
- The threat model gains a boundary, B8: platform → threat-intelligence
  providers. What crosses it is the indicator, over TLS, authenticated by an
  API key. What it discloses is which addresses and domains this organisation
  is seeing, which for a security operations platform is the point and for a
  secretive one would not be.
- A verdict is indicative and is labelled so everywhere it appears. The
  dashboard and report show the numbers behind it, and the triage model is
  told what the word means.
- At the current volume the providers are never close to their limits and the
  table costs cents. The bound exists for the day a flood of findings arrives,
  which is also the day the quota would matter.
- An indicator that no provider has heard of reads "not listed", which an
  analyst may mistake for "clean". The label was chosen to resist that; the
  report says it in words.
- No objective is set on enrichment and nothing alarms on it. An incident
  without a verdict is still correlated, triaged and reported; the dashboard
  graphs lookups, cache hits, provider failures and the configured-provider
  count so a silent failure is visible.
