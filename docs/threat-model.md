# Threat Model

A STRIDE analysis of CloudSentinel. The purpose is to record where the system
can be attacked, what currently stops each attack, and — more usefully — what
does not. Threats with no mitigation are listed as residual risks rather than
quietly omitted.

Scope: the deployed platform (four-account AWS Organization, ingestion
pipeline, SOAR layer, API, dashboard) and its build pipeline. Out of scope:
AWS's own control plane, and the security of the operator's endpoint device.

---

## 1. System decomposition

### Assets

| Asset | Why it matters |
|---|---|
| Normalized findings (DynamoDB) | Discloses the organization's weaknesses to anyone who reads it |
| Remediation authority (Step Functions) | Can isolate instances, disable credentials, alter bucket policies |
| Cognito user pool | Holds the only identities that can approve remediation |
| CDK source and pipeline | Compiles to infrastructure; controls the whole platform |
| ML model artefact (S3) | Influences which findings are prioritised |
| Cross-account roles | Reach into three member accounts |

### Trust boundaries

| # | Boundary | What crosses it |
|---|---|---|
| B1 | Internet → CloudFront | Anonymous requests for the SPA |
| B2 | Browser → ALB → API | Authenticated requests carrying a JWT |
| B3 | AWS security services → EventBridge → Kinesis | Findings entering the pipeline |
| B4 | Workload account → Audit account | Promotion of the trained model |
| B5 | Operator → Step Functions | **Approval decisions authorising destructive actions** |
| B6 | GitHub Actions → AWS | OIDC-federated deployment |
| B7 | Incidents → language model (Bedrock) | Attacker-influenced finding text in; advisory triage notes out |
| B8 | Platform → threat-intelligence providers (AbuseIPDB, AlienVault OTX) | The addresses and domains incidents name out; reputation verdicts in |

B5 is the boundary that distinguishes this system from a passive dashboard: a
human decision on one side causes irreversible change on the other.

One deliberate attack surface sits outside every boundary above. The honeypot
(`CloudSentinel-Honeypot`, deployed on demand in the workload account) is an
instance that exists to be attacked, so the platform sees real findings. It
is built to be worthless to whoever gets in: its own VPC with one subnet and
no NAT, no instance role and no key pair, IMDSv2 required, and a security
group with no outbound rule, so a compromised instance could reach nothing —
not the internet, not the account, not the platform. From its second run
(October 2026) sshd takes password attempts, so that brute force happens where
GuardDuty can see it, but every password is locked, root is refused, keys are
off and the only user allowed to log in does not exist: no attempt can
succeed. The
tests in `cdk/test/honeypot.test.ts` hold each of those properties.

---

## 2. STRIDE analysis

### B1 — Internet → CloudFront

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| **S** | Attacker serves a lookalike dashboard to harvest credentials | Cognito hosted UI is the only credential entry point; the SPA never handles passwords | A phishing page could still imitate the hosted UI. No user training or domain monitoring exists. |
| **T** | Modification of the SPA bundle | S3 bucket blocks public access; origin reachable only through Origin Access Control | Anyone able to write to the bucket alters what every operator executes. Object versioning is off. |
| **I** | Reading the SPA reveals configuration | `config.json` exposes only public values — API URL, Cognito pool and client IDs | None material; these are public by design in a PKCE flow. |
| **D** | Volumetric flood | CloudFront absorbs edge traffic | No AWS WAF and no rate limiting; accepted as a cost trade-off (see `nag-suppressions.ts`). |

### B2 — Browser → API

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| **S** | Forged or replayed token | Every data route verifies the JWT signature against the pool's JWKS, plus issuer and expiry. Asserted by tests, including a forged-signature case. | Token lifetime is Cognito's default; a stolen access token is usable until it expires. No revocation list. |
| **T** | Request tampering in transit | HTTPS end to end; ALB redirects HTTP; TLS 1.2 floor on CloudFront | None material. |
| **R** | Operator denies making a request | ALB access logs record every request | Logs identify the source, not the authenticated principal. **An action cannot currently be attributed to a named operator.** |
| **I** | Cross-origin data theft | CORS restricted to the dashboard origin — previously `*`, which would have let any site issue credentialed requests | None material for browsers that honour CORS. |
| **D** | Expensive queries | `limit` bounded 1–200 and asserted by tests; every findings route reads an index or a key, and the task role holds no `dynamodb:Scan` on that table, so no request costs the whole table | `/incidents` still reads the incidents table in full. Many small requests are now bounded twice — see the next row. |
| **D** | Flooding the API, from one address or with one stolen session | A WAF on the load balancer, created and destroyed with the Api stack: AWS's managed rule groups (IP reputation, common exploits, known bad inputs) and a rate-based rule that blocks an address above 2,000 requests in five minutes, pinned by a test, and both driven past their limits live on 21 October 2026 (`docs/slos.md`). Behind it the API counts identities: 120 requests a minute per verified user in a sliding window, then 429 with a Retry-After, counted only after the token is verified so a forged subject cannot spend a real user's window | The per-user counter lives in the one task's memory, so a second task would count separately. WAF logs are not kept, only its metrics and sampled requests; a managed rule that blocks a legitimate request shows there and nowhere else. |
| **E** | Reaching data without a token | Authorization enforced at the API, not the UI; every data route asserted to return 401 unauthenticated | None known. |
| **T** | Finding text carried into a document | The incident report is rendered with reportlab, whose paragraphs interpret inline markup. Every value from the record is escaped before it enters one, so a title written to contain `<b>` or `<font>` prints as those characters; a test puts markup in a title and reads the PDF back. The report also contains nothing generated: its one derived element is the ATT&CK placement, from a fixed table | A report is read outside the dashboard, where the advisory label on the triage note is the only reminder that part of it is model output over attacker-influenced text. |

### B3 — Findings ingestion

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| **S** | Injecting fabricated findings | EventBridge accepts only AWS service event sources within the organization | An attacker with `events:PutEvents` in the audit account could inject a finding and trigger a remediation workflow. |
| **T** | Altering findings in flight | Kinesis encrypted at rest; TLS in transit; DynamoDB uses a customer-managed key | A record that cannot be read is rejected (ADR 0008), but a well-formed event's content is trusted as it arrives — no schema validation or signature check. |
| **R** | A member account's finding attributed to the administrator | The normalizer files each GuardDuty and Inspector finding under the account the finding itself names, not the EventBridge envelope's, which for a delegated administrator is always the audit account; a test pins the member-account case | Until 18 October 2026 it read the envelope: the honeypot's first five findings, raised in the workload account, were stored and correlated under the audit account. They keep that attribution on the record. |
| **R** | No record of what was ingested | Normalizer logs every normalized finding to CloudWatch | Retention is CloudWatch's default; no immutable archive. |
| **I** | Reading the findings store | Customer-managed KMS key; `kms:Decrypt` scoped by `kms:ViaService` to DynamoDB only | Anyone with the audit account's admin role reads everything. Single-account blast radius. |
| **D** | Flooding the stream | Provisioned shard sustains 1,000 records/second against an observed ~950/day. Throttled writes are graphed; the `findings-fresh` alarm fires when findings wait over five minutes, and `findings-stored` when one is lost for good ([SLOs](slos.md)) | A sustained flood would still throttle ingestion. The alarms report it; nothing prevents it. |
| **D** | The alarms' notifications silently refused | The alarm topic's policy admits CloudWatch for this account's alarms beside its TLS requirement, a test pins the statement, and a change to the topic's policy by anyone but the deployment role is a control change (objective 8) | Until 13 October it did not: the TLS-only policy replaced the default that admits CloudWatch, and all 49 notifications since 20 September were refused, recorded only in each alarm's history. A refusal for another reason would again be visible only there. |
| **D** | One record the normalizer cannot read | Writing to the stream needs `kinesis:PutRecord` in the audit account, held by the ingestion rules' EventBridge role and the account's administrative roles. The normalizer rejects such a record to the failure queue on first sight, so it never holds the shard, and `findings-stored` reports each one (ADR 0008) | Before ADR 0008, E1's re-run (12 October) measured one such record holding every finding behind it for an hour and losing the one directly behind it; E1's third run (13 October) verified the fix: the record was reported in 11 seconds and the finding behind it stored by the same invocation. A stream of such records still raises findings-stored for each, which is the intent. |
| **E** | Normalizer role misuse | Role limited to Kinesis read, DynamoDB write, KMS use through DynamoDB, and sending to its own failure queue | None known. |

### B5 — Operator → Step Functions (approval)

The highest-consequence boundary in the system.

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| **S** | Someone other than the operator approves | The task token is written to a KMS-encrypted DynamoDB table and never leaves AWS. Resuming a workflow requires an authenticated `POST /approvals/{id}/decide` from a token in the Cognito `approvers` group; the API reads the group from the verified token's claims, so an analyst's session can list the queue and decide nothing, and the notification email carries no token and cannot approve anything. Checked live on 21 October 2026 with two accounts against a staged quarantine: the analyst's decision refused with 403 and the queue readable, the approver's accepted and recorded (`docs/slos.md`, `screenshots/approvals-*-2026-10-21.png`). | An approver's session token remains usable until expiry if stolen. Group membership travels in the token, so a user removed from the group keeps the power until their token expires, up to an hour. |
| **T** | Altering the remediation definition | State machine defined in CDK and deployed through a reviewed pipeline | An audit-account administrator can edit the state machine directly in the console; there is no drift detection or alarm. |
| **R** | Denying an approval decision | The deciding principal's Cognito `sub` and a timestamp are written to the approvals record before the workflow resumes; spent tokens are removed and replay returns 409 | Attribution is to a Cognito identity, not to a verified human; a shared account would defeat it. |
| **I** | Approval payload exposes finding detail | SNS topic requires TLS for publishers | Notification content reaches a mailbox outside AWS's trust boundary. |
| **D** | Blocking legitimate remediation | Failed executions surface in the dashboard; the `approvals-decided` alarm fires when an approval expires undecided, and `remediation-runs` when a step errors ([SLOs](slos.md)) | An unapproved execution waits up to 24 hours before anything alerts on it. |
| **E** | Executor exceeds intended scope | Playbook Lambdas hold narrowly scoped permissions; `SAFE_MODE` allows exercising the flow without touching resources | Compromise of a playbook role grants exactly the destructive power the playbook was designed to have. |
| **E** | An analyst promotes themselves to approver | Groups are set by an administrator through Cognito's admin API; the pool allows no self-service, and the console's hiding of the buttons is not the control — the API's check on the claim is, and a test refuses a decision from every token outside the group | Whoever administers the pool can add anyone to the group, with no second approver; the pool's own changes are CloudTrail events but not among the controls objective 8 watches. |

### B6 — GitHub Actions → AWS

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| **S** | Another repository assumes the deploy role | Trust policy pins the `sub` claim to `repo:abhishekjaden/cloud-sentinel:ref:refs/heads/main`; audience checked; asserted by tests | None known. |
| **T** | Malicious code reaching the pipeline | All actions pinned to commit SHAs; Semgrep, gitleaks and Dependabot run on every push | A single maintainer means no second reviewer; anything merged to `main` is trusted. |
| **I** | Secrets leaking through build logs | No long-lived AWS credentials exist; gitleaks scans full history and found none | Build logs are public on a public repository. |
| **E** | CI role escalating to deploy | Separate roles: CI is read-only and assumable from any branch; deploy is restricted to `main` | The deploy role can assume CDK roles in all four accounts — necessarily broad. |

### B7 — Incidents → language model (Bedrock)

The triage function sends each incident and its findings to a model and stores
the note it writes ([ADR 0005](adr/0005-advisory-llm-triage.md)). Finding
fields — resolved domain names, API callers' user agents, bucket and user
names — are chosen by whoever caused the finding.

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| **S** | A forged model response | Calls go to Bedrock over TLS, authenticated with the function's IAM role | None known. |
| **T** | Prompt injection through finding fields steers the note | Data escaped inside tags the prompt declares untrusted; one forced tool schema, validated field by field; unknown fields dropped; attempts flagged on the dashboard | A steered note can still read plausibly. It cannot change anything, but it can mislead an analyst who trusts it. |
| **R** | No record of which model wrote a note | Each note stores its model ID, prompt version and time | None known. |
| **I** | Finding data sent to a model | Stays within AWS; a US inference profile keeps processing in US Regions; the platform does not enable Bedrock invocation logging, so prompts are not stored | Account IDs and resource names are sent. |
| **D** | Exhausting the model quota or budget | Re-triage only when an incident changes; five incidents a run; a throttled run stops | A flood of incidents delays notes; it does not raise cost beyond the cap. |
| **E** | Model output gaining authority | The function cannot write incidents or findings, or touch Step Functions or SNS; the note is shown as advisory plain text beside the computed severity | None known: no path from a note to an action exists. |

### B8 — Platform → threat-intelligence providers

The enricher sends the public addresses and domains that open incidents name
to AbuseIPDB and AlienVault OTX and keeps their verdicts
([ADR 0006](adr/0006-threat-intel-enrichment.md)). This is the only boundary
across which anything leaves the account to a party other than AWS.

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| **S** | A forged provider answer | TLS with certificate and hostname verification to two fixed hosts; each request carries the provider's API key | A provider's own data can be wrong or poisoned; a verdict is labelled indicative everywhere it appears and nothing acts on it. |
| **T** | An indicator shaped to reach somewhere else | The value becomes part of a path, never a host or scheme; only a public address or a plain hostname (labels of letters, digits and inner hyphens) is sent, and the handler validates this itself rather than trusting the normalizer | None known. |
| **R** | No record of what was asked | Every lookup is a row with the providers asked, the time and the expiry; runs log a summary and publish metrics | Rows expire after a week; there is no permanent log of lookups. |
| **I** | Disclosure of what the organisation is seeing | Only the indicator is sent — no account, resource, finding or incident detail — and each indicator is sent once a week at most | The providers learn which addresses and domains appear in this organisation's findings. For a security operations platform that is the service; it is listed here because it is new. |
| **D** | Exhausting the providers' free tiers | Ten lookups a run, a seven-day cache, a one-hour retry on failure; a flood spreads over hours rather than spending the day's quota | A sustained flood of new indicators delays verdicts. It does not raise cost: both feeds are free. |
| **E** | A verdict gaining authority | The enricher writes only its own table and holds nothing that acts; the API, report and triage model read verdicts and act on none of them | None known: no path from a verdict to an action exists. |

---

## 3. Residual risks, ranked

1. **Single-account blast radius.** Audit-account administrator access reads
   every finding, edits the state machine, and disables the KMS key.
2. **Changes to the controls made through the deployment pipeline.** A change
   to the state machine, a rule, a key, GuardDuty, a function, a table or the
   alarms themselves is now reported with its caller unless it arrived through
   CloudFormation's CDK execution role ([SLO 8](slos.md)). A change that does
   arrive that way — a malicious commit on `main`, a stolen GitHub deploy
   role — looks like a deploy, and the run log's diff is the only record.
3. **Unvalidated ingestion input.** A record the normalizer cannot read is
   rejected on first sight (ADR 0008) rather than holding the shard, as it did
   under ADR 0007 alone (E1 re-run, 12 October 2026); but a well-formed event's
   content is still trusted as it arrives.
4. **WAF and rate limits are bounds, not proofs.** A WAF with AWS's managed
   rules and a per-address rate rule fronts the load balancer, and the API
   limits each identity to 120 requests a minute (B2). Both were driven past
   their limits once, on 21 October 2026 (`docs/slos.md`, *The API session of
   21 October*): 150 requests in 14 s from one identity gave 110 answers and
   40 refusals with a Retry-After, and 3,000 unauthenticated requests in
   3 min 25 s from one address gave 2,436 answers and 564 refusals, 589
   blocked by the rate rule on CloudWatch's count — with about 400 admitted
   past the nominal 2,000 before the rule caught up. The WAF keeps metrics
   and sampled requests, not logs, and the per-user counter is per task.

## 4. What this analysis changed

Three items were fixed as a direct result of writing this model. CORS was
restricted from `*` to the dashboard origin; the API container was moved off
root; and the SOAR approval gate was rebuilt so that the Step Functions task
token is held server-side rather than emailed, which removed the system's
highest-ranked residual risk and, in the same change, gave approvals a named
principal. A fourth and fifth followed in October: the single operator role was split
into analysts and approvers, so that reading the platform and resuming a
destructive workflow are no longer the same permission; and the API gained a
WAF and a per-user rate limit, which had been accepted as a residual risk on
cost grounds until the serving layer's on-demand pattern made the WAF's cost
a few rupees a day. The rest are recorded
above rather than silently resolved, because a threat model whose every threat
is neatly mitigated is not describing a real system.
