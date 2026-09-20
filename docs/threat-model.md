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

B5 is the boundary that distinguishes this system from a passive dashboard: a
human decision on one side causes irreversible change on the other.

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
| **D** | Expensive queries | `limit` bounded 1–200 and asserted by tests; severity filter uses the GSI rather than a scan | A determined caller can still issue many small requests; no per-principal throttling. |
| **E** | Reaching data without a token | Authorization enforced at the API, not the UI; every data route asserted to return 401 unauthenticated | None known. |

### B3 — Findings ingestion

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| **S** | Injecting fabricated findings | EventBridge accepts only AWS service event sources within the organization | An attacker with `events:PutEvents` in the audit account could inject a finding and trigger a remediation workflow. |
| **T** | Altering findings in flight | Kinesis encrypted at rest; TLS in transit; DynamoDB uses a customer-managed key | The normalizer trusts its input entirely — no schema validation or signature check. |
| **R** | No record of what was ingested | Normalizer logs every normalized finding to CloudWatch | Retention is CloudWatch's default; no immutable archive. |
| **I** | Reading the findings store | Customer-managed KMS key; `kms:Decrypt` scoped by `kms:ViaService` to DynamoDB only | Anyone with the audit account's admin role reads everything. Single-account blast radius. |
| **D** | Flooding the stream | Provisioned shard sustains 1,000 records/second against an observed ~950/day. Throttled writes are graphed; the `findings-fresh` alarm fires when findings wait over five minutes, and `findings-stored` when one is dropped ([SLOs](slos.md)) | A sustained flood would still throttle ingestion. The alarms report it; nothing prevents it. |
| **E** | Normalizer role misuse | Role limited to Kinesis read, DynamoDB write, and KMS use through DynamoDB | None known. |

### B5 — Operator → Step Functions (approval)

The highest-consequence boundary in the system.

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| **S** | Someone other than the operator approves | The task token is written to a KMS-encrypted DynamoDB table and never leaves AWS. Resuming a workflow requires an authenticated `POST /approvals/{id}/decide`; the notification email carries no token and cannot approve anything. | An operator's session token remains usable until expiry if stolen. |
| **T** | Altering the remediation definition | State machine defined in CDK and deployed through a reviewed pipeline | An audit-account administrator can edit the state machine directly in the console; there is no drift detection or alarm. |
| **R** | Denying an approval decision | The deciding principal's Cognito `sub` and a timestamp are written to the approvals record before the workflow resumes; spent tokens are removed and replay returns 409 | Attribution is to a Cognito identity, not to a verified human; a shared account would defeat it. |
| **I** | Approval payload exposes finding detail | SNS topic requires TLS for publishers | Notification content reaches a mailbox outside AWS's trust boundary. |
| **D** | Blocking legitimate remediation | Failed executions surface in the dashboard; the `approvals-decided` alarm fires when an approval expires undecided, and `remediation-runs` when a step errors ([SLOs](slos.md)) | An unapproved execution waits up to 24 hours before anything alerts on it. |
| **E** | Executor exceeds intended scope | Playbook Lambdas hold narrowly scoped permissions; `SAFE_MODE` allows exercising the flow without touching resources | Compromise of a playbook role grants exactly the destructive power the playbook was designed to have. |

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

---

## 3. Residual risks, ranked

1. **Single-account blast radius.** Audit-account administrator access reads
   every finding, edits the state machine, and disables the KMS key.
2. **Partial alerting on the security controls themselves.** Alarms now fire if
   ingestion drops or delays findings, correlation stops, a remediation step
   fails or an approval expires ([SLOs](slos.md)). Nothing yet alarms when the
   state machine, an EventBridge rule or the KMS key is changed or disabled.
3. **Unvalidated ingestion input.** The normalizer trusts whatever reaches it.
4. **No WAF or rate limiting.** Accepted deliberately on cost grounds.

## 4. What this analysis changed

Three items were fixed as a direct result of writing this model. CORS was
restricted from `*` to the dashboard origin; the API container was moved off
root; and the SOAR approval gate was rebuilt so that the Step Functions task
token is held server-side rather than emailed, which removed the system's
highest-ranked residual risk and, in the same change, gave approvals a named
principal. The rest are recorded above rather than silently resolved, because a
threat model whose every threat is neatly mitigated is not describing a real
system.
