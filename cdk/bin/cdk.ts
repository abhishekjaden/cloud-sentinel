#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib/core';
import { Aspects } from 'aws-cdk-lib/core';
import { AwsSolutionsChecks } from 'cdk-nag';
import { ACCOUNTS, env } from '../lib/config';
import { SecurityServicesStack } from '../lib/stacks/security-services-stack';
import { WorkloadNetworkStack } from '../lib/stacks/workload-network-stack';
import { IngestionStack } from '../lib/stacks/ingestion-stack';
import { DataStoresStack } from '../lib/stacks/datastores-stack';
import { MLStack } from '../lib/stacks/ml-stack';
import { RemediationStack } from '../lib/stacks/remediation-stack';
import { ApiStack } from '../lib/stacks/api-stack';
import { DashboardStack } from '../lib/stacks/dashboard-stack';
import { DnsDelegationStack } from '../lib/stacks/dns-delegation-stack';
import { DnsStack } from '../lib/stacks/dns-stack';
import { AuthStack } from '../lib/stacks/auth-stack';
import { CicdStack } from '../lib/stacks/cicd-stack';
import { ObservabilityStack } from '../lib/stacks/observability-stack';
import { TriageStack } from '../lib/stacks/triage-stack';

const app = new cdk.App();

// Policy-scan every synthesized template against the AWS Solutions
// ruleset. Findings surface at synth time, so CI fails on any new
// violation; accepted risks are suppressed individually with a reason.
Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

new SecurityServicesStack(app, 'CloudSentinel-SecurityServices', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: Security Hub cross-region finding aggregation (Audit account)',
});

new WorkloadNetworkStack(app, 'CloudSentinel-WorkloadNetwork', {
  env: env(ACCOUNTS.workload),
  description: 'CloudSentinel: workload VPC with Flow Logs',
});

const dataStores = new DataStoresStack(app, 'CloudSentinel-DataStores', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: DynamoDB for normalized findings (Audit account)',
});

new IngestionStack(app, 'CloudSentinel-Ingestion', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: findings ingestion — EventBridge -> Kinesis -> normalizer (Audit account)',
});

new MLStack(app, 'CloudSentinel-ML', {
  env: env(ACCOUNTS.workload),
  description: 'CloudSentinel: ML data lake for intrusion detection (workload account)',
});

new RemediationStack(app, 'CloudSentinel-Remediation', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: Step Functions remediation playbooks / SOAR layer (Audit account)',
});
const dnsStack = new DnsStack(app, 'CloudSentinel-Dns', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: api subdomain zone + ACM cert (Audit account, persistent)',
});

new ApiStack(app, 'CloudSentinel-Api', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: FastAPI backend on ECS Fargate + ALB (Audit account)',
  apiZone: dnsStack.apiZone,
  apiCertificate: dnsStack.apiCertificate,
});
new DashboardStack(app, 'CloudSentinel-Dashboard', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: React SOC dashboard on S3 + CloudFront (Audit account)',
});
new DnsDelegationStack(app, 'CloudSentinel-DnsDelegation', {
  env: env(ACCOUNTS.management),
  description: 'CloudSentinel: DNS delegation role for api subdomain (Management account)',
});
new AuthStack(app, 'CloudSentinel-Auth', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: Cognito user pool for SOC dashboard + API auth (Audit account)',
});
new CicdStack(app, 'CloudSentinel-Cicd', {
  env: env(ACCOUNTS.management),
  description: 'CloudSentinel: GitHub OIDC provider + CI/deploy roles (Management account)',
});
new ObservabilityStack(app, 'CloudSentinel-Observability', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: service level objectives — alarms, alarm topic and SLO dashboard (Audit account)',
});
const triage = new TriageStack(app, 'CloudSentinel-Triage', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: advisory incident triage with a Bedrock model (Audit account)',
});
// The triage function finds its table by name, so nothing orders the two
// stacks unless this does: its first scheduled run must not precede the table.
triage.addDependency(dataStores);
app.synth();
