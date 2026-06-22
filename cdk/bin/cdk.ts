#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib/core';
import { ACCOUNTS, env } from '../lib/config';
import { SecurityServicesStack } from '../lib/stacks/security-services-stack';
import { WorkloadNetworkStack } from '../lib/stacks/workload-network-stack';
import { IngestionStack } from '../lib/stacks/ingestion-stack';
import { DataStoresStack } from '../lib/stacks/datastores-stack';

const app = new cdk.App();

new SecurityServicesStack(app, 'CloudSentinel-SecurityServices', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: Security Hub cross-region finding aggregation (Audit account)',
});

new WorkloadNetworkStack(app, 'CloudSentinel-WorkloadNetwork', {
  env: env(ACCOUNTS.workload),
  description: 'CloudSentinel: workload VPC with Flow Logs',
});

new DataStoresStack(app, 'CloudSentinel-DataStores', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: DynamoDB + OpenSearch for normalized findings (Audit account)',
});

new IngestionStack(app, 'CloudSentinel-Ingestion', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: findings ingestion — EventBridge -> Kinesis -> normalizer (Audit account)',
});

app.synth();
