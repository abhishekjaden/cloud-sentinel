#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib/core';
import { ACCOUNTS, env } from '../lib/config';
import { SecurityServicesStack } from '../lib/stacks/security-services-stack';
import { WorkloadNetworkStack } from '../lib/stacks/workload-network-stack';

const app = new cdk.App();

// Security services config — Audit account (delegated admin)
new SecurityServicesStack(app, 'CloudSentinel-SecurityServices', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: Security Hub cross-region finding aggregation (Audit account)',
});

// Workload network — VPC, subnets, NAT, Flow Logs (workload account)
new WorkloadNetworkStack(app, 'CloudSentinel-WorkloadNetwork', {
  env: env(ACCOUNTS.workload),
  description: 'CloudSentinel: workload VPC with Flow Logs',
});

app.synth();
