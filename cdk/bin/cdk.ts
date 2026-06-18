#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib/core';
import { ACCOUNTS, env } from '../lib/config';
import { SecurityServicesStack } from '../lib/stacks/security-services-stack';

const app = new cdk.App();

new SecurityServicesStack(app, 'CloudSentinel-SecurityServices', {
  env: env(ACCOUNTS.audit),
  description: 'CloudSentinel: Security Hub cross-region finding aggregation (Audit account)',
});

app.synth();
