#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib/core';
import { ACCOUNTS, env } from '../lib/config';

const app = new cdk.App();

// Stacks are added from Day 2 (security services) onward.
// Each stack targets a specific account via the env() helper, e.g.:
//   new SecurityFoundationStack(app, 'SecurityFoundation', { env: env(ACCOUNTS.audit) });

app.synth();
