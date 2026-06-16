import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';

/**
 * SecurityFoundationStack
 * Org-wide security service enablement (GuardDuty, Security Hub, Macie,
 * Inspector, Config) with delegated administration to the Audit account.
 * Resources added Day 2.
 */
export class SecurityFoundationStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    // Day 2: security services + delegated admin
  }
}
