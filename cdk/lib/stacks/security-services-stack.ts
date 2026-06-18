import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as securityhub from 'aws-cdk-lib/aws-securityhub';

/**
 * SecurityServicesStack — deploys to the Audit account (delegated admin).
 *
 * Security Hub finding aggregator: funnels findings from all linked
 * regions into us-east-1 so the Audit account is a single pane of glass.
 *
 * Note: FSBP standard is auto-enabled by Security Hub on activation,
 * so it is intentionally NOT declared here (declaring it conflicts with
 * the default subscription). Org-level member auto-enable toggles are
 * handled by scripts/enable-org-security.sh. See docs/adr/0002.
 */
export class SecurityServicesStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    new securityhub.CfnFindingAggregator(this, 'FindingAggregator', {
      regionLinkingMode: 'ALL_REGIONS',
    });
  }
}
