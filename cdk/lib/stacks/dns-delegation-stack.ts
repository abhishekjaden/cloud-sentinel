import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as iam from 'aws-cdk-lib/aws-iam';
import { ACCOUNTS } from '../config';

/**
 * DnsDelegationStack — deploys to the MANAGEMENT account (062345618950).
 *
 * The apex zone cloudsentinel-soc.com lives here (Route 53 created it at
 * domain registration). The API runs in the Audit account, so we delegate the
 * subdomain api.cloudsentinel-soc.com to Audit: this stack publishes a
 * delegation role that the Audit account assumes to write the NS record into
 * the parent zone. Audit then owns its subdomain zone outright — cert, records
 * and ALB all same-account, fully IaC (no cross-account custom resources).
 *
 * This is the standard multi-account DNS pattern: central account owns the
 * apex; workload accounts own delegated subdomains.
 */
export class DnsDelegationStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const parentZone = route53.HostedZone.fromHostedZoneAttributes(this, 'ParentZone', {
      hostedZoneId: 'Z0387487U1PUV4VLJE46',
      zoneName: 'cloudsentinel-soc.com',
    });

    // Role the Audit account assumes to upsert the subdomain NS record.
    new iam.Role(this, 'ApiSubdomainDelegationRole', {
      roleName: 'CloudSentinelApiDnsDelegationRole',
      assumedBy: new iam.AccountPrincipal(ACCOUNTS.audit),
      inlinePolicies: {
        AllowSubdomainDelegation: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              actions: ['route53:ChangeResourceRecordSets', 'route53:ListResourceRecordSets'],
              resources: [parentZone.hostedZoneArn],
            }),
            new iam.PolicyStatement({
              actions: ['route53:GetChange'],
              resources: ['*'],
            }),
          ],
        }),
      },
      description: 'Assumed by the Audit account to delegate api.cloudsentinel-soc.com',
    });

    new cdk.CfnOutput(this, 'ParentZoneId', { value: parentZone.hostedZoneId });
  }
}
