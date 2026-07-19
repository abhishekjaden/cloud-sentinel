import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as iam from 'aws-cdk-lib/aws-iam';
import { ACCOUNTS } from '../config';

const API_DOMAIN = 'api.cloudsentinel-soc.com';
const PARENT_ZONE_ID = 'Z0387487U1PUV4VLJE46';

/**
 * DnsStack — deploys to the Audit account (118821712739). PERSISTENT.
 *
 * Owns the api.cloudsentinel-soc.com hosted zone, its cross-account NS
 * delegation into the Management apex, and the ACM certificate. These are
 * deliberately separated from the (ephemeral) Api stack: the ACM
 * DNS-validation record lives here, so tearing the Api stack down never leaves
 * a stray record in a zone it is trying to delete. The Api stack imports the
 * zone and cert and destroys cleanly every time.
 *
 * This stack is not torn down between sessions (a hosted zone is ~$0.50/mo and
 * keeping the validated cert avoids re-validation on every Api redeploy).
 */
export class DnsStack extends cdk.Stack {
  public readonly apiZone: route53.PublicHostedZone;
  public readonly apiCertificate: acm.Certificate;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    this.apiZone = new route53.PublicHostedZone(this, 'ApiZone', {
      zoneName: API_DOMAIN,
    });

    const delegationRole = iam.Role.fromRoleArn(
      this,
      'DnsDelegationRole',
      `arn:aws:iam::${ACCOUNTS.management}:role/CloudSentinelApiDnsDelegationRole`,
    );

    new route53.CrossAccountZoneDelegationRecord(this, 'ApiZoneDelegation', {
      delegatedZone: this.apiZone,
      parentHostedZoneId: PARENT_ZONE_ID,
      delegationRole,
    });

    this.apiCertificate = new acm.Certificate(this, 'ApiCertificate', {
      domainName: API_DOMAIN,
      validation: acm.CertificateValidation.fromDns(this.apiZone),
    });

    new cdk.CfnOutput(this, 'ApiZoneId', { value: this.apiZone.hostedZoneId });
    new cdk.CfnOutput(this, 'ApiCertArn', { value: this.apiCertificate.certificateArn });
  }
}
