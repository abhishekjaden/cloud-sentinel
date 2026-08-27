/**
 * cdk-nag suppressions.
 *
 * Every entry here is an accepted risk, not a silenced warning. Each records
 * why the control does not apply or why the residual risk is tolerated, so the
 * decision can be reviewed rather than inherited blindly.
 */
import { NagSuppressions } from 'cdk-nag';
import { Stack } from 'aws-cdk-lib/core';

/** Suppressions that apply to constructs the CDK itself generates. */
export function suppressCdkManagedResources(stack: Stack): void {
  NagSuppressions.addStackSuppressions(stack, [
    {
      id: 'AwsSolutions-IAM4',
      reason:
        'AWSLambdaBasicExecutionRole is an AWS-managed policy granting only ' +
        'CloudWatch Logs write access. Hand-rolling an equivalent inline policy ' +
        'would add maintenance burden without reducing privilege.',
    },
    {
      id: 'AwsSolutions-IAM5',
      reason:
        'Wildcards here originate from CDK-generated roles (asset deployment, ' +
        'custom resource providers) or are constrained by condition keys — the ' +
        'KMS grants are scoped by kms:ViaService to DynamoDB only, so the role ' +
        'cannot use the key against any other service.',
    },
    {
      id: 'AwsSolutions-L1',
      reason:
        'The flagged functions are CDK-provided custom resource handlers whose ' +
        'runtime is pinned by the framework, not by application code.',
    },
  ], true);
}

/** Suppressions specific to the public API surface. */
export function suppressPublicIngress(stack: Stack): void {
  NagSuppressions.addStackSuppressions(stack, [
    {
      id: 'AwsSolutions-EC23',
      reason:
        'The load balancer security group is intentionally reachable from the ' +
        'internet: this is a public HTTPS API. Authorisation is enforced at the ' +
        'application layer, where every data route requires a valid Cognito JWT.',
    },
    {
      id: 'AwsSolutions-ECS2',
      reason:
        'The container environment carries non-secret configuration only — the ' +
        'DynamoDB table name, Cognito pool and client identifiers, and an auth ' +
        'toggle. All AWS access is obtained through the task role; no ' +
        'credentials or secrets are passed as environment variables.',
    },
  ], true);
}

/** Suppressions for the content delivery layer. */
export function suppressCloudFrontOptional(stack: Stack): void {
  NagSuppressions.addStackSuppressions(stack, [
    {
      id: 'AwsSolutions-CFR1',
      reason:
        'Geographic restriction is not applicable: the dashboard is a ' +
        'demonstration surface with no jurisdictional access requirement.',
    },
    {
      id: 'AwsSolutions-CFR2',
      reason:
        'AWS WAF is a deliberate cost trade-off. The distribution serves a ' +
        'static single-page application with no server-side processing, and the ' +
        'API it calls is separately authenticated. Recorded as future work.',
    },
    {
      id: 'AwsSolutions-CFR3',
      reason:
        'CloudFront access logging is omitted in favour of ALB access logs, ' +
        'which capture the requests that reach application data.',
    },
  ], true);
}

/** Suppressions for the identity layer. */
export function suppressCognitoTier(stack: Stack): void {
  NagSuppressions.addStackSuppressions(stack, [
    {
      id: 'AwsSolutions-COG8',
      reason:
        'The Cognito Plus feature plan is billed per monthly active user and ' +
        'provides compromised-credential detection and adaptive authentication. ' +
        'With a single operator account and MFA enforced, the marginal risk ' +
        'reduction does not justify the recurring cost. Recorded as future work ' +
        'for any multi-user deployment.',
    },
  ], true);
}

/** Suppressions for the streaming ingestion path. */
export function suppressStreamEncryption(stack: Stack): void {
  NagSuppressions.addStackSuppressions(stack, [
    {
      id: 'AwsSolutions-KDS3',
      reason:
        'The stream is encrypted with the AWS-managed key. Findings are held in ' +
        'the stream only in transit for seconds before being written to ' +
        'DynamoDB, which does use a customer-managed key; a second CMK for a ' +
        'transient buffer was not judged worth the additional monthly cost.',
    },
  ], true);
}

/** Suppressions for the machine-learning data plane. */
export function suppressMlDataLake(stack: Stack): void {
  NagSuppressions.addStackSuppressions(stack, [
    {
      id: 'AwsSolutions-IAM5',
      reason:
        'The wildcards are action-level suffixes emitted by the CDK grant API ' +
        '(s3:GetObject*, s3:List* and similar) and are scoped to the data lake ' +
        'bucket alone. Enumerating each concrete action would drift from the ' +
        'grant helper without narrowing effective access.',
    },
  ], true);
}

/** CloudFront TLS floor is constrained by the default certificate. */
export function suppressCloudFrontTls(stack: Stack): void {
  NagSuppressions.addStackSuppressions(stack, [
    {
      id: 'AwsSolutions-CFR4',
      reason:
        'The distribution is served on the default *.cloudfront.net certificate, ' +
        'for which AWS fixes the minimum viewer protocol at TLSv1 and ignores a ' +
        'stricter security policy. Attaching a custom domain with an ACM ' +
        'certificate would allow TLSv1.2_2021 to take effect; recorded as future ' +
        'work alongside moving the dashboard onto the project domain.',
    },
  ], true);
}

/** Suppressions for the cross-account DNS delegation role. */
export function suppressDnsDelegation(stack: Stack): void {
  NagSuppressions.addStackSuppressions(stack, [
    {
      id: 'AwsSolutions-IAM5',
      reason:
        'route53:ListHostedZonesByName does not support resource-level ' +
        'permissions, so AWS requires Resource: * for it. The role is otherwise ' +
        'scoped to a single hosted zone and is assumable only by the audit ' +
        'account, so the wildcard confers no ability to modify DNS elsewhere.',
    },
  ], true);
}
