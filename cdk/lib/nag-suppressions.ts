/**
 * cdk-nag suppressions.
 *
 * Every entry here is an accepted risk, not a silenced warning. Each records
 * why the control does not apply or why the residual risk is tolerated, so the
 * decision can be reviewed rather than inherited blindly.
 */
import { NagSuppressions } from 'cdk-nag';
import { Stack } from 'aws-cdk-lib/core';
import { IConstruct } from 'constructs';

/**
 * The three findings every stack with a Lambda function raises, accepted once
 * for the same reasons everywhere.
 *
 * Most of what these cover is this project's own code, not machinery the CDK
 * generates — the wildcard that lets the remediation executor act on the
 * account is here, and so is the runtime every handler runs on.
 */
export function suppressLambdaBaseline(stack: Stack): void {
  NagSuppressions.addStackSuppressions(stack, [
    {
      id: 'AwsSolutions-IAM4',
      reason:
        'The flagged roles are Lambda execution roles — this project\'s own ' +
        'functions as well as the bucket-deployment handler CDK generates. The ' +
        'managed policy on each is AWSLambdaBasicExecutionRole, which grants ' +
        'CreateLogGroup, CreateLogStream and PutLogEvents and nothing else. An ' +
        'inline equivalent would grant the same access and would have to be ' +
        'maintained against AWS\'s changes, so it would add work without ' +
        'narrowing privilege.',
    },
    {
      id: 'AwsSolutions-IAM5',
      reason:
        'The wildcards fall into four groups. (1) Actions AWS does not scope to ' +
        'a resource: X-Ray\'s PutTraceSegments, PutTelemetryRecords, ' +
        'GetSamplingRules and GetSamplingTargets; the logs:*LogDelivery and ' +
        'logs:PutResourcePolicy calls Step Functions makes to configure its own ' +
        'logging; ecr:GetAuthorizationToken, which precedes any image pull; ' +
        'states:SendTaskSuccess and SendTaskFailure, which name a task token ' +
        'rather than a state machine; and cloudformation:DescribeStacks, ' +
        'GetTemplate and ListStacks, which the CI roles use to read what a ' +
        'deploy would change. (2) The remediation executor\'s five playbook ' +
        'actions on Resource: * — an accepted risk rather than an inapplicable ' +
        'rule, recorded at the statement itself in remediation-stack.ts. (3) ' +
        'Suffixes below a named resource: a function ARN with :* to cover its ' +
        'versions, a bucket ARN with /* to cover its objects, and index/* on the ' +
        'approvals table, which the API queries by more than one index. (4) ' +
        'Action-level suffixes the CDK grant helpers emit, such as s3:GetObject* ' +
        'and s3:List*, scoped to a single bucket; spelling each one out would ' +
        'drift from the helper without changing effective access.',
    },
    {
      id: 'AwsSolutions-L1',
      reason:
        'The functions run Python 3.12, which is current and supported. The rule ' +
        'flags any runtime that is not the newest the installed CDK library ' +
        'knows of, which is Python 3.14 — a version the handlers have not been ' +
        'tested on. Moving them is a deliberate, tested step rather than one ' +
        'taken to clear a linter. The bucket-deployment handler among them is ' +
        'CDK\'s, and its runtime is the framework\'s to choose, not ours.',
    },
  ], true);
}

/**
 * A queue that is itself the end of the line: an event source mapping's
 * failure destination. Scoped to the one queue rather than its stack, so a
 * queue added later still has to answer the rule.
 */
export function suppressFailureDestination(queue: IConstruct): void {
  NagSuppressions.addResourceSuppressions(queue, [
    {
      id: 'AwsSolutions-SQS3',
      reason:
        'This queue is a dead-letter destination, not a queue that needs one: ' +
        'Lambda reports to it the batches the normalizer could not process ' +
        'after its retries. cdk-nag recognises a queue as a dead-letter queue ' +
        "only when another queue's redrive policy or a function's " +
        'DeadLetterConfig names it, and neither does here — an event source ' +
        'mapping names it instead, which the rule cannot see. Giving it a ' +
        'redrive policy of its own would satisfy the rule by moving the same ' +
        'question one queue further along.',
    },
  ]);
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

/** Suppressions for the model-backed triage function. */
export function suppressModelInvocation(stack: Stack, foundationModel: string): void {
  NagSuppressions.addStackSuppressions(stack, [
    {
      id: 'AwsSolutions-IAM5',
      reason:
        'Cross-Region inference serves each request from whichever Region in the ' +
        "profile's geography has capacity, so the foundation model's ARN needs a " +
        'Region wildcard. The statement names one model and is conditioned on ' +
        'bedrock:InferenceProfileArn, so the model can be reached only through the ' +
        'one inference profile the function is also granted.',
      appliesTo: [`Resource::arn:aws:bedrock:*::foundation-model/${foundationModel}`],
    },
  ], true);
}
