import * as cdk from 'aws-cdk-lib/core';
import { Duration } from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as path from 'path';
import { suppressCdkManagedResources, suppressModelInvocation } from '../nag-suppressions';
import { FUNCTION_NAMES, TRIAGE_TABLE_NAME } from '../names';

/**
 * The model the triage function calls, through a US cross-Region inference
 * profile: requests are served from whichever US Region has capacity, and do
 * not leave the United States.
 */
export const TRIAGE_MODEL = {
  inferenceProfile: 'us.anthropic.claude-haiku-4-5-20251001-v1:0',
  foundationModel: 'anthropic.claude-haiku-4-5-20251001-v1:0',
};

/**
 * TriageStack — deploys to the Audit account (118821712739).
 *
 * Advisory triage of correlated incidents by a language model on Amazon
 * Bedrock (docs/adr/0005-advisory-llm-triage.md). Kept in its own stack so the
 * one component whose output comes from a model is separable: it can be
 * destroyed without touching detection, correlation or response.
 *
 * The function's permissions are the containment. It can read incidents and
 * findings, invoke one model through one inference profile, and write its own
 * table. It cannot write an incident or a finding, and holds nothing that
 * could start, approve or stop a remediation, so no answer the model gives —
 * however it was steered — can become an action.
 */
export class TriageStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const table = (name: string) => `arn:aws:dynamodb:${this.region}:${this.account}:table/${name}`;

    const triage = new lambda.Function(this, 'Triage', {
      functionName: FUNCTION_NAMES.triage,
      tracing: lambda.Tracing.ACTIVE,
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../lambda/triage')),
      // At most MAX_PER_RUN model calls a run, each under a minute.
      timeout: Duration.minutes(3),
      memorySize: 256,
      environment: {
        INCIDENTS_TABLE: 'cloudsentinel-incidents',
        FINDINGS_TABLE: 'cloudsentinel-findings',
        TRIAGE_TABLE: TRIAGE_TABLE_NAME,
        TRIAGE_MODEL_ID: TRIAGE_MODEL.inferenceProfile,
        MAX_PER_RUN: '5',
      },
      description: 'Writes advisory triage notes for correlated incidents with a Bedrock model',
    });

    // Written out action by action rather than through grantReadData, which
    // would add batch reads, stream reads and every index on each table.
    triage.addToRolePolicy(new iam.PolicyStatement({
      sid: 'ReadIncidents',
      actions: ['dynamodb:Scan'],
      resources: [table('cloudsentinel-incidents')],
    }));
    triage.addToRolePolicy(new iam.PolicyStatement({
      sid: 'ReadIncidentFindings',
      actions: ['dynamodb:Query'],
      resources: [table('cloudsentinel-findings')],
    }));
    triage.addToRolePolicy(new iam.PolicyStatement({
      sid: 'KeepTriageNotes',
      actions: ['dynamodb:Scan', 'dynamodb:PutItem'],
      resources: [table(TRIAGE_TABLE_NAME)],
    }));
    // All three tables share the findings key.
    triage.addToRolePolicy(new iam.PolicyStatement({
      sid: 'UseFindingsKeyThroughDynamoDB',
      actions: ['kms:Decrypt', 'kms:Encrypt', 'kms:GenerateDataKey', 'kms:DescribeKey'],
      resources: [cdk.Fn.importValue('CloudSentinelFindingsKeyArn')],
      conditions: {
        StringEquals: { 'kms:ViaService': `dynamodb.${this.region}.amazonaws.com` },
      },
    }));

    // One model, reachable only through its inference profile. The profile
    // routes each request to a US Region with capacity, so the foundation
    // model's ARN carries a Region wildcard; the condition keeps that wildcard
    // from reaching the model any other way.
    const profileArn =
      `arn:aws:bedrock:${this.region}:${this.account}:inference-profile/${TRIAGE_MODEL.inferenceProfile}`;
    triage.addToRolePolicy(new iam.PolicyStatement({
      sid: 'InvokeTriageModelProfile',
      actions: ['bedrock:InvokeModel'],
      resources: [profileArn],
    }));
    triage.addToRolePolicy(new iam.PolicyStatement({
      sid: 'InvokeTriageModelThroughProfile',
      actions: ['bedrock:InvokeModel'],
      resources: [`arn:aws:bedrock:*::foundation-model/${TRIAGE_MODEL.foundationModel}`],
      conditions: { StringEquals: { 'bedrock:InferenceProfileArn': profileArn } },
    }));

    // Offset from the correlator's schedule is not needed: a note written
    // before the correlator's next run is only as stale as the incident it
    // describes, and is rewritten once the incident changes.
    const schedule = new events.Rule(this, 'TriageSchedule', {
      ruleName: 'cloudsentinel-triage',
      schedule: events.Schedule.rate(Duration.minutes(15)),
      targets: [new targets.LambdaFunction(triage)],
    });
    // Nothing is routed to a function until its log group exists (see the
    // ingestion stack).
    schedule.node.addDependency(triage.logGroup);

    // The specific suppression first: cdk-nag reports the first that applies,
    // and the Bedrock wildcard deserves its own reason, not the generic one.
    suppressModelInvocation(this, TRIAGE_MODEL.foundationModel);
    suppressCdkManagedResources(this);
  }
}
