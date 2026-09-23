import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as kinesis from 'aws-cdk-lib/aws-kinesis';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import { Duration } from 'aws-cdk-lib/core';
import { StartingPosition } from 'aws-cdk-lib/aws-lambda';
import { KinesisEventSource, SqsDlq } from 'aws-cdk-lib/aws-lambda-event-sources';
import * as path from 'path';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import {
  suppressCdkManagedResources, suppressFailureDestination, suppressStreamEncryption,
} from '../nag-suppressions';
import {
  FAILED_FINDINGS_QUEUE_NAME, FINDINGS_STREAM_NAME, FUNCTION_NAMES, INGESTION_RULE_NAMES,
} from '../names';

/**
 * IngestionStack — deploys to the Audit account (118821712739).
 *
 * Capture -> buffer -> normalize:
 *  - EventBridge rules match GuardDuty / Security Hub / Inspector findings
 *    and route them to a Kinesis Data Stream (decoupled, buffered).
 *  - A Lambda normalizer consumes the stream and maps every source's native
 *    shape into one common schema, emitting to CloudWatch Logs (interim sink;
 *    DynamoDB).
 */
export class IngestionStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Buffered ingestion stream
    const stream = new kinesis.Stream(this, 'FindingsStream', {
      streamName: FINDINGS_STREAM_NAME,
      // Provisioned, not on-demand. At roughly 950 records a day the on-demand
      // base charge (~$26/month per stream) costs more than a single
      // provisioned shard (~$11/month), which handles 1,000 records a second.
      streamMode: kinesis.StreamMode.PROVISIONED,
      shardCount: 1,
      retentionPeriod: Duration.hours(24),
    });

    // Normalizer Lambda
    const normalizer = new lambda.Function(this, 'Normalizer', {
      // Named so the observability stack's alarms can find it without a
      // cross-stack reference (see names.ts), and so it reads as itself in the
      // X-Ray trace map rather than as a generated identifier.
      functionName: FUNCTION_NAMES.normalizer,
      tracing: lambda.Tracing.ACTIVE,
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../lambda/normalizer')),
      timeout: Duration.seconds(60),
      memorySize: 256,
      environment: { FINDINGS_TABLE: 'cloudsentinel-findings' },
      description: 'Normalizes security findings into a common schema',
    });

    // Where a batch goes once the normalizer has failed on it through every
    // retry. Lambda sends the batch's *metadata* — the shard and the range of
    // sequence numbers — not the findings themselves, so a message is a pointer
    // back into the stream rather than a copy of what was lost. The stream
    // keeps records for 24 hours; the queue keeps the pointers for 14 days, so
    // that a loss is still on the record after the records themselves have
    // aged out and recovery has to come from the source service's own console.
    const failedFindings = new sqs.Queue(this, 'FailedFindings', {
      queueName: FAILED_FINDINGS_QUEUE_NAME,
      // SQS-managed keys rather than a CMK: the messages name sequence numbers
      // and carry no finding content.
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: Duration.days(14),
    });
    suppressFailureDestination(failedFindings);

    // Lambda consumes the Kinesis stream in batches
    normalizer.addEventSource(new KinesisEventSource(stream, {
      startingPosition: StartingPosition.LATEST,
      batchSize: 100,
      maxBatchingWindow: Duration.seconds(10),
      retryAttempts: 2,
      // Without this, the checkpoint advances past every record the handler
      // returned from, whether or not it stored them, and a finding that failed
      // on a throttle or a timeout was simply gone. With it, the handler names
      // the records it could not store and Lambda delivers them again.
      reportBatchItemFailures: true,
      // And when the retries run out, the batch is reported rather than
      // discarded silently. This is the only signal that a finding was lost,
      // so the findings-stored objective is measured from it (docs/slos.md).
      onFailure: new SqsDlq(failedFindings),
    }));

    // Nothing is routed to a function until its log group exists. CDK creates
    // each function's log group after the function; if the function were
    // invoked in between, Lambda would create the group itself and the
    // deployment would then fail on the taken name. That window opens whenever
    // a function is replaced — renaming them for the alarms replaced them all.
    for (const mapping of normalizer.node.children) {
      if (mapping instanceof lambda.EventSourceMapping) mapping.node.addDependency(normalizer.logGroup);
    }

    // Grant the normalizer write access to the findings table (by name,
    // avoids cross-stack coupling; table lives in DataStoresStack).
    const findingsTable = dynamodb.Table.fromTableName(this, 'FindingsTableRef', 'cloudsentinel-findings');
    findingsTable.grantWriteData(normalizer);

    // fromTableName() carries no knowledge of the table's encryption key, so
    // the KMS grant has to be made explicitly or every write fails.
    normalizer.addToRolePolicy(new iam.PolicyStatement({
      sid: 'EncryptFindingsTable',
      actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey', 'kms:DescribeKey'],
      // Scoped to the findings key by alias rather than '*': Security Hub
      // control KMS.2 flags wildcard decrypt permissions, and the ViaService
      // condition alone does not satisfy it.
      resources: [cdk.Fn.importValue('CloudSentinelFindingsKeyArn')],
      conditions: {
        StringEquals: { 'kms:ViaService': `dynamodb.${this.region}.amazonaws.com` },
      },
    }));

    // EventBridge rules -> Kinesis, one per finding source
    const sources = [
      { id: 'GuardDuty', source: 'aws.guardduty', detailType: 'GuardDuty Finding' },
      { id: 'SecurityHub', source: 'aws.securityhub', detailType: 'Security Hub Findings - Imported' },
      { id: 'Inspector', source: 'aws.inspector2', detailType: 'Inspector2 Finding' },
    ] as const;

    for (const s of sources) {
      new events.Rule(this, `${s.id}Rule`, {
        ruleName: INGESTION_RULE_NAMES[s.id],
        description: `Route ${s.id} findings to the ingestion stream`,
        eventPattern: {
          source: [s.source],
          detailType: [s.detailType],
        },
        targets: [new targets.KinesisStream(stream)],
      });
    }

    // Correlation runs on a schedule rather than per record: grouping requires
    // seeing findings together, which a stream handler processing one record at
    // a time cannot do.
    const correlator = new lambda.Function(this, 'Correlator', {
      functionName: FUNCTION_NAMES.correlator,
      tracing: lambda.Tracing.ACTIVE,
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset('lambda/correlator'),
      timeout: cdk.Duration.minutes(5),
      memorySize: 512,
      environment: {
        FINDINGS_TABLE: 'cloudsentinel-findings',
        INCIDENTS_TABLE: 'cloudsentinel-incidents',
        CORRELATION_WINDOW_MINUTES: '30',
        // A year. The findings under correlation are security events, which are
        // sparse — a week's window would have excluded every one of them.
        CORRELATION_LOOKBACK_HOURS: '8760',
      },
    });

    const incidentsTable = dynamodb.Table.fromTableName(
      this, 'IncidentsTableRef', 'cloudsentinel-incidents');
    findingsTable.grantReadData(correlator);
    incidentsTable.grantWriteData(correlator);
    correlator.addToRolePolicy(new iam.PolicyStatement({
      sid: 'UseFindingsKeyForCorrelation',
      actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey', 'kms:DescribeKey'],
      resources: [cdk.Fn.importValue('CloudSentinelFindingsKeyArn')],
      conditions: {
        StringEquals: { 'kms:ViaService': `dynamodb.${this.region}.amazonaws.com` },
      },
    }));

    const schedule = new events.Rule(this, 'CorrelationSchedule', {
      ruleName: 'cloudsentinel-correlation',
      schedule: events.Schedule.rate(cdk.Duration.minutes(15)),
      targets: [new targets.LambdaFunction(correlator)],
    });
    schedule.node.addDependency(correlator.logGroup); // see the normalizer's event source

    new cdk.CfnOutput(this, 'StreamName', { value: stream.streamName });

    suppressCdkManagedResources(this);
    suppressStreamEncryption(this);

  }
}
