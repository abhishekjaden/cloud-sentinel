import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as kinesis from 'aws-cdk-lib/aws-kinesis';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import { Duration } from 'aws-cdk-lib/core';
import { StartingPosition } from 'aws-cdk-lib/aws-lambda';
import { KinesisEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';
import * as path from 'path';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import { suppressCdkManagedResources, suppressStreamEncryption } from '../nag-suppressions';

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
      streamName: 'cloudsentinel-findings',
      // Provisioned, not on-demand. At roughly 950 records a day the on-demand
      // base charge (~$26/month per stream) costs more than a single
      // provisioned shard (~$11/month), which handles 1,000 records a second.
      streamMode: kinesis.StreamMode.PROVISIONED,
      shardCount: 1,
      retentionPeriod: Duration.hours(24),
    });

    // Normalizer Lambda
    const normalizer = new lambda.Function(this, 'Normalizer', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../lambda/normalizer')),
      timeout: Duration.seconds(60),
      memorySize: 256,
      environment: { FINDINGS_TABLE: 'cloudsentinel-findings' },
      description: 'Normalizes security findings into a common schema',
    });

    // Lambda consumes the Kinesis stream in batches
    normalizer.addEventSource(new KinesisEventSource(stream, {
      startingPosition: StartingPosition.LATEST,
      batchSize: 100,
      maxBatchingWindow: Duration.seconds(10),
      retryAttempts: 2,
    }));

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
    ];

    for (const s of sources) {
      new events.Rule(this, `${s.id}Rule`, {
        ruleName: `cloudsentinel-${s.id.toLowerCase()}-findings`,
        description: `Route ${s.id} findings to the ingestion stream`,
        eventPattern: {
          source: [s.source],
          detailType: [s.detailType],
        },
        targets: [new targets.KinesisStream(stream)],
      });
    }

    new cdk.CfnOutput(this, 'StreamName', { value: stream.streamName });

    suppressCdkManagedResources(this);
    suppressStreamEncryption(this);

  }
}
