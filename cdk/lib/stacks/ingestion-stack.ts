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
  }
}
