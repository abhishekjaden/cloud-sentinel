import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as kms from 'aws-cdk-lib/aws-kms';
import { RemovalPolicy } from 'aws-cdk-lib/core';

export class DataStoresStack extends cdk.Stack {
  public readonly findingsTable: dynamodb.Table;
  public readonly findingsKey: kms.Key;
  public readonly modelsBucket: s3.Bucket;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    // Customer-managed key rather than the AWS-owned default: key usage is
    // recorded in CloudTrail, rotation is under our control, and access can be
    // revoked by disabling the key. Callers therefore need kms:Decrypt in
    // addition to their DynamoDB permissions.
    this.findingsKey = new kms.Key(this, 'FindingsKey', {
      alias: 'alias/cloudsentinel-findings',
      description: 'Encrypts the CloudSentinel normalized findings table',
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    this.findingsTable = new dynamodb.Table(this, 'FindingsTable', {
      tableName: 'cloudsentinel-findings',
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.findingsKey,
    });
    new cdk.CfnOutput(this, 'FindingsKeyArn', {
      value: this.findingsKey.keyArn,
      exportName: 'CloudSentinelFindingsKeyArn',
    });

    this.findingsTable.addGlobalSecondaryIndex({
      indexName: 'severity-index',
      partitionKey: { name: 'severity_bucket', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'severity', type: dynamodb.AttributeType.NUMBER },
    });
    // Serving-side model artifacts. Models trained in the workload account are
    // promoted here (audit account) so the API serves them same-account.
    this.modelsBucket = new s3.Bucket(this, 'ModelsBucket', {
      bucketName: `cloudsentinel-models-${this.account}`,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    new cdk.CfnOutput(this, 'ModelsBucketName', { value: this.modelsBucket.bucketName });

    new cdk.CfnOutput(this, 'FindingsTableName', {
      value: this.findingsTable.tableName,
    });
  }
}
