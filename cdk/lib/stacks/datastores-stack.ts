import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as opensearch from 'aws-cdk-lib/aws-opensearchservice';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { RemovalPolicy } from 'aws-cdk-lib/core';

export class DataStoresStack extends cdk.Stack {
  public readonly findingsTable: dynamodb.Table;
  public readonly searchDomain: opensearch.Domain;
  public readonly modelsBucket: s3.Bucket;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    this.findingsTable = new dynamodb.Table(this, 'FindingsTable', {
      tableName: 'cloudsentinel-findings',
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });
    this.findingsTable.addGlobalSecondaryIndex({
      indexName: 'severity-index',
      partitionKey: { name: 'severity_bucket', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'severity', type: dynamodb.AttributeType.NUMBER },
    });
    this.searchDomain = new opensearch.Domain(this, 'SearchDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_2_11,
      domainName: 'cloudsentinel-findings',
      capacity: {
        dataNodes: 1,
        dataNodeInstanceType: 't3.small.search',
        multiAzWithStandbyEnabled: false,
      },
      ebs: {
        volumeSize: 10,
        volumeType: ec2.EbsDeviceVolumeType.GP3,
      },
      zoneAwareness: { enabled: false },
      encryptionAtRest: { enabled: true },
      nodeToNodeEncryption: true,
      enforceHttps: true,
      removalPolicy: RemovalPolicy.DESTROY,
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
    new cdk.CfnOutput(this, 'SearchDomainEndpoint', {
      value: this.searchDomain.domainEndpoint,
    });
  }
}
