import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import { RemovalPolicy } from 'aws-cdk-lib/core';

/**
 * MLStack — deploys to the workload account (743181156000).
 *
 * Data lake for the intrusion-detection ML pipeline. Layout:
 *   raw/        CICIDS2017 source CSVs
 *   processed/  cleaned + feature-engineered parquet
 *   features/   train/val/test splits for SageMaker
 *   models/     model artifacts + evaluation reports
 *
 * SageMaker Studio domain and execution role were bootstrapped via console
 * (one-time environment setup; see ADR 0003). Pipelines that RUN inside the
 * domain are defined as code (ml/ directory) — that is the production-grade
 * artifact, not the domain itself.
 */
export class MLStack extends cdk.Stack {
  public readonly dataLake: s3.Bucket;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    this.dataLake = new s3.Bucket(this, 'DataLake', {
      bucketName: `cloudsentinel-ml-${this.account}`,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: false,
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // Grant the SageMaker Studio execution role read/write to the data lake.
    // Role was created by the console domain bootstrap (ADR 0003); we look it
    // up by name and grant least-privilege access to this bucket only.
    const sagemakerRole = iam.Role.fromRoleName(
      this, 'SageMakerExecRole', 'AmazonSageMaker-ExecutionRole-20260624T010157'
    );
    this.dataLake.grantReadWrite(sagemakerRole);

    new cdk.CfnOutput(this, 'DataLakeBucket', { value: this.dataLake.bucketName });
  }
}
