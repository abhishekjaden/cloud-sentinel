import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ecsPatterns from 'aws-cdk-lib/aws-ecs-patterns';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Duration } from 'aws-cdk-lib/core';
import * as path from 'path';

/**
 * ApiStack — deploys to the Audit account (118821712739).
 *
 * The CloudSentinel REST API (FastAPI) on ECS Fargate behind an Application
 * Load Balancer. Serves findings, ML predictions, and remediation status to
 * the SOC dashboard. Reads existing resources same-account:
 *   - DynamoDB cloudsentinel-findings
 *   - S3 cloudsentinel-models-<acct> (binary model)
 *   - Step Functions cloudsentinel-remediation
 *
 * Cost note: ALB + Fargate + NAT are always-on. Run `cdk destroy
 * CloudSentinel-Api` when not actively demoing.
 */
export class ApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Minimal 2-AZ VPC: public subnets for the ALB, private (w/ NAT) for tasks.
    const vpc = new ec2.Vpc(this, 'ApiVpc', {
      maxAzs: 2,
      natGateways: 1,
    });

    const cluster = new ecs.Cluster(this, 'ApiCluster', {
      vpc,
      clusterName: 'cloudsentinel-api',
    });

    // Fargate service + ALB in one construct. Builds the image from backend/.
    const service = new ecsPatterns.ApplicationLoadBalancedFargateService(this, 'ApiService', {
      cluster,
      serviceName: 'cloudsentinel-api',
      cpu: 256,
      memoryLimitMiB: 512,
      desiredCount: 1,
      taskImageOptions: {
        image: ecs.ContainerImage.fromAsset(
          path.join(__dirname, '../../../backend')
        ),
        containerPort: 8000,
        environment: {
          AWS_REGION: this.region,
          FINDINGS_TABLE: 'cloudsentinel-findings',
          ML_BUCKET: `cloudsentinel-models-${this.account}`,
          MODEL_KEY: 'binary_model.json',
          STATE_MACHINE_ARN: `arn:aws:states:${this.region}:${this.account}:stateMachine:cloudsentinel-remediation`,
        },
      },
      publicLoadBalancer: true,
    });

    // Health check hits /health (our FastAPI route).
    service.targetGroup.configureHealthCheck({
      path: '/health',
      healthyHttpCodes: '200',
      interval: Duration.seconds(30),
    });

    // Task role: least-privilege reads for the resources the API queries.
    const taskRole = service.taskDefinition.taskRole;
    taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      actions: [
        'dynamodb:Query', 'dynamodb:Scan', 'dynamodb:GetItem',
      ],
      resources: [
        `arn:aws:dynamodb:${this.region}:${this.account}:table/cloudsentinel-findings`,
        `arn:aws:dynamodb:${this.region}:${this.account}:table/cloudsentinel-findings/index/*`,
      ],
    }));
    taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      actions: ['s3:GetObject'],
      resources: [`arn:aws:s3:::cloudsentinel-models-${this.account}/*`],
    }));
    taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      actions: ['states:ListExecutions'],
      resources: [`arn:aws:states:${this.region}:${this.account}:stateMachine:cloudsentinel-remediation`],
    }));

    new cdk.CfnOutput(this, 'ApiUrl', {
      value: `http://${service.loadBalancer.loadBalancerDnsName}`,
    });
  }
}
