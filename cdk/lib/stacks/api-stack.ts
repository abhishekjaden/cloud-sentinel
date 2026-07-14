import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ecsPatterns from 'aws-cdk-lib/aws-ecs-patterns';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Duration } from 'aws-cdk-lib/core';
import * as path from 'path';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import { ACCOUNTS } from '../config';

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
const API_DOMAIN = 'api.cloudsentinel-soc.com';
const PARENT_ZONE_ID = 'Z0387487U1PUV4VLJE46';
const COGNITO_USER_POOL_ID = 'us-east-1_jHroJVSo9';
const COGNITO_CLIENT_ID = '3i0gv6cm27of4hancq8fjs551t';

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
    // ---- DNS + TLS ----
    // Audit owns the delegated subdomain zone outright, so cert, DNS records
    // and ALB all live same-account. The NS delegation is written into the
    // parent zone (Management account) via an assumed delegation role.
    const apiZone = new route53.PublicHostedZone(this, 'ApiZone', {
      zoneName: API_DOMAIN,
    });

    const delegationRole = iam.Role.fromRoleArn(
      this,
      'DnsDelegationRole',
      `arn:aws:iam::${ACCOUNTS.management}:role/CloudSentinelApiDnsDelegationRole`,
    );

    new route53.CrossAccountZoneDelegationRecord(this, 'ApiZoneDelegation', {
      delegatedZone: apiZone,
      parentHostedZoneId: PARENT_ZONE_ID,
      delegationRole,
    });

    const cert = new acm.Certificate(this, 'ApiCertificate', {
      domainName: API_DOMAIN,
      validation: acm.CertificateValidation.fromDns(apiZone),
    });

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
          // Cognito: the API verifies every data request's JWT against the pool.
          COGNITO_USER_POOL_ID: COGNITO_USER_POOL_ID,
          COGNITO_CLIENT_ID: COGNITO_CLIENT_ID,
          AUTH_ENABLED: 'true',
        },
      },
      publicLoadBalancer: true,
      // TLS: HTTPS listener on 443 with the ACM cert, alias record in our zone,
      // and an HTTP:80 -> HTTPS:443 redirect.
      certificate: cert,
      domainName: API_DOMAIN,
      domainZone: apiZone,
      protocol: elbv2.ApplicationProtocol.HTTPS,
      redirectHTTP: true,
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

    new cdk.CfnOutput(this, 'ApiUrl', { value: `https://${API_DOMAIN}` });
    new cdk.CfnOutput(this, 'AlbDnsName', { value: service.loadBalancer.loadBalancerDnsName });
  }
}
