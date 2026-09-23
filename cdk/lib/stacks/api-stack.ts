import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ecsPatterns from 'aws-cdk-lib/aws-ecs-patterns';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Duration } from 'aws-cdk-lib/core';
import * as path from 'path';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as sns from 'aws-cdk-lib/aws-sns';
import { ACCOUNTS } from '../config';
import { ALARM_TOPIC_NAME, TRIAGE_TABLE_NAME } from '../names';
import { suppressCdkManagedResources, suppressPublicIngress } from '../nag-suppressions';

/**
 * ApiStack — deploys to the Audit account (118821712739).
 *
 * The CloudSentinel REST API (FastAPI) on ECS Fargate behind an Application
 * Load Balancer. Serves findings, ML predictions, and remediation status to
 * the SOC dashboard. Reads existing resources same-account:
 *   - DynamoDB cloudsentinel-findings
 *   - DynamoDB cloudsentinel-incidents (read-only)
 *   - S3 cloudsentinel-models-<acct> (binary model)
 *   - Step Functions cloudsentinel-remediation
 *
 * Cost note: ALB + Fargate + NAT are always-on. Run `cdk destroy
 * CloudSentinel-Api` when not actively demoing.
 */
const API_DOMAIN = 'api.cloudsentinel-soc.com';
const COGNITO_USER_POOL_ID = 'us-east-1_jHroJVSo9';
const COGNITO_CLIENT_ID = '3i0gv6cm27of4hancq8fjs551t';

interface ApiStackProps extends cdk.StackProps {
  apiZone: route53.IPublicHostedZone;
  apiCertificate: acm.ICertificate;
}

export class ApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);
    const { apiZone, apiCertificate } = props;

    // Minimal 2-AZ VPC: public subnets for the ALB, private (w/ NAT) for tasks.
    const vpc = new ec2.Vpc(this, 'ApiVpc', {
      maxAzs: 2,
      natGateways: 1,
      // Network-level forensics: without flow logs there is no record of what
      // talked to what inside the serving VPC.
      flowLogs: {
        ApiVpcFlowLog: {
          trafficType: ec2.FlowLogTrafficType.ALL,
          destination: ec2.FlowLogDestination.toCloudWatchLogs(),
        },
      },
    });

    const cluster = new ecs.Cluster(this, 'ApiCluster', {
      vpc,
      clusterName: 'cloudsentinel-api',
      containerInsightsV2: ecs.ContainerInsights.ENABLED,
    });

    // Access logs answer "who called the API, when, and with what result" —
    // the ALB is the only path to application data.
    // S3 access logs for the ALB log bucket land here. A bucket must not log
    // into itself: each write would generate a further write.
    const logArchive = new s3.Bucket(this, 'LogArchive', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      lifecycleRules: [{ expiration: cdk.Duration.days(90) }],
    });

    const albLogs = new s3.Bucket(this, 'AlbAccessLogs', {
      serverAccessLogsBucket: logArchive,
      serverAccessLogsPrefix: 'alb-log-bucket/',
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      lifecycleRules: [{ expiration: cdk.Duration.days(90) }],
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
          // Cognito: the API verifies every data request's JWT against the pool.
          COGNITO_USER_POOL_ID: COGNITO_USER_POOL_ID,
          COGNITO_CLIENT_ID: COGNITO_CLIENT_ID,
          AUTH_ENABLED: 'true',
          // Browser origins allowed to call this API. Restricting this stops a
          // malicious site from issuing credentialed requests on behalf of a
          // logged-in operator.
          CORS_ORIGINS: 'https://d2tb90osqfrb0m.cloudfront.net',
          APPROVALS_TABLE: 'cloudsentinel-approvals',
          INCIDENTS_TABLE: 'cloudsentinel-incidents',
          TRIAGE_TABLE: TRIAGE_TABLE_NAME,
        },
      },
      publicLoadBalancer: true,
      // Zero-downtime rolling deployment: never drop below the running count,
      // allow a second task to start and pass health checks before the old one
      // is stopped. The CDK default of 50% would briefly take the API offline.
      // Fail fast and roll back if replacement tasks cannot start; without this
      // a bad deployment can hang for up to three hours before ECS gives up.
      circuitBreaker: { rollback: true },
      minHealthyPercent: 100,
      maxHealthyPercent: 200,
      // TLS: HTTPS listener on 443 with the ACM cert, alias record in our zone,
      // and an HTTP:80 -> HTTPS:443 redirect.
      certificate: apiCertificate,
      domainName: API_DOMAIN,
      domainZone: apiZone,
      protocol: elbv2.ApplicationProtocol.HTTPS,
      redirectHTTP: true,
    });

    service.loadBalancer.logAccessLogs(albLogs);

    // Health check hits /health (our FastAPI route).
    service.targetGroup.configureHealthCheck({
      path: '/health',
      healthyHttpCodes: '200',
      interval: Duration.seconds(30),
    });

    // Task role: least-privilege reads for the resources the API queries.
    const taskRole = service.taskDefinition.taskRole;
    // The findings table is encrypted with a customer-managed key, so reading
    // it requires kms:Decrypt in addition to the DynamoDB actions.
    // Resuming a paused remediation is the whole point of the approvals route,
    // so the task role may send task outcomes — but nothing else on the state
    // machine.
    taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'ResumeRemediationWorkflows',
      actions: ['states:SendTaskSuccess', 'states:SendTaskFailure'],
      resources: ['*'],
    }));

    taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'ReadWriteApprovals',
      actions: ['dynamodb:GetItem', 'dynamodb:Query', 'dynamodb:UpdateItem'],
      resources: [
        `arn:aws:dynamodb:${this.region}:${this.account}:table/cloudsentinel-approvals`,
        `arn:aws:dynamodb:${this.region}:${this.account}:table/cloudsentinel-approvals/index/*`,
      ],
    }));

    // Correlated incidents are read-only to the API: the correlator writes them,
    // the dashboard displays them. The one index the API queries is named
    // rather than matched by index/* — there is no other index it needs.
    taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'ReadIncidents',
      actions: ['dynamodb:Query', 'dynamodb:Scan'],
      resources: [
        `arn:aws:dynamodb:${this.region}:${this.account}:table/cloudsentinel-incidents`,
        `arn:aws:dynamodb:${this.region}:${this.account}:table/cloudsentinel-incidents/index/status-index`,
      ],
    }));

    // Triage notes are shown beside each incident. The API reads them and
    // nothing else: the triage function is their only writer.
    taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'ReadTriageNotes',
      actions: ['dynamodb:BatchGetItem'],
      resources: [`arn:aws:dynamodb:${this.region}:${this.account}:table/${TRIAGE_TABLE_NAME}`],
    }));

    // The incidents and triage tables share this key, so this grant also
    // covers reading them.
    taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'DecryptFindingsTable',
      actions: ['kms:Decrypt', 'kms:DescribeKey'],
      resources: [cdk.Fn.importValue('CloudSentinelFindingsKeyArn')],
      conditions: {
        StringEquals: { 'kms:ViaService': `dynamodb.${this.region}.amazonaws.com` },
      },
    }));

    // Findings are read through two indexes and by key, and never scanned, so
    // the role holds neither dynamodb:Scan nor index/*: the two indexes the
    // routes query are named, and an index added later has to be granted
    // deliberately rather than inherited.
    taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'ReadFindings',
      actions: ['dynamodb:Query', 'dynamodb:GetItem'],
      resources: [
        `arn:aws:dynamodb:${this.region}:${this.account}:table/cloudsentinel-findings`,
        `arn:aws:dynamodb:${this.region}:${this.account}:table/cloudsentinel-findings/index/severity-index`,
        `arn:aws:dynamodb:${this.region}:${this.account}:table/cloudsentinel-findings/index/source-time-index`,
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

    // ---- Service level objectives (docs/slos.md) ----
    // These live here rather than in ObservabilityStack because the load
    // balancer they measure exists only while this stack is deployed; they are
    // created and destroyed with it. They notify the persistent alarm topic,
    // found by name like the tables above.
    const alarmTopic = sns.Topic.fromTopicArn(this, 'AlarmTopic',
      `arn:aws:sns:${this.region}:${this.account}:${ALARM_TOPIC_NAME}`);
    const notify = new cwActions.SnsAction(alarmTopic);
    const period = Duration.minutes(5);
    const alb = service.loadBalancer;
    const requests = alb.metrics.requestCount({ period, statistic: 'Sum', label: 'requests' });

    // Server errors from the application (target 5xx) and from the load
    // balancer itself (ELB 5xx: no healthy task, or a task that did not answer).
    // A window with fewer than ten requests counts as healthy: with the
    // dashboard as the only client, one error in a quiet window would
    // otherwise read as an outage.
    const failedShare = new cloudwatch.MathExpression({
      expression: 'IF(requests >= 10, 100 * (app + lb) / requests, 0)',
      usingMetrics: {
        requests,
        app: alb.metrics.httpCodeTarget(elbv2.HttpCodeTarget.TARGET_5XX_COUNT, { period, statistic: 'Sum' }),
        lb: alb.metrics.httpCodeElb(elbv2.HttpCodeElb.ELB_5XX_COUNT, { period, statistic: 'Sum' }),
      },
      label: 'failed requests (%)',
      period,
    });
    const p95 = alb.metrics.targetResponseTime({ period, statistic: 'p95', label: 'p95' });
    const p50 = alb.metrics.targetResponseTime({ period, statistic: 'p50', label: 'p50' });

    const apiAlarms = [
      new cloudwatch.Alarm(this, 'SloApiAvailable', {
        alarmName: 'cloudsentinel-slo-api-available',
        alarmDescription:
          'More than 5% of API requests have failed with a server error for 15 minutes. If the ' +
          'load balancer is returning the errors, no healthy task is serving: check the ' +
          'cloudsentinel-api service\'s events and the task logs.',
        metric: failedShare,
        threshold: 5,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluationPeriods: 3,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, 'SloApiLatency', {
        alarmName: 'cloudsentinel-slo-api-latency',
        alarmDescription:
          'The slowest 5% of API requests have taken over 2 seconds for 15 minutes. Every ' +
          'route now reads an index or a key, so the work per request no longer grows with ' +
          'the table; check the task logs and the ALB target metrics.',
        metric: p95,
        threshold: 2,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluationPeriods: 3,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
    ];
    for (const alarm of apiAlarms) {
      alarm.addAlarmAction(notify);
      alarm.addOkAction(notify);
    }

    new cloudwatch.Dashboard(this, 'ApiDashboard', {
      dashboardName: 'CloudSentinel-API',
      defaultInterval: Duration.hours(3),
      widgets: [
        [
          new cloudwatch.TextWidget({
            width: 8, height: 6,
            markdown: [
              '# CloudSentinel API',
              'Objectives: 99.5% of requests succeed, and 95% complete within 2 seconds.',
              'This dashboard is created and destroyed with the API stack; the pipeline\'s',
              'objectives are on CloudSentinel-SLOs.',
            ].join('\n'),
          }),
          new cloudwatch.AlarmStatusWidget({ title: 'Objectives', width: 16, height: 6, alarms: apiAlarms }),
        ],
        [
          new cloudwatch.GraphWidget({
            title: 'Failed requests, % (alarm above 5)', width: 12,
            left: [failedShare],
            leftAnnotations: [{ value: 5, label: 'alarm', color: '#d62728' }],
            leftYAxis: { min: 0, showUnits: false },
          }),
          new cloudwatch.GraphWidget({
            title: 'Response time, seconds (alarm: p95 above 2)', width: 12,
            left: [p50, p95],
            leftAnnotations: [{ value: 2, label: 'alarm', color: '#d62728' }],
            leftYAxis: { min: 0, showUnits: false },
          }),
        ],
        [
          new cloudwatch.GraphWidget({
            title: 'Requests', width: 12, left: [requests], leftYAxis: { min: 0, showUnits: false },
          }),
          new cloudwatch.GraphWidget({
            title: 'Healthy tasks', width: 12,
            left: [service.targetGroup.metrics.healthyHostCount({ period, statistic: 'Minimum', label: 'healthy' })],
            leftYAxis: { min: 0, showUnits: false },
          }),
        ],
      ],
    });

    new cdk.CfnOutput(this, 'ApiUrl', { value: `https://${API_DOMAIN}` });

    suppressCdkManagedResources(this);
    suppressPublicIngress(this);
    new cdk.CfnOutput(this, 'AlbDnsName', { value: service.loadBalancer.loadBalancerDnsName });
  }
}
