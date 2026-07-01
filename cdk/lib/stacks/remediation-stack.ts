import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Duration } from 'aws-cdk-lib/core';
import * as path from 'path';

/**
 * RemediationStack — deploys to the Audit account (118821712739).
 *
 * SOAR layer: high-severity findings trigger a Step Functions state machine
 * that routes to one of four remediation playbooks:
 *   1. Compromised EC2   -> isolate + snapshot (approval-gated)
 *   2. Exposed IAM key   -> disable access key (approval-gated)
 *   3. Public S3 bucket  -> block public access (approval-gated)
 *   4. Generic high-sev  -> enrich + notify (non-destructive)
 *
 * Design: human-in-the-loop approval (waitForTaskToken + SNS) on destructive
 * actions; SAFE_MODE (default ON) makes executor Lambdas dry-run so the whole
 * workflow is testable without touching real resources. Toggle with
 * `cdk deploy -c safeMode=false`.
 */
export class RemediationStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const safeMode = this.node.tryGetContext('safeMode') !== 'false';

    const notifyTopic = new sns.Topic(this, 'RemediationTopic', {
      topicName: 'cloudsentinel-remediation-approvals',
      displayName: 'CloudSentinel Remediation Approvals & Notifications',
    });

    const executor = new lambda.Function(this, 'RemediationExecutor', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../lambda/remediation')),
      timeout: Duration.seconds(60),
      memorySize: 256,
      environment: { SAFE_MODE: String(safeMode) },
      description: 'CloudSentinel remediation executor (isolate/snapshot/disable-key/block-s3)',
    });

    executor.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'ec2:ModifyInstanceAttribute',
        'ec2:CreateSnapshot',
        'ec2:DescribeInstances',
        'iam:UpdateAccessKey',
        's3:PutBucketPublicAccessBlock',
      ],
      resources: ['*'],
    }));

    // ---- Step Functions state machine (SOAR workflow) ----

    // Reusable approval gate: pause, publish approval request with task token,
    // wait for a human to resume (SendTaskSuccess/Failure).
    const approvalGate = (id: string) => new tasks.SnsPublish(this, id, {
      topic: notifyTopic,
      integrationPattern: sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
      message: sfn.TaskInput.fromObject({
        message: 'CloudSentinel remediation requires approval',
        finding: sfn.JsonPath.stringAt('$.finding_id'),
        playbook: sfn.JsonPath.stringAt('$.playbook'),
        taskToken: sfn.JsonPath.taskToken,
      }),
      resultPath: '$.approval',
    });

    // Reusable executor-invoke for a given action.
    const invokeAction = (id: string, action: string) =>
      new tasks.LambdaInvoke(this, id, {
        lambdaFunction: executor,
        payload: sfn.TaskInput.fromObject({
          action,
          params: sfn.JsonPath.objectAt('$.params'),
        }),
        resultPath: '$.result',
      });

    // Reusable outcome notification.
    const notify = (id: string, text: string) => new tasks.SnsPublish(this, id, {
      topic: notifyTopic,
      message: sfn.TaskInput.fromObject({
        message: text,
        finding: sfn.JsonPath.stringAt('$.finding_id'),
        playbook: sfn.JsonPath.stringAt('$.playbook'),
      }),
    });

    // Playbook 1: compromised EC2 -> approval -> isolate -> snapshot -> notify.
    const ec2Playbook = approvalGate('ApproveEc2')
      .next(invokeAction('IsolateEc2', 'isolate_ec2'))
      .next(invokeAction('SnapshotEbs', 'snapshot_ebs'))
      .next(notify('NotifyEc2', 'CloudSentinel: EC2 remediation complete'));

    // Playbook 2: exposed IAM credential -> approval -> disable key -> notify.
    const iamPlaybook = approvalGate('ApproveIam')
      .next(invokeAction('DisableAccessKey', 'disable_access_key'))
      .next(notify('NotifyIam', 'CloudSentinel: IAM credential remediation complete'));

    // Playbook 3: public S3 bucket -> approval -> block public access -> notify.
    const s3Playbook = approvalGate('ApproveS3')
      .next(invokeAction('BlockS3Public', 'block_s3_public'))
      .next(notify('NotifyS3', 'CloudSentinel: S3 remediation complete'));

    // Playbook 4: generic high-severity -> enrich + notify (non-destructive).
    const genericPlaybook = invokeAction('EnrichFinding', 'enrich')
      .next(notify('NotifyGeneric', 'CloudSentinel: high-severity finding enriched'));

    // Classifier: route by finding type.
    const classify = new sfn.Choice(this, 'ClassifyFinding')
      .when(sfn.Condition.stringEquals('$.playbook', 'ec2_compromise'), ec2Playbook)
      .when(sfn.Condition.stringEquals('$.playbook', 'iam_credential'), iamPlaybook)
      .when(sfn.Condition.stringEquals('$.playbook', 's3_public'), s3Playbook)
      .otherwise(genericPlaybook);

    const stateMachine = new sfn.StateMachine(this, 'RemediationStateMachine', {
      stateMachineName: 'cloudsentinel-remediation',
      definitionBody: sfn.DefinitionBody.fromChainable(classify),
      timeout: Duration.hours(24), // allow time for human approval
    });

    new cdk.CfnOutput(this, 'StateMachineArn', { value: stateMachine.stateMachineArn });
    new cdk.CfnOutput(this, 'NotifyTopicArn', { value: notifyTopic.topicArn });
    new cdk.CfnOutput(this, 'SafeMode', { value: String(safeMode) });
  }
}
