import { ArnFormat, Duration, RemovalPolicy, Stack } from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as sns from 'aws-cdk-lib/aws-sns';
import { ALARM_TOPIC_NAME, CDK_QUALIFIER, STATE_MACHINE_NAME } from '../names';

/** The metric one control change adds one to. Its own namespace, because
 *  it is emitted by a metric filter rather than by a handler. */
export const CONTROL_CHANGES_METRIC = { namespace: 'CloudSentinel/Controls', metricName: 'ControlChanges' };

/** Every platform function's name begins with this; the watch relies on it. */
export const WATCHED_FUNCTION_PREFIX = 'CloudSentinel-';

/** Where every out-of-band change is kept, one event each, for a year. */
export const CONTROL_CHANGES_LOG_GROUP = '/cloudsentinel/control-changes';

/**
 * One watched area: the CloudTrail events that change it, and the request
 * fields that say it was one of the platform's resources.
 */
interface Watch {
  readonly id: string;
  readonly what: string;
  readonly source: string;
  readonly eventNames: Array<string | { prefix: string }>;
  readonly requestParameters?: Record<string, unknown>;
}

/**
 * A rule target that writes to a log group and nothing more. The CDK's own
 * target installs a log-group resource policy per rule through a custom
 * resource — a Lambda function with a wildcard policy — and CloudWatch Logs
 * allows ten such policies per Region, fewer than the rules here. One policy
 * written as a plain resource covers every rule instead.
 */
class LogGroupTarget implements events.IRuleTarget {
  constructor(private readonly logGroup: logs.ILogGroup) {}

  bind(_rule: events.IRule): events.RuleTargetConfig {
    return {
      // EventBridge wants the group's ARN without the ":*" that logGroupArn carries.
      arn: Stack.of(this.logGroup).formatArn({
        service: 'logs', resource: 'log-group', arnFormat: ArnFormat.COLON_RESOURCE_NAME,
        resourceName: this.logGroup.logGroupName,
      }),
      targetResource: this.logGroup,
    };
  }
}

/**
 * Alarms on changes to the security controls themselves.
 *
 * Every objective so far watched the pipeline doing its job. None watched the
 * controls being switched off: the remediation state machine rewritten, an
 * ingestion rule disabled, the findings key scheduled for deletion, the
 * GuardDuty detector deleted or a filter added that archives findings, a
 * function's code replaced, a table dropped, the alarms themselves silenced.
 * Each of those is one API call, and CloudTrail records every one.
 *
 * This construct matches those calls as they arrive in EventBridge, excluding
 * the ones CloudFormation makes through the CDK bootstrap execution role —
 * which is how every legitimate change reaches these resources, whether from
 * the deploy workflow or from `cdk deploy` at a terminal. Anything else is
 * reported with who made it, from where, and the request as sent: to the
 * alarm topic in words, and to a log group that keeps a year of such
 * changes. A metric filter on that log group feeds the objective's alarm.
 *
 * Changes made through the execution role by a compromised deploy pipeline
 * are not caught here; that is the CI/CD boundary's residual risk, recorded
 * in the threat model.
 */
export class ControlChanges extends Construct {
  /** Every out-of-band change, one event each, for a year. */
  readonly log: logs.LogGroup;
  /** Changes in the period, for the alarm and the dashboard. */
  readonly metric: cloudwatch.Metric;
  readonly rules: events.Rule[] = [];

  constructor(scope: Construct, id: string, topic: sns.ITopic) {
    super(scope, id);
    const stack = Stack.of(this);
    const account = stack.account;
    const region = stack.region;

    // CloudFormation acts through this role for every CDK deployment in the
    // account. A session under it is the one caller that may change these
    // resources quietly.
    const deployer = `arn:aws:sts::${account}:assumed-role/cdk-${CDK_QUALIFIER}-cfn-exec-role-${account}-${region}/`;
    const stateMachineArn = `arn:aws:states:${region}:${account}:stateMachine:${STATE_MACHINE_NAME}`;
    const topicArn = `arn:aws:sns:${region}:${account}:${ALARM_TOPIC_NAME}`;
    const functionArnPrefix = `arn:aws:lambda:${region}:${account}:function:${WATCHED_FUNCTION_PREFIX}`;

    const watches: Watch[] = [
      {
        id: 'Remediation', what: 'the remediation state machine', source: 'aws.states',
        eventNames: ['UpdateStateMachine', 'DeleteStateMachine'],
        requestParameters: { stateMachineArn: [stateMachineArn] },
      },
      {
        id: 'RuleDefinitions', what: "one of the platform's EventBridge rules", source: 'aws.events',
        eventNames: ['PutRule', 'DeleteRule', 'DisableRule', 'EnableRule'],
        requestParameters: { name: [{ prefix: 'cloudsentinel-' }] },
      },
      {
        id: 'RuleTargets', what: "one of the platform's EventBridge rules' targets", source: 'aws.events',
        eventNames: ['PutTargets', 'RemoveTargets'],
        requestParameters: { rule: [{ prefix: 'cloudsentinel-' }] },
      },
      {
        id: 'Keys', what: 'a KMS key', source: 'aws.kms',
        eventNames: ['DisableKey', 'ScheduleKeyDeletion', 'PutKeyPolicy', 'DisableKeyRotation', 'DeleteAlias'],
      },
      {
        id: 'GuardDuty', what: 'GuardDuty', source: 'aws.guardduty',
        eventNames: [
          'DeleteDetector', 'UpdateDetector', 'DisassociateFromAdministratorAccount',
          'DisassociateFromMasterAccount', 'DisassociateMembers', 'DeleteMembers', 'StopMonitoringMembers',
          'UpdateOrganizationConfiguration', 'DeletePublishingDestination',
          // A trusted-IP list or an archiving filter silences findings without
          // touching the detector.
          'CreateIPSet', 'UpdateIPSet', 'CreateFilter', 'UpdateFilter',
        ],
      },
      {
        // Lambda's CloudTrail event names carry an API version suffix, such as
        // UpdateFunctionCode20150331v2, so they are matched by prefix.
        id: 'Functions', what: "one of the platform's functions", source: 'aws.lambda',
        eventNames: [
          { prefix: 'UpdateFunctionCode' }, { prefix: 'UpdateFunctionConfiguration' },
          { prefix: 'DeleteFunction' }, { prefix: 'PutFunctionConcurrency' },
        ],
        requestParameters: { functionName: [{ prefix: WATCHED_FUNCTION_PREFIX }, { prefix: functionArnPrefix }] },
      },
      {
        id: 'EventSourceMappings', what: "the normalizer's stream mapping", source: 'aws.lambda',
        eventNames: [{ prefix: 'DeleteEventSourceMapping' }, { prefix: 'UpdateEventSourceMapping' }],
      },
      {
        id: 'Tables', what: "one of the platform's tables", source: 'aws.dynamodb',
        eventNames: ['DeleteTable', 'UpdateTable', 'UpdateTimeToLive', 'UpdateContinuousBackups'],
        requestParameters: { tableName: [{ prefix: 'cloudsentinel-' }] },
      },
      {
        id: 'Alarms', what: 'an objective alarm', source: 'aws.monitoring',
        eventNames: ['DeleteAlarms', 'DisableAlarmActions', 'PutMetricAlarm'],
        requestParameters: { alarmNames: [{ prefix: 'cloudsentinel-slo-' }] },
      },
      {
        id: 'AlarmTopic', what: 'the alarm topic', source: 'aws.sns',
        eventNames: ['DeleteTopic', 'SetTopicAttributes', 'RemovePermission'],
        requestParameters: { topicArn: [topicArn] },
      },
      {
        id: 'AlarmSubscriptions', what: "the alarm topic's subscriptions", source: 'aws.sns',
        eventNames: ['Unsubscribe'],
        requestParameters: { subscriptionArn: [{ prefix: `${topicArn}:` }] },
      },
    ];

    this.log = new logs.LogGroup(this, 'Log', {
      logGroupName: CONTROL_CHANGES_LOG_GROUP,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    new logs.ResourcePolicy(this, 'EventsMayWrite', {
      resourcePolicyName: 'cloudsentinel-control-changes-events',
      policyStatements: [new iam.PolicyStatement({
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        principals: [new iam.ServicePrincipal('events.amazonaws.com')],
        resources: [this.log.logGroupArn],
      })],
    });

    // Scalar fields only: a text template cannot carry the request object,
    // whose quotes would break it. The full event, request included, is in
    // the log group under the event ID the message names.
    const field = (path: string) => events.EventField.fromPath(path);
    const message = (watch: Watch) => events.RuleTargetInput.fromText([
      `CloudSentinel: ${watch.what} was changed outside the deployment pipeline.`,
      '',
      `What:  ${field('$.detail.eventName')} (${field('$.detail.eventSource')})`,
      `Who:   ${field('$.detail.userIdentity.arn')} (${field('$.detail.userIdentity.type')})`,
      `From:  ${field('$.detail.sourceIPAddress')} via ${field('$.detail.userAgent')}`,
      `When:  ${field('$.detail.eventTime')} in ${field('$.detail.awsRegion')}`,
      `Event: ${field('$.detail.eventID')} — the full request is in the ${CONTROL_CHANGES_LOG_GROUP} log group`,
      '',
      'Every legitimate change to this resource arrives through CloudFormation and the CDK ' +
      'execution role, which this message excludes. If you made this change by hand, record ' +
      'why. If you did not, treat it as an intrusion in progress: the control it changed is ' +
      'the one that would have reported the attacker (docs/slos.md, objective 8).',
    ].join('\n'));

    for (const watch of watches) {
      const rule = new events.Rule(this, watch.id, {
        ruleName: `cloudsentinel-control-${watch.id.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase()}`,
        description: `A change to ${watch.what} not made through the CDK execution role`,
        eventPattern: {
          detailType: ['AWS API Call via CloudTrail'],
          source: [watch.source],
          detail: {
            eventName: watch.eventNames,
            ...(watch.requestParameters ? { requestParameters: watch.requestParameters } : {}),
            // userIdentity.arn is present on every call a principal makes;
            // under the execution role it begins with the deployer prefix.
            userIdentity: { arn: [{ 'anything-but': { prefix: deployer } }] },
          },
        },
      });
      rule.addTarget(new targets.SnsTopic(topic, { message: message(watch) }));
      rule.addTarget(new LogGroupTarget(this.log));
      this.rules.push(rule);
    }

    new logs.MetricFilter(this, 'Changes', {
      logGroup: this.log,
      filterPattern: logs.FilterPattern.allEvents(),
      metricNamespace: CONTROL_CHANGES_METRIC.namespace,
      metricName: CONTROL_CHANGES_METRIC.metricName,
      metricValue: '1',
    });
    this.metric = new cloudwatch.Metric({
      ...CONTROL_CHANGES_METRIC, statistic: 'Sum', period: Duration.minutes(5),
      label: 'changes outside the pipeline',
    });
  }
}
