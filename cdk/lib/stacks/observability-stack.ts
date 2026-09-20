import * as cdk from 'aws-cdk-lib/core';
import { Duration } from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as sns from 'aws-cdk-lib/aws-sns';
import {
  ALARM_TOPIC_NAME, FINDINGS_STREAM_NAME, FUNCTION_NAMES, INGESTION_RULE_NAMES,
  METRIC_NAMESPACE, REMEDIATION_RULE_NAME, STATE_MACHINE_NAME,
} from '../names';

/**
 * ObservabilityStack — deploys to the Audit account (118821712739).
 *
 * The platform's service level objectives, each an alarm on the metric that
 * measures it, plus the dashboard that shows every measure against its
 * objective. docs/slos.md defines each objective and says what to do when its
 * alarm fires.
 *
 * Nothing here holds data, so the stack is persistent and costs cents a month.
 * The API's objectives live in ApiStack, because the load balancer they
 * measure exists only while that stack is deployed.
 */
const FIVE_MINUTES = Duration.minutes(5);
const RED = '#d62728';

export class ObservabilityStack extends cdk.Stack {
  /** Every SLO alarm this stack defines, for the status widget and tests. */
  readonly sloAlarms: cloudwatch.Alarm[] = [];

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Alarm notifications carry alarm names, states and metric values — never
    // finding content — so the topic enforces TLS but is not KMS-encrypted:
    // CloudWatch cannot publish to a topic under the AWS-managed SNS key, and a
    // customer-managed key would protect nothing sensitive. Subscriptions are
    // added outside CDK (docs/slos.md), so no address is committed to the
    // repository and a deploy never removes one.
    const topic = new sns.Topic(this, 'AlarmTopic', {
      topicName: ALARM_TOPIC_NAME,
      displayName: 'CloudSentinel SLO alarms',
      enforceSSL: true,
    });
    const notify = new cwActions.SnsAction(topic);

    // ------------------------------------------------------------ what we watch
    const fn = (key: keyof typeof FUNCTION_NAMES) =>
      lambda.Function.fromFunctionName(this, `${key}Function`, FUNCTION_NAMES[key]);
    const normalizer = fn('normalizer');
    const correlator = fn('correlator');
    const router = fn('router');
    const executor = fn('executor');
    const approvalRecorder = fn('approvalRecorder');
    const stateMachine = sfn.StateMachine.fromStateMachineName(
      this, 'RemediationStateMachine', STATE_MACHINE_NAME);

    const sum = { statistic: 'Sum', period: FIVE_MINUTES };
    const errors = (f: lambda.IFunction, label: string) => f.metricErrors({ ...sum, label });

    /** Metrics the handlers publish themselves (Embedded Metric Format). */
    const published = (metricName: string, component: string, label: string,
      period: Duration = FIVE_MINUTES) =>
      new cloudwatch.Metric({
        namespace: METRIC_NAMESPACE, metricName, dimensionsMap: { Component: component },
        statistic: 'Sum', period, label,
      });

    /** Events a rule matched but could not deliver, after EventBridge's retries. */
    const undelivered = (ruleName: string) => new cloudwatch.Metric({
      namespace: 'AWS/Events', metricName: 'FailedInvocations',
      dimensionsMap: { RuleName: ruleName }, ...sum,
    });

    const stream = (metricName: string, label: string) => new cloudwatch.Metric({
      namespace: 'AWS/Kinesis', metricName, dimensionsMap: { StreamName: FINDINGS_STREAM_NAME },
      ...sum, label,
    });

    // ------------------------------------------------------------ objectives
    const slo = (name: string, description: string, props: {
      metric: cloudwatch.IMetric;
      threshold: number;
      comparisonOperator: cloudwatch.ComparisonOperator;
      treatMissingData: cloudwatch.TreatMissingData;
      evaluationPeriods?: number;
    }) => {
      const alarm = new cloudwatch.Alarm(this, `Slo-${name}`, {
        alarmName: `cloudsentinel-slo-${name}`,
        alarmDescription: description,
        evaluationPeriods: 1,
        ...props,
      });
      // Recovery is announced as well as the breach, so a notification is
      // never left standing for a problem that has cleared.
      alarm.addAlarmAction(notify);
      alarm.addOkAction(notify);
      this.sloAlarms.push(alarm);
      return alarm;
    };

    // 1. Findings are stored. Three places can drop one: EventBridge failing to
    //    deliver it to the stream, the normalizer failing on the record (such
    //    failures are caught per record, so they never reach Lambda's own
    //    Errors metric — the handler counts them itself), and the normalizer
    //    failing a whole batch.
    const failedInNormalizer = published('RecordsFailed', 'normalizer', 'failed in normalizer');
    const normalizerErrors = errors(normalizer, 'normalizer batch errors');
    const ingestionUndelivered = new cloudwatch.MathExpression({
      expression: 'SUM([gd, sh, insp])',
      usingMetrics: {
        gd: undelivered(INGESTION_RULE_NAMES.GuardDuty),
        sh: undelivered(INGESTION_RULE_NAMES.SecurityHub),
        insp: undelivered(INGESTION_RULE_NAMES.Inspector),
      },
      label: 'undelivered by EventBridge',
      period: FIVE_MINUTES,
    });
    slo('findings-stored',
      'A security finding failed between EventBridge and the findings table in the last 5 ' +
      'minutes. A record that fails inside the normalizer is not retried, so that finding is ' +
      'lost. The CloudSentinel-SLOs dashboard shows which stage failed; the normalizer logs ' +
      'each failure as "Failed to process record".', {
        metric: new cloudwatch.MathExpression({
          expression: 'SUM([failed, batch, undelivered])',
          usingMetrics: { failed: failedInNormalizer, batch: normalizerErrors, undelivered: ingestionUndelivered },
          label: 'findings not stored',
          period: FIVE_MINUTES,
        }),
        threshold: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });

    // 2. Findings are stored promptly. Iterator age is how long the oldest
    //    record in the latest batch waited in the stream. No records means
    //    nothing is waiting, so missing data is not a breach.
    const iteratorAge = normalizer.metric('IteratorAge', { statistic: 'Maximum', period: FIVE_MINUTES });
    slo('findings-fresh',
      'Findings have waited in the stream for more than 5 minutes in two consecutive 5-minute ' +
      'windows. The normalizer is falling behind or failing: check its errors, throttles and ' +
      'duration on the CloudSentinel-SLOs dashboard.', {
        metric: iteratorAge,
        threshold: Duration.minutes(5).toMilliseconds(),
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
        evaluationPeriods: 2,
      });

    // 3. Incidents stay current. The correlator runs every 15 minutes and
    //    publishes a count only once a run has finished, so the count is a
    //    heartbeat: a run that crashes, times out or never starts publishes
    //    nothing, and silence is the breach.
    const correlationRuns = published('CorrelationRunsCompleted', 'correlator',
      'completed runs', Duration.minutes(45));
    slo('incidents-current',
      'No correlation run has completed in 45 minutes; the correlator is scheduled every 15. ' +
      'Incidents on the dashboard are going stale. Check the correlator\'s log and the ' +
      'cloudsentinel-correlation schedule.', {
        metric: correlationRuns,
        threshold: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.BREACHING,
      });

    // 4. Remediation steps run. Lambda errors rather than failed executions:
    //    an operator rejecting an approval also fails the execution, and a
    //    rejection is a decision, not a fault.
    const routerErrors = errors(router, 'router');
    const recorderErrors = errors(approvalRecorder, 'approval recorder');
    const executorErrors = errors(executor, 'executor');
    const routeUndelivered = undelivered(REMEDIATION_RULE_NAME).with({ label: 'undelivered by EventBridge' });
    slo('remediation-runs',
      'A remediation step failed: EventBridge could not invoke the router, the router could ' +
      'not start a workflow, or the approval recorder or executor raised an error. A ' +
      'high-severity finding may not have reached its playbook. Check the ' +
      'cloudsentinel-remediation state machine\'s recent executions and the functions\' logs.', {
        metric: new cloudwatch.MathExpression({
          expression: 'SUM([route, record, execute, deliver])',
          usingMetrics: {
            route: routerErrors, record: recorderErrors, execute: executorErrors, deliver: routeUndelivered,
          },
          label: 'remediation errors',
          period: FIVE_MINUTES,
        }),
        threshold: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });

    // 5. Approvals are decided. A workflow times out only when its approval
    //    waited the full 24 hours, so a timeout means an action that was
    //    judged necessary never ran.
    const approvalsExpired = stateMachine.metricTimedOut({ ...sum, label: 'approval expired' });
    slo('approvals-decided',
      'A remediation approval expired: nobody approved or rejected it within 24 hours, so the ' +
      'workflow timed out and its action never ran. Review the finding and act on it manually ' +
      'if it still applies.', {
        metric: approvalsExpired,
        threshold: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });

    // ------------------------------------------------------------ dashboard
    const line = (value: number, label: string) => ({ value, label, color: RED });
    const seconds = (id: string, metric: cloudwatch.IMetric, label: string) =>
      new cloudwatch.MathExpression({ expression: `${id} / 1000`, usingMetrics: { [id]: metric }, label });

    new cloudwatch.Dashboard(this, 'SloDashboard', {
      dashboardName: 'CloudSentinel-SLOs',
      defaultInterval: Duration.days(7),
      widgets: [
        [
          new cloudwatch.TextWidget({
            width: 8, height: 6,
            markdown: [
              '# CloudSentinel objectives',
              'Each row is one service level objective: the measure on the left, with its',
              'alarm threshold drawn in red, and context on the right. Alarms notify the',
              `\`${ALARM_TOPIC_NAME}\` topic when they fire and when they clear.`,
              '',
              'Definitions and responses: `docs/slos.md` in the repository.',
            ].join('\n'),
          }),
          new cloudwatch.AlarmStatusWidget({
            title: 'Objectives', width: 16, height: 6, alarms: this.sloAlarms,
          }),
        ],
        [
          new cloudwatch.GraphWidget({
            title: 'Findings not stored (objective: none)', width: 12, stacked: true,
            left: [failedInNormalizer, normalizerErrors, ingestionUndelivered],
            leftAnnotations: [line(1, 'alarm')],
            leftYAxis: { min: 0, showUnits: false },
          }),
          new cloudwatch.GraphWidget({
            title: 'Findings arriving', width: 12,
            left: [
              stream('IncomingRecords', 'written to the stream'),
              published('RecordsReceived', 'normalizer', 'read by the normalizer'),
            ],
            leftYAxis: { min: 0, showUnits: false },
          }),
        ],
        [
          new cloudwatch.GraphWidget({
            title: 'Oldest waiting finding, seconds (objective: under 5 minutes)', width: 12,
            left: [seconds('age', iteratorAge, 'iterator age')],
            leftAnnotations: [line(300, 'alarm')],
            leftYAxis: { min: 0, showUnits: false },
          }),
          new cloudwatch.GraphWidget({
            title: 'Stream write throttling', width: 12,
            left: [stream('WriteProvisionedThroughputExceeded', 'throttled writes')],
            leftYAxis: { min: 0, showUnits: false },
          }),
        ],
        [
          new cloudwatch.GraphWidget({
            title: 'Completed correlation runs per 15 minutes (alarm: none in 45)', width: 12,
            left: [published('CorrelationRunsCompleted', 'correlator', 'completed runs', Duration.minutes(15))],
            leftAnnotations: [line(1, 'expected')],
            leftYAxis: { min: 0, showUnits: false },
          }),
          new cloudwatch.GraphWidget({
            title: 'Correlator run time, seconds (timeout: 300)', width: 12,
            left: [seconds('duration', correlator.metricDuration({ statistic: 'Maximum', period: FIVE_MINUTES }), 'longest run')],
            leftAnnotations: [line(300, 'timeout')],
            leftYAxis: { min: 0, showUnits: false },
          }),
        ],
        [
          new cloudwatch.GraphWidget({
            title: 'Remediation errors (objective: none)', width: 12, stacked: true,
            left: [routerErrors, recorderErrors, executorErrors, routeUndelivered],
            leftAnnotations: [line(1, 'alarm')],
            leftYAxis: { min: 0, showUnits: false },
          }),
          new cloudwatch.GraphWidget({
            title: 'Remediation workflows', width: 12,
            left: [
              stateMachine.metricStarted({ ...sum, label: 'started' }),
              stateMachine.metricSucceeded({ ...sum, label: 'completed' }),
              stateMachine.metricFailed({ ...sum, label: 'failed or rejected' }),
              approvalsExpired,
            ],
            leftYAxis: { min: 0, showUnits: false },
          }),
        ],
        [
          new cloudwatch.GraphWidget({
            title: 'Advisory triage — no objective: a note helps an analyst but protects nothing',
            width: 24, height: 5,
            left: [
              published('IncidentsTriaged', 'triage', 'notes written', Duration.minutes(15)),
              published('TriageRejected', 'triage', 'answers rejected', Duration.minutes(15)),
              published('TriageFailed', 'triage', 'model errors', Duration.minutes(15)),
              published('TriageThrottled', 'triage', 'runs throttled', Duration.minutes(15)),
            ],
            right: [new cloudwatch.Metric({
              namespace: METRIC_NAMESPACE, metricName: 'IncidentsAwaitingTriage',
              dimensionsMap: { Component: 'triage' }, statistic: 'Maximum',
              period: Duration.minutes(15), label: 'incidents awaiting a note',
            })],
            leftYAxis: { min: 0, showUnits: false },
            rightYAxis: { min: 0, showUnits: false },
          }),
        ],
        [
          new cloudwatch.TextWidget({
            width: 24, height: 3,
            markdown: [
              '**Tracing.** Every CloudSentinel function and the remediation state machine record',
              'X-Ray traces; a remediation is one trace from the router to each playbook step. Open',
              'them from X-Ray traces → Trace Map in the CloudWatch console.',
              '',
              '**API.** Availability and latency objectives are on the CloudSentinel-API dashboard,',
              'which exists only while the on-demand API stack is deployed.',
            ].join('\n'),
          }),
        ],
      ],
    });

    new cdk.CfnOutput(this, 'AlarmTopicArn', { value: topic.topicArn });
  }
}
