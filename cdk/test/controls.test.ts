/**
 * Changes to the security controls themselves.
 *
 * Every objective before this one watched the pipeline work; this one watches
 * the controls being switched off. These tests pin what is watched — a list
 * of the API calls an attacker or a careless hand would make — that each is
 * reported and recorded, that a CloudFormation deployment through the CDK
 * execution role is the one caller left out, and that the watch protects its
 * own rules and the alarm topic it reports to.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib/core';
import { Template } from 'aws-cdk-lib/assertions';
import { ACCOUNTS, env } from '../lib/config';
import {
  CONTROL_CHANGES_LOG_GROUP, CONTROL_CHANGES_METRIC, WATCHED_FUNCTION_PREFIX,
} from '../lib/constructs/control-changes';
import { ALARM_TOPIC_NAME, CDK_QUALIFIER, FUNCTION_NAMES, STATE_MACHINE_NAME } from '../lib/names';
import { ObservabilityStack } from '../lib/stacks/observability-stack';

const { context } = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'cdk.json'), 'utf8'));
const app = new cdk.App({ context });
const t = Template.fromStack(new ObservabilityStack(app, 'TestObservability', { env: env(ACCOUNTS.audit) }));

type Props = Record<string, any>;
const resources = (type: string): Props[] =>
  Object.values(t.findResources(type)).map((r: any) => r.Properties);
const rules = resources('AWS::Events::Rule').filter((r) => r.EventPattern);
const [topicId] = Object.keys(t.findResources('AWS::SNS::Topic'));
const ACCOUNT_REGION = `us-east-1:${ACCOUNTS.audit}`;
const DEPLOYER = `arn:aws:sts::${ACCOUNTS.audit}:assumed-role/cdk-${CDK_QUALIFIER}-cfn-exec-role-${ACCOUNTS.audit}-us-east-1/`;

/** Does one of our patterns match this (source, eventName, requestParameters)? */
function watched(source: string, eventName: string, requestParameters: Record<string, unknown>): boolean {
  const matchesValue = (candidates: any[], value: unknown) => candidates.some((c) =>
    typeof c === 'string' ? c === value : typeof value === 'string' && value.startsWith(c.prefix));
  return rules.some((r) => {
    const p = r.EventPattern;
    if (!p.source.includes(source) || !matchesValue(p.detail.eventName, eventName)) return false;
    for (const [key, candidates] of Object.entries(p.detail.requestParameters ?? {})) {
      const value = requestParameters[key];
      // A list-valued request field matches if any element does.
      const values = Array.isArray(value) ? value : [value];
      if (!values.some((v) => matchesValue(candidates as any[], v))) return false;
    }
    return true;
  });
}

describe('what counts as a change to a control', () => {
  const machine = `arn:aws:states:${ACCOUNT_REGION}:stateMachine:${STATE_MACHINE_NAME}`;
  const topic = `arn:aws:sns:${ACCOUNT_REGION}:${ALARM_TOPIC_NAME}`;

  test.each([
    ['aws.states', 'UpdateStateMachine', { stateMachineArn: machine }],
    ['aws.states', 'DeleteStateMachine', { stateMachineArn: machine }],
    ['aws.events', 'DisableRule', { name: 'cloudsentinel-guardduty-findings' }],
    ['aws.events', 'DeleteRule', { name: 'cloudsentinel-highsev-remediation' }],
    ['aws.events', 'PutRule', { name: 'cloudsentinel-correlation' }],
    ['aws.events', 'RemoveTargets', { rule: 'cloudsentinel-triage', ids: ['Target0'] }],
    ['aws.events', 'DisableRule', { name: 'cloudsentinel-control-functions' }],  // the watch itself
    ['aws.kms', 'ScheduleKeyDeletion', { keyId: 'any' }],
    ['aws.kms', 'DisableKey', { keyId: 'any' }],
    ['aws.kms', 'PutKeyPolicy', { keyId: 'any', policyName: 'default' }],
    ['aws.guardduty', 'DeleteDetector', { detectorId: 'd' }],
    ['aws.guardduty', 'UpdateDetector', { detectorId: 'd', enable: false }],
    ['aws.guardduty', 'CreateIPSet', { detectorId: 'd', name: 'trusted' }],
    ['aws.guardduty', 'CreateFilter', { detectorId: 'd', action: 'ARCHIVE' }],
    ['aws.guardduty', 'DisassociateMembers', { detectorId: 'd' }],
    ['aws.lambda', 'UpdateFunctionCode20150331v2', { functionName: FUNCTION_NAMES.normalizer }],
    ['aws.lambda', 'UpdateFunctionConfiguration20150331v2', { functionName: FUNCTION_NAMES.triage }],
    ['aws.lambda', 'PutFunctionConcurrency20170930', { functionName: FUNCTION_NAMES.correlator }],
    ['aws.lambda', 'DeleteFunction20150331', {
      functionName: `arn:aws:lambda:${ACCOUNT_REGION}:function:${FUNCTION_NAMES.executor}` }],
    ['aws.lambda', 'DeleteEventSourceMapping20150331', { uuid: 'u' }],
    ['aws.lambda', 'UpdateEventSourceMapping20150331', { uuid: 'u', enabled: false }],
    ['aws.dynamodb', 'DeleteTable', { tableName: 'cloudsentinel-findings' }],
    ['aws.dynamodb', 'UpdateTimeToLive', { tableName: 'cloudsentinel-intel' }],
    ['aws.dynamodb', 'UpdateContinuousBackups', { tableName: 'cloudsentinel-incidents' }],
    ['aws.iam', 'PutRolePolicy', { roleName: 'CloudSentinel-Ingestion-NormalizerServiceRole7A4B-1AB2C3', policyName: 'deny' }],
    ['aws.iam', 'AttachRolePolicy', { roleName: 'CloudSentinel-Api-ApiServiceTaskDefTaskRole-X' }],
    ['aws.iam', 'UpdateAssumeRolePolicy', { roleName: 'CloudSentinel-Remediation-ExecutorRole-Y' }],
    ['aws.monitoring', 'DeleteAlarms', { alarmNames: ['cloudsentinel-slo-findings-stored'] }],
    ['aws.monitoring', 'DisableAlarmActions', { alarmNames: ['x', 'cloudsentinel-slo-controls-unchanged'] }],
    ['aws.sns', 'DeleteTopic', { topicArn: topic }],
    ['aws.sns', 'Unsubscribe', { subscriptionArn: `${topic}:0f2a...` }],
  ])('%s %s is reported', (source, eventName, request) => {
    expect(watched(source, eventName, request)).toBe(true);
  });

  test.each([
    ['aws.events', 'DisableRule', { name: 'someone-elses-rule' }],
    ['aws.lambda', 'UpdateFunctionCode20150331v2', { functionName: 'OtherTeam-Function' }],
    ['aws.dynamodb', 'DeleteTable', { tableName: 'other-table' }],
    ['aws.monitoring', 'DeleteAlarms', { alarmNames: ['other-alarm'] }],
    ['aws.iam', 'PutRolePolicy', { roleName: 'SomeOtherRole', policyName: 'x' }],
    ['aws.states', 'DescribeStateMachine', { stateMachineArn: machine }],
  ])('%s %s on something else is not', (source, eventName, request) => {
    expect(watched(source, eventName, request)).toBe(false);
  });

  test('every platform function carries the prefix the watch relies on', () => {
    for (const name of Object.values(FUNCTION_NAMES)) expect(name.startsWith(WATCHED_FUNCTION_PREFIX)).toBe(true);
  });
});

describe('every control rule', () => {
  test('reads CloudTrail and leaves out the CDK execution role, and only it', () => {
    expect(rules.length).toBeGreaterThanOrEqual(10);
    for (const r of rules) {
      expect(r.EventPattern['detail-type']).toEqual(['AWS API Call via CloudTrail']);
      expect(r.EventPattern.detail.userIdentity).toEqual({ arn: [{ 'anything-but': { prefix: DEPLOYER } }] });
    }
  });

  test('reports to the alarm topic in words and records the event in the log group', () => {
    const [logId] = Object.keys(t.findResources('AWS::Logs::LogGroup'));
    for (const r of rules) {
      const [sns, log] = r.Targets;
      expect(sns.Arn).toEqual({ Ref: topicId });
      expect(sns.InputTransformer.InputTemplate).toContain('outside the deployment pipeline');
      expect(sns.InputTransformer.InputPathsMap['detail-userIdentity-arn']).toBe('$.detail.userIdentity.arn');
      expect(sns.InputTransformer.InputPathsMap['detail-eventID']).toBe('$.detail.eventID');
      expect(JSON.stringify(log.Arn)).toContain(logId);
      expect(log.InputTransformer).toBeUndefined();  // the whole event, as CloudTrail recorded it
    }
  });

  test('is named so that the watch covers its own rules', () => {
    for (const r of rules) expect(r.Name).toMatch(/^cloudsentinel-control-/);
  });
});

describe('the record of changes', () => {
  test('is kept for a year and may be written by EventBridge alone', () => {
    t.hasResourceProperties('AWS::Logs::LogGroup', { LogGroupName: CONTROL_CHANGES_LOG_GROUP, RetentionInDays: 365 });
    const [policy] = resources('AWS::Logs::ResourcePolicy');
    const text = JSON.stringify(policy.PolicyDocument);
    expect(text).toContain('events.amazonaws.com');
    expect(text).toContain('logs:PutLogEvents');
    expect(text).not.toContain('"*"');
  });

  test('feeds the objective through one metric filter', () => {
    const [filter] = resources('AWS::Logs::MetricFilter');
    expect(filter.MetricTransformations).toEqual([expect.objectContaining({
      MetricNamespace: CONTROL_CHANGES_METRIC.namespace, MetricName: CONTROL_CHANGES_METRIC.metricName, MetricValue: '1',
    })]);
    const alarm = resources('AWS::CloudWatch::Alarm').find((a) => a.AlarmName === 'cloudsentinel-slo-controls-unchanged')!;
    // A labelled metric is rendered in the Metrics form; one metric, read directly.
    expect(alarm.Metrics).toEqual([expect.objectContaining({
      ReturnData: true,
      MetricStat: expect.objectContaining({ Stat: 'Sum', Metric: {
        Namespace: CONTROL_CHANGES_METRIC.namespace, MetricName: CONTROL_CHANGES_METRIC.metricName } }),
    })]);
    expect(alarm.Threshold).toBe(1);
    expect(alarm.TreatMissingData).toBe('notBreaching');
  });
});
