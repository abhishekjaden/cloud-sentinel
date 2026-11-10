/**
 * The platform's own detector (ADR 0011), from capture file to findings table.
 *
 * In the workload account: what the function is built from and what it may
 * touch — the capture prefix to read, its own day's tally, its own account's
 * bus — and that every capture file reaches it, because a file that lands
 * unscored is a report section 8's D4 would count missing. In the audit
 * account: that the detector's findings reach the stream the other sources
 * reach, and that the bus admits nothing else from the workload account.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib/core';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { ACCOUNTS, env } from '../lib/config';
import { DETECTOR_DETAIL_TYPE, DETECTOR_SOURCE, INGESTION_RULE_NAMES } from '../lib/names';
import {
  CAPTURE_PREFIX, DETECTOR_IMAGE_FILES, DETECTOR_RECORD, HONEYPOT_CIDR, HoneypotStack, detectorImageContext,
  parseDetectorRecord,
} from '../lib/stacks/honeypot-stack';
import { IngestionStack } from '../lib/stacks/ingestion-stack';

const REPO = path.join(__dirname, '..', '..');
const LOGGING_POLICY_FLAG = '@aws-cdk/aws-s3:createDefaultLoggingPolicy';
const app = new cdk.App({ context: { [LOGGING_POLICY_FLAG]: true } });
const honeypot = Template.fromStack(new HoneypotStack(app, 'TestDetectorHoneypot', { env: env(ACCOUNTS.workload) }));
const ingestion = Template.fromStack(new IngestionStack(new cdk.App(), 'TestDetectorIngestion', { env: env(ACCOUNTS.audit) }));

const detectorFunction = () => {
  const found = Object.values(honeypot.findResources('AWS::Lambda::Function', {
    Properties: { PackageType: 'Image' },
  })) as any[];
  expect(found).toHaveLength(1);
  return found[0].Properties;
};
const statementsOf = (roleRef: string) => {
  const policies = Object.values(honeypot.findResources('AWS::IAM::Policy')) as any[];
  return policies
    .filter((p) => JSON.stringify(p.Properties.Roles).includes(roleRef))
    .flatMap((p) => p.Properties.PolicyDocument.Statement);
};

describe('the detector function', () => {
  test('serves the model section 8 recorded, at the threshold its rule chose, under the version it was chosen under', () => {
    const record = JSON.parse(fs.readFileSync(DETECTOR_RECORD, 'utf-8'));
    const vars = detectorFunction().Environment.Variables;
    expect(vars.MODEL_SHA256).toBe(record.model.sha256);
    expect(Number(vars.THRESHOLD_MARGIN)).toBe(record.threshold.margin);   // the same double, so the same float32
    expect(vars.XGBOOST_VERSION).toBe(record.versions.xgboost);
    expect(vars.HOST_NETWORK).toBe(HONEYPOT_CIDR);
    expect(vars.CAPTURE_PREFIX).toBe(CAPTURE_PREFIX);
  });

  test('is an x86-64 image with room for the model, and no reserved concurrency to take from the account', () => {
    const f = detectorFunction();
    expect(f.Architectures).toEqual(['x86_64']);
    expect(f.MemorySize).toBe(1024);
    expect(f.Timeout).toBe(300);
    expect(f.ReservedConcurrentExecutions).toBeUndefined();
  });

  test('may read the capture prefix, keep its own tally and report to its own bus, and nothing else', () => {
    const roleRef = detectorFunction().Role['Fn::GetAtt'][0];
    const statements = statementsOf(roleRef);
    const actions = statements.flatMap((s: any) => [].concat(s.Action)).sort();
    expect(actions).toEqual([
      'dynamodb:GetItem', 'dynamodb:UpdateItem', 'events:PutEvents', 's3:GetObject',
      'sqs:GetQueueAttributes', 'sqs:GetQueueUrl', 'sqs:SendMessage',      // its on-failure destination
    ].sort());
    const read = statements.find((s: any) => s.Sid === 'ReadCaptureFiles');
    expect(JSON.stringify(read.Resource)).toContain(`/${CAPTURE_PREFIX}*`);
    const report = statements.find((s: any) => s.Sid === 'ReportToThisAccountsBus');
    expect(JSON.stringify(report.Resource)).toContain(':event-bus/default');
    expect(JSON.stringify(report.Resource)).not.toContain(ACCOUNTS.audit);
  });

  test('builds its image from its own files and, unchanged, the extractor, the schema and the model', () => {
    const dir = detectorImageContext();
    try {
      // Everything the image names that is here: all but the model, which git ignores.
      const expected: string[] = [];
      for (const [name, from] of Object.entries(DETECTOR_IMAGE_FILES)) {
        const source = path.join(REPO, from);
        if (!fs.existsSync(source)) continue;
        expected.push(name);
        expect(fs.readFileSync(path.join(dir, name)).equals(fs.readFileSync(source))).toBe(true);
      }
      expect(fs.readdirSync(dir).sort()).toEqual(expected.sort());
      expect(expected).toEqual(expect.arrayContaining(['Dockerfile', 'handler.py', 'pcap_flows.py', 'harmonize.py']));
      const dockerfile = fs.readFileSync(path.join(dir, 'Dockerfile'), 'utf-8');
      expect(dockerfile).toContain('xgboost-cpu==3.3.0');
      expect(dockerfile).toContain('COPY handler.py pcap_flows.py harmonize.py cross_dataset.py platform_detector.ubj');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('is not deployed from a record whose rule was not met, or whose model does not reproduce section 7', () => {
    const met = { reproduction: { reproduced: true }, rule_met: true, model: { sha256: 'a' }, threshold: { margin: 0.5 },
      versions: { xgboost: '3.3.0' } };
    expect(parseDetectorRecord(JSON.stringify(met))).toEqual({ sha256: 'a', threshold: '0.5', xgboost: '3.3.0' });
    expect(() => parseDetectorRecord(JSON.stringify({ ...met, rule_met: false }))).toThrow(/rule was not met/);
    expect(() => parseDetectorRecord(JSON.stringify({ ...met, reproduction: { reproduced: false } })))
      .toThrow(/rule was not met/);
  });
});

describe('every capture file reaches the detector', () => {
  test('the bucket notifies it of every capture file created, and of nothing else', () => {
    const [notifications] = Object.values(honeypot.findResources('Custom::S3BucketNotifications')) as any[];
    const config = notifications.Properties.NotificationConfiguration;
    expect(Object.keys(config)).toEqual(['LambdaFunctionConfigurations']);
    expect(config.LambdaFunctionConfigurations).toHaveLength(1);
    const [only] = config.LambdaFunctionConfigurations;
    expect(only.Events).toEqual(['s3:ObjectCreated:*']);
    expect(only.LambdaFunctionArn['Fn::GetAtt'][0]).toMatch(/^Detector/);
    const rules = [...only.Filter.Key.FilterRules].sort((a: any, b: any) => a.Name.localeCompare(b.Name));
    expect(rules).toEqual([{ Name: 'prefix', Value: CAPTURE_PREFIX }, { Name: 'suffix', Value: '.pcap' }]);
  });

  test('the instance boots only once the notification is in place, so no file lands unscored', () => {
    const [instance] = Object.values(honeypot.findResources('AWS::EC2::Instance')) as any[];
    const notifications = Object.keys(honeypot.findResources('Custom::S3BucketNotifications'));
    expect(notifications).toHaveLength(1);
    expect(instance.DependsOn).toEqual(expect.arrayContaining(notifications));
  });

  test('a file it cannot score, or a finding the rule cannot deliver, ends in one queue', () => {
    const queues = Object.keys(honeypot.findResources('AWS::SQS::Queue'));
    expect(queues).toHaveLength(1);
    honeypot.hasResourceProperties('AWS::Lambda::EventInvokeConfig', {
      MaximumRetryAttempts: 2,
      DestinationConfig: { OnFailure: { Destination: { 'Fn::GetAtt': [queues[0], 'Arn'] } } },
    });
  });
});

describe('the findings reach the audit account', () => {
  test('the workload account forwards the detector\'s events, and only those, to the audit account\'s bus', () => {
    honeypot.hasResourceProperties('AWS::Events::Rule', {
      EventPattern: { source: [DETECTOR_SOURCE], 'detail-type': [DETECTOR_DETAIL_TYPE] },
      Targets: [Match.objectLike({
        Arn: Match.stringLikeRegexp(`:${ACCOUNTS.audit}:event-bus/default`),
        DeadLetterConfig: Match.anyValue(),
      })],
    });
  });

  test('the audit account routes them into the stream with the other sources, from the workload account only', () => {
    const rules = Object.values(ingestion.findResources('AWS::Events::Rule', {
      Properties: { Name: INGESTION_RULE_NAMES.Detector },
    })) as any[];
    expect(rules).toHaveLength(1);
    const rule = rules[0].Properties;
    expect(rule.EventPattern).toEqual({
      source: [DETECTOR_SOURCE], 'detail-type': [DETECTOR_DETAIL_TYPE], account: [ACCOUNTS.workload],
    });
    const guardduty = Object.values(ingestion.findResources('AWS::Events::Rule', {
      Properties: { Name: INGESTION_RULE_NAMES.GuardDuty },
    })) as any[];
    expect(rule.Targets[0].Arn).toEqual(guardduty[0].Properties.Targets[0].Arn);    // the same stream
  });

  test('the audit account\'s bus admits the workload account\'s events with the detector\'s source and type alone', () => {
    const policies = Object.values(ingestion.findResources('AWS::Events::EventBusPolicy')) as any[];
    expect(policies).toHaveLength(1);
    const { Statement, EventBusName } = policies[0].Properties;
    expect(EventBusName).toBe('default');
    expect(Statement.Principal).toEqual({ AWS: `arn:aws:iam::${ACCOUNTS.workload}:root` });
    expect(Statement.Action).toBe('events:PutEvents');
    expect(Statement.Condition).toEqual({
      'ForAllValues:StringEquals': { 'events:source': [DETECTOR_SOURCE], 'events:detail-type': [DETECTOR_DETAIL_TYPE] },
    });
  });
});
