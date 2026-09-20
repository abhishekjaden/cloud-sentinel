/**
 * Triage containment.
 *
 * The triage function hands attacker-influenced text to a language model, so
 * what the function is able to do is the control that matters, not what the
 * model says. These tests pin its permissions: read incidents and findings,
 * invoke one model through one inference profile, write its own table — and
 * nothing that acts. They also pin that the notes it writes stay read-only to
 * everyone else.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib/core';
import { Template } from 'aws-cdk-lib/assertions';
import { ACCOUNTS, env } from '../lib/config';
import { TRIAGE_TABLE_NAME } from '../lib/names';
import { ApiStack } from '../lib/stacks/api-stack';
import { DataStoresStack } from '../lib/stacks/datastores-stack';
import { DnsStack } from '../lib/stacks/dns-stack';
import { TRIAGE_MODEL, TriageStack } from '../lib/stacks/triage-stack';

const audit = { env: env(ACCOUNTS.audit) };
// The app's own feature flags, as `cdk synth` applies them (see
// observability.test.ts). Every stack is added before the first template.
const { context } = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'cdk.json'), 'utf8'));
const app = new cdk.App({ context });
const stacks = {
  dataStores: new DataStoresStack(app, 'TestDataStores', audit),
  triage: new TriageStack(app, 'TestTriage', audit),
  api: (() => {
    const dns = new DnsStack(app, 'TestDns', audit);
    return new ApiStack(app, 'TestApi', { ...audit, apiZone: dns.apiZone, apiCertificate: dns.apiCertificate });
  })(),
};
const triage = Template.fromStack(stacks.triage);
const dataStores = Template.fromStack(stacks.dataStores);
const api = Template.fromStack(stacks.api);

const ACCOUNT_REGION = `us-east-1:${ACCOUNTS.audit}`;
const TABLE = (name: string) => `arn:aws:dynamodb:${ACCOUNT_REGION}:table/${name}`;
const PROFILE_ARN = `arn:aws:bedrock:${ACCOUNT_REGION}:inference-profile/${TRIAGE_MODEL.inferenceProfile}`;
const WRITES = ['dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem',
  'dynamodb:BatchWriteItem', 'dynamodb:*', '*'];

type Statement = { Action: string | string[]; Resource: any; Condition?: any; Sid?: string };
const statements = (t: Template): Statement[] =>
  Object.values(t.findResources('AWS::IAM::Policy'))
    .flatMap((p: any) => p.Properties.PolicyDocument.Statement);
const actionsOf = (st: Statement) => ([] as string[]).concat(st.Action);
const resourcesOf = (st: Statement) => ([] as any[]).concat(st.Resource).map((r) => JSON.stringify(r));

describe('the triage function', () => {
  const all = statements(triage);

  test('holds no permission beyond reading, one model and its own table', () => {
    // Anything outside this list — Step Functions, SNS, Lambda, IAM, EC2, S3 —
    // could turn a steered answer into an action.
    const allowed = new Set([
      'dynamodb:Scan', 'dynamodb:Query', 'dynamodb:PutItem',
      'kms:Decrypt', 'kms:Encrypt', 'kms:GenerateDataKey', 'kms:DescribeKey',
      'bedrock:InvokeModel',
      'xray:PutTraceSegments', 'xray:PutTelemetryRecords',
    ]);
    const granted = all.flatMap(actionsOf);
    expect(granted.length).toBeGreaterThan(0);
    expect(granted.filter((a) => !allowed.has(a))).toEqual([]);

    const roles = Object.values(triage.findResources('AWS::IAM::Role'));
    const managed = roles.flatMap((r: any) => r.Properties.ManagedPolicyArns ?? []);
    expect(JSON.stringify(managed)).not.toMatch(/AdministratorAccess|FullAccess|PowerUser/);
    expect(managed.every((m: any) => JSON.stringify(m).includes('AWSLambdaBasicExecutionRole'))).toBe(true);
  });

  test('writes only its own table', () => {
    const writing = all.filter((st) => actionsOf(st).some((a) => WRITES.includes(a)));
    expect(writing.length).toBeGreaterThan(0);
    for (const st of writing) {
      expect(resourcesOf(st)).toEqual([JSON.stringify(TABLE(TRIAGE_TABLE_NAME))]);
    }
  });

  test('reaches one model, only through its inference profile', () => {
    const invoking = all.filter((st) => actionsOf(st).some((a) => a.startsWith('bedrock:')));
    expect(invoking.flatMap(actionsOf)).toEqual(['bedrock:InvokeModel', 'bedrock:InvokeModel']);

    const direct = invoking.find((st) => !st.Condition)!;
    expect(resourcesOf(direct)).toEqual([JSON.stringify(PROFILE_ARN)]);

    // The foundation model's Region wildcard is safe only because of this
    // condition: without it, the model could be called directly in any Region.
    const routed = invoking.find((st) => st.Condition)!;
    expect(resourcesOf(routed)).toEqual([JSON.stringify(
      `arn:aws:bedrock:*::foundation-model/${TRIAGE_MODEL.foundationModel}`)]);
    expect(routed.Condition).toEqual({ StringEquals: { 'bedrock:InferenceProfileArn': PROFILE_ARN } });
  });

  test('uses the table key only through DynamoDB', () => {
    const keyUse = all.filter((st) => actionsOf(st).some((a) => a.startsWith('kms:')));
    expect(keyUse.length).toBeGreaterThan(0);
    for (const st of keyUse) {
      expect(st.Condition).toEqual({ StringEquals: { 'kms:ViaService': 'dynamodb.us-east-1.amazonaws.com' } });
    }
  });

  test('is configured with the model its permissions name', () => {
    const [fn] = Object.values(triage.findResources('AWS::Lambda::Function')) as any[];
    expect(fn.Properties.Environment.Variables.TRIAGE_MODEL_ID).toBe(TRIAGE_MODEL.inferenceProfile);
    expect(TRIAGE_MODEL.inferenceProfile.endsWith(TRIAGE_MODEL.foundationModel)).toBe(true);
    // A US profile keeps requests inside US Regions; a global one would not.
    expect(TRIAGE_MODEL.inferenceProfile.startsWith('us.')).toBe(true);
  });
});

describe('triage notes', () => {
  test('are encrypted with the customer-managed key and recoverable, like every table', () => {
    const tables = Object.values(dataStores.findResources('AWS::DynamoDB::Table')) as any[];
    const names = tables.map((t) => t.Properties.TableName);
    expect(names).toContain(TRIAGE_TABLE_NAME);
    for (const t of tables) {
      expect(t.Properties.SSESpecification).toEqual(expect.objectContaining({
        SSEEnabled: true, SSEType: 'KMS', KMSMasterKeyId: expect.anything(),
      }));
      expect(t.Properties.PointInTimeRecoverySpecification).toEqual({ PointInTimeRecoveryEnabled: true });
    }
  });

  test('are read-only to the API', () => {
    const reaching = statements(api).filter((st) =>
      resourcesOf(st).some((r) => r.includes(TRIAGE_TABLE_NAME) || r === '"*"'));
    const actions = reaching.flatMap(actionsOf);
    expect(actions).toContain('dynamodb:BatchGetItem');
    for (const write of WRITES) expect(actions).not.toContain(write);
  });
});
