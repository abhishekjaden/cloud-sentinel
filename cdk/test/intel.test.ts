/**
 * Enrichment scope.
 *
 * The enricher is the one component that sends anything outside the account:
 * the addresses and domains an incident names go to two threat-intelligence
 * providers. These tests pin what it can touch on the way — read incidents,
 * read and write its own cache table, read one secret — and that nothing in
 * its permissions could turn a provider's answer into an action or a change
 * to the record of an attack. They also pin the two bounds the handler is
 * deployed with: the per-run budget that keeps the free tiers unexhausted,
 * and the cache that makes a lookup a weekly event.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib/core';
import { Template } from 'aws-cdk-lib/assertions';
import { ACCOUNTS, env } from '../lib/config';
import { INTEL_SECRET_NAME, INTEL_TABLE_NAME } from '../lib/names';
import { DataStoresStack } from '../lib/stacks/datastores-stack';
import { IntelStack } from '../lib/stacks/intel-stack';

const audit = { env: env(ACCOUNTS.audit) };
const { context } = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'cdk.json'), 'utf8'));
const app = new cdk.App({ context });
const stacks = {
  dataStores: new DataStoresStack(app, 'TestDataStores', audit),
  intel: new IntelStack(app, 'TestIntel', audit),
};
const intel = Template.fromStack(stacks.intel);
const dataStores = Template.fromStack(stacks.dataStores);

const TABLE = (name: string) => `arn:aws:dynamodb:us-east-1:${ACCOUNTS.audit}:table/${name}`;
const WRITES = ['dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem',
  'dynamodb:BatchWriteItem', 'dynamodb:*', '*'];

type Statement = { Action: string | string[]; Resource: any; Condition?: any; Sid?: string };
const statements = (t: Template): Statement[] =>
  Object.values(t.findResources('AWS::IAM::Policy'))
    .flatMap((p: any) => p.Properties.PolicyDocument.Statement);
const actionsOf = (st: Statement) => ([] as string[]).concat(st.Action);
const resourcesOf = (st: Statement) => ([] as any[]).concat(st.Resource).map((r) => JSON.stringify(r));

describe('the enricher', () => {
  const all = statements(intel);

  test('holds no permission beyond reading incidents, its cache table and one secret', () => {
    const allowed = new Set([
      'dynamodb:Scan', 'dynamodb:BatchGetItem', 'dynamodb:PutItem',
      'kms:Decrypt', 'kms:Encrypt', 'kms:GenerateDataKey', 'kms:DescribeKey',
      'secretsmanager:GetSecretValue',
      'xray:PutTraceSegments', 'xray:PutTelemetryRecords',
    ]);
    const granted = all.flatMap(actionsOf);
    expect(granted.length).toBeGreaterThan(0);
    expect(granted.filter((a) => !allowed.has(a))).toEqual([]);

    const roles = Object.values(intel.findResources('AWS::IAM::Role'));
    const managed = roles.flatMap((r: any) => r.Properties.ManagedPolicyArns ?? []);
    expect(JSON.stringify(managed)).not.toMatch(/AdministratorAccess|FullAccess|PowerUser/);
    expect(managed.every((m: any) => JSON.stringify(m).includes('AWSLambdaBasicExecutionRole'))).toBe(true);
  });

  test('writes only its own table, and reads incidents without being able to change them', () => {
    const writing = all.filter((st) => actionsOf(st).some((a) => WRITES.includes(a)));
    expect(writing.length).toBeGreaterThan(0);
    for (const st of writing) {
      expect(resourcesOf(st)).toEqual([JSON.stringify(TABLE(INTEL_TABLE_NAME))]);
    }
    const incidents = all.filter((st) => resourcesOf(st).some((r) => r.includes('cloudsentinel-incidents')));
    expect(incidents.flatMap(actionsOf)).toEqual(['dynamodb:Scan']);
  });

  test('reads one secret, the one holding the provider keys', () => {
    const secrets = all.filter((st) => actionsOf(st).some((a) => a.startsWith('secretsmanager:')));
    expect(secrets.flatMap(actionsOf)).toEqual(['secretsmanager:GetSecretValue']);
    const [secret] = Object.values(intel.findResources('AWS::SecretsManager::Secret')) as any[];
    expect(secret.Properties.Name).toBe(INTEL_SECRET_NAME);
    // The statement names the secret resource, not a wildcard or a prefix.
    expect(resourcesOf(secrets[0])).toEqual([expect.stringContaining('"Ref"')]);
  });

  test('is created without keys, so the stack deploys before the operator has any', () => {
    const [secret] = Object.values(intel.findResources('AWS::SecretsManager::Secret')) as any[];
    const template = JSON.parse(secret.Properties.GenerateSecretString.SecretStringTemplate);
    expect(template).toEqual({ abuseipdb_api_key: '', otx_api_key: '' });
    expect(secret.Properties.GenerateSecretString.GenerateStringKey).toBe('placeholder');
  });

  test('uses the table key only through DynamoDB', () => {
    const keyUse = all.filter((st) => actionsOf(st).some((a) => a.startsWith('kms:')));
    expect(keyUse.length).toBeGreaterThan(0);
    for (const st of keyUse) {
      expect(st.Condition).toEqual({ StringEquals: { 'kms:ViaService': 'dynamodb.us-east-1.amazonaws.com' } });
    }
  });

  test('is bounded: ten lookups a run, a week in the cache, retried within the hour on failure', () => {
    const [fn] = Object.values(intel.findResources('AWS::Lambda::Function')) as any[];
    const vars = fn.Properties.Environment.Variables;
    // 10 a run × 96 runs a day stays under AbuseIPDB's 1,000 free checks.
    expect(Number(vars.MAX_LOOKUPS_PER_RUN) * 96).toBeLessThan(1000);
    expect(vars.INTEL_CACHE_DAYS).toBe('7');
    expect(vars.INTEL_RETRY_HOURS).toBe('1');
    expect(vars.INTEL_TABLE).toBe(INTEL_TABLE_NAME);
    expect(vars.INTEL_SECRET_ID).toBe(INTEL_SECRET_NAME);
    expect(fn.Properties.Timeout).toBeGreaterThanOrEqual(Number(vars.MAX_LOOKUPS_PER_RUN) * 2 * 6);
  });

  test('runs on a schedule and is not placed in a VPC', () => {
    intel.hasResourceProperties('AWS::Events::Rule', { ScheduleExpression: 'rate(15 minutes)' });
    const [fn] = Object.values(intel.findResources('AWS::Lambda::Function')) as any[];
    // A VPC without a NAT gateway would cut the function off from the
    // providers silently; outside one, Lambda has the internet access it needs.
    expect(fn.Properties.VpcConfig).toBeUndefined();
  });
});

describe('the intel table', () => {
  test('expires its rows, and is encrypted and recoverable like every table', () => {
    const tables = Object.values(dataStores.findResources('AWS::DynamoDB::Table')) as any[];
    const table = tables.find((t) => t.Properties.TableName === INTEL_TABLE_NAME);
    expect(table).toBeDefined();
    expect(table.Properties.TimeToLiveSpecification).toEqual({ AttributeName: 'expires_at', Enabled: true });
    expect(table.Properties.KeySchema).toEqual([{ AttributeName: 'indicator', KeyType: 'HASH' }]);
    expect(table.Properties.SSESpecification).toEqual(expect.objectContaining({ SSEEnabled: true, SSEType: 'KMS' }));
    expect(table.Properties.PointInTimeRecoverySpecification).toEqual({ PointInTimeRecoveryEnabled: true });
  });
});
