/**
 * Security posture assertions.
 *
 * These tests encode the security decisions the platform depends on, so that a
 * later refactor cannot quietly undo them. Each one corresponds to a control
 * described in docs/well-architected-review.md.
 */
import * as cdk from 'aws-cdk-lib/core';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { ACCOUNTS, env } from '../lib/config';
import { DataStoresStack } from '../lib/stacks/datastores-stack';
import { DashboardStack } from '../lib/stacks/dashboard-stack';
import { AuthStack } from '../lib/stacks/auth-stack';
import { CicdStack } from '../lib/stacks/cicd-stack';
import { DnsStack } from '../lib/stacks/dns-stack';
import { ApiStack } from '../lib/stacks/api-stack';

const audit = { env: env(ACCOUNTS.audit) };
const management = { env: env(ACCOUNTS.management) };

function templateFor(factory: (app: cdk.App) => cdk.Stack): Template {
  const app = new cdk.App();
  return Template.fromStack(factory(app));
}

describe('DataStoresStack', () => {
  const t = templateFor((app) => new DataStoresStack(app, 'TestDataStores', audit));

  test('findings table has point-in-time recovery enabled', () => {
    t.hasResourceProperties('AWS::DynamoDB::Table', {
      PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
    });
  });

  test('findings table is server-side encrypted', () => {
    t.hasResourceProperties('AWS::DynamoDB::Table', {
      SSESpecification: Match.objectLike({ SSEEnabled: true }),
    });
  });

  test('the findings table carries the indexes the API reads it through', () => {
    // The API holds no dynamodb:Scan on this table, so an index missing or
    // renamed here is not a slower dashboard but an empty one.
    const [findings] = Object.values(t.findResources('AWS::DynamoDB::Table'))
      .map((r: any) => r.Properties).filter((p: any) => p.TableName === 'cloudsentinel-findings');
    const keys = Object.fromEntries((findings.GlobalSecondaryIndexes ?? [])
      .map((i: any) => [i.IndexName, i.KeySchema.map((k: any) => `${k.KeyType}:${k.AttributeName}`)]));

    expect(keys).toEqual({
      'severity-index': ['HASH:severity_bucket', 'RANGE:severity'],
      // sk, not created_at: an item that arrives without a created_at has the
      // attribute dropped, and an item missing a sort key is left out of the
      // index entirely rather than sorted oddly within it.
      'source-time-index': ['HASH:source', 'RANGE:sk'],
    });
  });

  test('every S3 bucket blocks all public access', () => {
    const buckets = t.findResources('AWS::S3::Bucket');
    expect(Object.keys(buckets).length).toBeGreaterThan(0);
    for (const [name, bucket] of Object.entries(buckets)) {
      expect(bucket.Properties.PublicAccessBlockConfiguration).toEqual({
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      });
      expect(name).toBeTruthy();
    }
  });
});

describe('DashboardStack', () => {
  const t = templateFor((app) => new DashboardStack(app, 'TestDashboard', audit));

  test('dashboard bucket is private and blocks public access', () => {
    t.hasResourceProperties('AWS::S3::Bucket', {
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      },
    });
  });

  test('CloudFront redirects all viewer traffic to HTTPS', () => {
    t.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        DefaultCacheBehavior: Match.objectLike({
          ViewerProtocolPolicy: 'redirect-to-https',
        }),
      }),
    });
  });

  test('the origin is reached through Origin Access Control, not a public bucket', () => {
    t.resourceCountIs('AWS::CloudFront::OriginAccessControl', 1);
  });
});

describe('AuthStack', () => {
  const t = templateFor((app) => new AuthStack(app, 'TestAuth', audit));

  test('self sign-up is disabled', () => {
    t.hasResourceProperties('AWS::Cognito::UserPool', {
      AdminCreateUserConfig: Match.objectLike({ AllowAdminCreateUserOnly: true }),
    });
  });

  test('password policy requires 12 characters and full complexity', () => {
    t.hasResourceProperties('AWS::Cognito::UserPool', {
      Policies: {
        PasswordPolicy: Match.objectLike({
          MinimumLength: 12,
          RequireLowercase: true,
          RequireUppercase: true,
          RequireNumbers: true,
          RequireSymbols: true,
        }),
      },
    });
  });

  test('the SPA client uses authorization-code flow, never the deprecated implicit grant', () => {
    t.hasResourceProperties('AWS::Cognito::UserPoolClient', {
      AllowedOAuthFlows: ['code'],
    });
  });

  test('the public SPA client is not issued a secret', () => {
    const clients = t.findResources('AWS::Cognito::UserPoolClient');
    const props = Object.values(clients).map((c: any) => c.Properties);
    expect(props.length).toBeGreaterThan(0);
    for (const p of props) {
      // A browser cannot keep a secret; the client must be public.
      expect(p.GenerateSecret).not.toBe(true);
    }
  });
});

describe('CicdStack', () => {
  const t = templateFor((app) => new CicdStack(app, 'TestCicd', management));

  test('the deploy role trusts only this repository, on main or the production environment', () => {
    const roles = t.findResources('AWS::IAM::Role');
    const deploy = Object.values(roles).find(
      (r: any) => r.Properties?.RoleName === 'CloudSentinelGitHubDeployRole');
    expect(deploy).toBeDefined();

    const subs: string[] = JSON.parse(JSON.stringify(deploy))
      .Properties.AssumeRolePolicyDocument.Statement
      .flatMap((st: any) => {
        const c = st.Condition?.['ForAnyValue:StringEquals'] ?? {};
        const v = c['token.actions.githubusercontent.com:sub'];
        return v ? (Array.isArray(v) ? v : [v]) : [];
      });

    expect(subs.length).toBeGreaterThan(0);
    // Every accepted subject must name this repository explicitly: a wildcard
    // here would let any repository's workflow assume the deployment role.
    for (const sub of subs) {
      expect(sub.startsWith('repo:abhishekjaden/cloud-sentinel:')).toBe(true);
      expect(sub).not.toContain('*');
    }
    expect(subs).toContain('repo:abhishekjaden/cloud-sentinel:ref:refs/heads/main');
  });

  test('every GitHub role verifies the sts.amazonaws.com audience', () => {
    const roles = t.findResources('AWS::IAM::Role');
    const github = Object.values(roles).filter((r: any) =>
      JSON.stringify(r).includes('token.actions.githubusercontent.com'));
    expect(github.length).toBe(2);
    for (const role of github) {
      expect(JSON.stringify(role)).toContain('sts.amazonaws.com');
    }
  });
});

describe('ApiStack', () => {
  const t = templateFor((app) => {
    const dns = new DnsStack(app, 'TestDns', audit);
    return new ApiStack(app, 'TestApi', {
      ...audit, apiZone: dns.apiZone, apiCertificate: dns.apiCertificate,
    });
  });

  test('the API can read correlated incidents but never write them', () => {
    // The correlator owns the incidents table. If the internet-facing API could
    // write to it, a compromised API task could rewrite or erase the record of
    // an attack in progress. A wildcard resource counts, since it covers the
    // table as much as naming it does.
    const statements = Object.values(t.findResources('AWS::IAM::Policy'))
      .flatMap((p: any) => p.Properties.PolicyDocument.Statement);
    const reaching = statements.filter((st: any) => {
      const r = JSON.stringify(st.Resource);
      return r.includes('cloudsentinel-incidents') || r === '"*"';
    });
    const actions = reaching.flatMap((st: any) => ([] as string[]).concat(st.Action));

    expect(actions).toEqual(expect.arrayContaining(['dynamodb:Query', 'dynamodb:Scan']));
    for (const write of ['dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem',
      'dynamodb:BatchWriteItem', 'dynamodb:*', '*']) {
      expect(actions).not.toContain(write);
    }
  });

  test('the API reads findings by key or by a named index, and cannot scan them', () => {
    // The routes stopped scanning so that a request would not cost the whole
    // table; keeping the permission would let the cost come back unnoticed, and
    // hand a compromised task the cheapest possible way to read every finding.
    const statements = Object.values(t.findResources('AWS::IAM::Policy'))
      .flatMap((p: any) => p.Properties.PolicyDocument.Statement)
      .filter((st: any) => JSON.stringify(st.Resource).includes('cloudsentinel-findings'));

    expect(statements.length).toBe(1);
    const [findings] = statements as any[];
    expect(findings.Action).toEqual(['dynamodb:Query', 'dynamodb:GetItem']);
    expect(findings.Resource).toEqual([
      expect.stringMatching(/table\/cloudsentinel-findings$/),
      expect.stringMatching(/index\/severity-index$/),
      expect.stringMatching(/index\/source-time-index$/),
    ]);
  });
});
