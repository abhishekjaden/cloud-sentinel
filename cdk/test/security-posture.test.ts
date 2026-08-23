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

  test('the deploy role trusts only the main branch of this repository', () => {
    t.hasResourceProperties('AWS::IAM::Role', {
      RoleName: 'CloudSentinelGitHubDeployRole',
      AssumeRolePolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Condition: Match.objectLike({
              StringEquals: Match.objectLike({
                'token.actions.githubusercontent.com:sub':
                  'repo:abhishekjaden/cloud-sentinel:ref:refs/heads/main',
              }),
            }),
          }),
        ]),
      }),
    });
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
