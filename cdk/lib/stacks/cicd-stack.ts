import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import { ACCOUNTS } from '../config';

const GITHUB_OWNER = 'abhishekjaden';
const GITHUB_REPO = 'cloud-sentinel';
const CDK_QUALIFIER = 'hnb659fds';

/**
 * CicdStack — deploys to the MANAGEMENT account (062345618950).
 *
 * Publishes the GitHub OIDC provider and two roles that GitHub Actions assumes
 * with short-lived, federated credentials. No IAM access keys are created and
 * nothing long-lived is stored in GitHub secrets.
 *
 * Trust is scoped to this repository specifically; a workflow in any other
 * repository (including a fork) presents a different `sub` claim and is denied.
 *
 *  - CiRole      any branch or pull request; may only read state (synth / diff)
 *  - DeployRole  main branch only; may assume the CDK deployment roles
 */
export class CicdStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const provider = new iam.OpenIdConnectProvider(this, 'GitHubOidcProvider', {
      url: 'https://token.actions.githubusercontent.com',
      clientIds: ['sts.amazonaws.com'],
    });

    const allAccounts = Object.values(ACCOUNTS);
    const cdkRole = (name: string) =>
      allAccounts.map((a) => `arn:aws:iam::${a}:role/cdk-${CDK_QUALIFIER}-${name}-${a}-${this.region}`);

    // ---- CI: any branch / PR, read-only ----------------------------------
    const ciRole = new iam.Role(this, 'GitHubCiRole', {
      roleName: 'CloudSentinelGitHubCiRole',
      description: 'Assumed by GitHub Actions to synth and diff CloudSentinel stacks',
      maxSessionDuration: cdk.Duration.hours(1),
      assumedBy: new iam.OpenIdConnectPrincipal(provider, {
        StringEquals: {
          'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
        },
        StringLike: {
          'token.actions.githubusercontent.com:sub': `repo:${GITHUB_OWNER}/${GITHUB_REPO}:*`,
        },
      }),
    });
    ciRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AssumeCdkLookupRoles',
      actions: ['sts:AssumeRole'],
      resources: cdkRole('lookup-role'),
    }));
    ciRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadStackStateForDiff',
      actions: [
        'cloudformation:DescribeStacks',
        'cloudformation:GetTemplate',
        'cloudformation:ListStacks',
      ],
      resources: ['*'],
    }));

    // ---- Deploy: main branch only ----------------------------------------
    const deployRole = new iam.Role(this, 'GitHubDeployRole', {
      roleName: 'CloudSentinelGitHubDeployRole',
      description: 'Assumed by GitHub Actions on main to deploy CloudSentinel stacks',
      maxSessionDuration: cdk.Duration.hours(1),
      assumedBy: new iam.OpenIdConnectPrincipal(provider, {
        StringEquals: {
          'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
          'token.actions.githubusercontent.com:sub':
            `repo:${GITHUB_OWNER}/${GITHUB_REPO}:ref:refs/heads/main`,
        },
      }),
    });
    deployRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AssumeCdkDeploymentRoles',
      actions: ['sts:AssumeRole'],
      resources: [
        ...cdkRole('deploy-role'),
        ...cdkRole('file-publishing-role'),
        ...cdkRole('image-publishing-role'),
        ...cdkRole('lookup-role'),
      ],
    }));

    new cdk.CfnOutput(this, 'CiRoleArn', { value: ciRole.roleArn });
    new cdk.CfnOutput(this, 'DeployRoleArn', { value: deployRole.roleArn });
  }
}
