import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import { RemovalPolicy, Duration } from 'aws-cdk-lib/core';
import { suppressLambdaBaseline, suppressCognitoTier } from '../nag-suppressions';

/**
 * AuthStack — deploys to the Audit account (118821712739).
 *
 * Cognito user pool guarding the SOC dashboard and API. A security dashboard
 * exposes the organisation's posture (critical findings, unpatched resources,
 * account IDs); it must not be world-readable.
 *
 * Design:
 *  - Hosted UI (not a hand-rolled login form): Cognito handles password policy,
 *    lockout, reset and MFA flows. Rolling your own auth on a security project
 *    is the wrong instinct.
 *  - Self sign-up DISABLED. Operators are created by an administrator; a SOC
 *    does not let strangers register.
 *  - The API validates the resulting JWT on every data request, so the login is
 *    not merely cosmetic — the endpoints cannot be reached by bypassing the UI.
 *  - Two roles, as groups. Every operator reads what the console shows; only a
 *    member of `approvers` can approve or reject a staged remediation. Cognito
 *    writes a user's groups into the tokens it issues, the API checks the claim
 *    on the decide route (backend/app/auth.py), and the console hides the
 *    buttons from everyone else. Membership is an administrator's call
 *    (README, "Operators"); a new user starts in no group and can decide
 *    nothing.
 */
/** The group the API requires on its decide route; the API stack names the same word. */
export const APPROVERS_GROUP = 'approvers';
export const ANALYSTS_GROUP = 'analysts';

export class AuthStack extends cdk.Stack {
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    this.userPool = new cognito.UserPool(this, 'SocUserPool', {
      userPoolName: 'cloudsentinel-soc',
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      autoVerify: { email: true },
      standardAttributes: {
        email: { required: true, mutable: false },
      },
      // The console can approve destructive remediation, so a stolen password
      // must not be sufficient on its own.
      mfa: cognito.Mfa.REQUIRED,
      mfaSecondFactor: { otp: true, sms: false },
      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // Hosted UI domain: <prefix>.auth.<region>.amazoncognito.com
    const domain = this.userPool.addDomain('SocUserPoolDomain', {
      cognitoDomain: { domainPrefix: 'cloudsentinel-soc' },
    });

    const callbackUrls = [
      'https://d2tb90osqfrb0m.cloudfront.net',
      'http://localhost:5173',
    ];

    this.userPoolClient = this.userPool.addClient('SocDashboardClient', {
      userPoolClientName: 'cloudsentinel-dashboard',
      generateSecret: false, // public SPA client — no secret can be kept secret in a browser
      authFlows: { userSrp: true },
      oAuth: {
        // Authorization code + PKCE: the current standard for public SPA
        // clients. Implicit grant is deprecated in OAuth 2.1 (tokens leak via
        // URL fragments, history and referrers) and has no place in a
        // security platform.
        flows: { authorizationCodeGrant: true },
        scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
        callbackUrls,
        logoutUrls: callbackUrls,
      },
      idTokenValidity: Duration.hours(1),
      accessTokenValidity: Duration.hours(1),
      refreshTokenValidity: Duration.days(30),
      preventUserExistenceErrors: true,
    });

    // The two roles. Precedence orders the groups in the token when a user is
    // in both; it carries no permission of its own.
    new cognito.CfnUserPoolGroup(this, 'ApproversGroup', {
      userPoolId: this.userPool.userPoolId,
      groupName: APPROVERS_GROUP,
      description: 'May approve or reject a staged remediation; every decision is recorded against the deciding identity',
      precedence: 10,
    });
    new cognito.CfnUserPoolGroup(this, 'AnalystsGroup', {
      userPoolId: this.userPool.userPoolId,
      groupName: ANALYSTS_GROUP,
      description: 'Reads findings, incidents, notes and the approval queue; cannot decide an approval',
      precedence: 20,
    });

    new cdk.CfnOutput(this, 'UserPoolId', { value: this.userPool.userPoolId });
    new cdk.CfnOutput(this, 'UserPoolClientId', { value: this.userPoolClient.userPoolClientId });
    new cdk.CfnOutput(this, 'HostedUiDomain', { value: domain.baseUrl() });
    new cdk.CfnOutput(this, 'JwksUrl', {
      value: `https://cognito-idp.${this.region}.amazonaws.com/${this.userPool.userPoolId}/.well-known/jwks.json`,
    });

    suppressLambdaBaseline(this);
    suppressCognitoTier(this);

  }
}
