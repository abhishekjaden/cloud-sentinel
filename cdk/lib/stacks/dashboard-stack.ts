import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import { RemovalPolicy } from 'aws-cdk-lib/core';
import * as path from 'path';
import { suppressCdkManagedResources, suppressCloudFrontOptional, suppressCloudFrontTls } from '../nag-suppressions';

/**
 * DashboardStack — deploys to the Audit account (118821712739).
 *
 * Hosts the React SOC dashboard as a static site: private S3 bucket fronted by
 * CloudFront (HTTPS + CDN) via Origin Access Control. SPA routing handled by
 * rewriting 403/404 to index.html. The dashboard fetches /config.json at
 * runtime for the API URL, so the built artifact is not coupled to a backend.
 *
 * Cheap (pennies/mo, no NAT/ALB) — safe to leave running.
 */
export class DashboardStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const dashLogs = new s3.Bucket(this, 'DashboardAccessLogs', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      lifecycleRules: [{ expiration: cdk.Duration.days(90) }],
    });

        const siteBucket = new s3.Bucket(this, 'DashboardBucket', {
      enforceSSL: true,
      serverAccessLogsBucket: dashLogs,
      serverAccessLogsPrefix: 'dashboard/',
      bucketName: `cloudsentinel-dashboard-${this.account}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    const distribution = new cloudfront.Distribution(this, 'DashboardCdn', {
      // Refuse TLS 1.0/1.1 and SSLv3 for viewer connections.
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(siteBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
      defaultRootObject: 'index.html',
      // SPA: send routing errors back to index.html.
      errorResponses: [
        { httpStatus: 403, responseHttpStatus: 200, responsePagePath: '/index.html' },
        { httpStatus: 404, responseHttpStatus: 200, responsePagePath: '/index.html' },
      ],
    });

    // Deploy the built dashboard (frontend/dist) to the bucket, invalidate CDN.
    new s3deploy.BucketDeployment(this, 'DeployDashboard', {
      sources: [
        s3deploy.Source.asset(path.join(__dirname, '../../../frontend/dist')),
        // Generated here rather than shipped from the build: frontend/dist
        // carries a developer's local config.json, and deploying that would
        // point the live dashboard at localhost. Writing it at deploy time
        // means the artifact cannot be coupled to a local environment.
        s3deploy.Source.jsonData('config.json', {
          apiUrl: 'https://api.cloudsentinel-soc.com',
        }),
      ],
      destinationBucket: siteBucket,
      distribution,
      distributionPaths: ['/*'],
    });

    new cdk.CfnOutput(this, 'DashboardUrl', {
      value: `https://${distribution.distributionDomainName}`,
    });
    new cdk.CfnOutput(this, 'DashboardBucketName', { value: siteBucket.bucketName });

    suppressCdkManagedResources(this);
    suppressCloudFrontOptional(this);
    suppressCloudFrontTls(this);

  }
}
