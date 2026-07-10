import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import { RemovalPolicy } from 'aws-cdk-lib/core';
import * as path from 'path';

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

    const siteBucket = new s3.Bucket(this, 'DashboardBucket', {
      bucketName: `cloudsentinel-dashboard-${this.account}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    const distribution = new cloudfront.Distribution(this, 'DashboardCdn', {
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
      sources: [s3deploy.Source.asset(path.join(__dirname, '../../../frontend/dist'))],
      destinationBucket: siteBucket,
      distribution,
      distributionPaths: ['/*'],
    });

    new cdk.CfnOutput(this, 'DashboardUrl', {
      value: `https://${distribution.distributionDomainName}`,
    });
    new cdk.CfnOutput(this, 'DashboardBucketName', { value: siteBucket.bucketName });
  }
}
