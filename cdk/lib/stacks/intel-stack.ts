import * as cdk from 'aws-cdk-lib/core';
import { Duration } from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as path from 'path';
import { suppressLambdaBaseline, suppressThirdPartyKeyRotation } from '../nag-suppressions';
import { FUNCTION_NAMES, INTEL_SECRET_NAME, INTEL_TABLE_NAME } from '../names';

/**
 * IntelStack — deploys to the Audit account (118821712739).
 *
 * Threat-intelligence enrichment of the addresses and domains that open
 * incidents name (docs/adr/0006-threat-intel-enrichment.md). A scheduled
 * function asks AbuseIPDB and AlienVault OTX about each indicator once,
 * keeps the verdict in a cache table for a week, and bounds itself to a few
 * lookups a run so the providers' free tiers are never exhausted.
 *
 * Its own stack, like triage, because it is the one component that sends
 * anything outside the account: the indicator itself goes to two third
 * parties. It can be destroyed without touching detection, correlation,
 * triage or response, and nothing else depends on its table existing.
 *
 * The function's permissions are the scope. It reads incidents, reads and
 * writes its own cache table, and reads one secret. It cannot write an
 * incident, a finding or a note, and holds nothing that acts.
 */
export class IntelStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const table = (name: string) => `arn:aws:dynamodb:${this.region}:${this.account}:table/${name}`;

    // The providers' API keys. Created with placeholder values so the stack
    // deploys without them; the enricher treats an empty key as "provider not
    // configured" and the operator fills the real ones in:
    //   aws secretsmanager put-secret-value --secret-id cloudsentinel/threat-intel \
    //     --secret-string '{"abuseipdb_api_key":"...","otx_api_key":"..."}'
    const keys = new secretsmanager.Secret(this, 'ThreatIntelKeys', {
      secretName: INTEL_SECRET_NAME,
      description: 'CloudSentinel: AbuseIPDB and AlienVault OTX API keys for the enricher',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ abuseipdb_api_key: '', otx_api_key: '' }),
        // A generated value has to land somewhere; this key is never read.
        generateStringKey: 'placeholder',
        excludePunctuation: true,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    suppressThirdPartyKeyRotation(keys);

    const enricher = new lambda.Function(this, 'Enricher', {
      functionName: FUNCTION_NAMES.enricher,
      tracing: lambda.Tracing.ACTIVE,
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../lambda/enricher')),
      // At most MAX_LOOKUPS_PER_RUN indicators a run, two providers each, six
      // seconds a call: two minutes covers the worst case with room.
      timeout: Duration.minutes(2),
      memorySize: 256,
      environment: {
        INCIDENTS_TABLE: 'cloudsentinel-incidents',
        INTEL_TABLE: INTEL_TABLE_NAME,
        INTEL_SECRET_ID: INTEL_SECRET_NAME,
        // Ten a run, ninety-six runs a day: under AbuseIPDB's thousand free
        // checks even if every run finds something new to ask about.
        MAX_LOOKUPS_PER_RUN: '10',
        INTEL_CACHE_DAYS: '7',
        INTEL_RETRY_HOURS: '1',
      },
      description: 'Looks up the addresses and domains open incidents name in threat-intelligence feeds',
    });

    // Written out action by action rather than through the grant helpers,
    // which would add batch writes, stream reads and every index.
    enricher.addToRolePolicy(new iam.PolicyStatement({
      sid: 'ReadIncidents',
      actions: ['dynamodb:Scan'],
      resources: [table('cloudsentinel-incidents')],
    }));
    enricher.addToRolePolicy(new iam.PolicyStatement({
      sid: 'KeepIntelVerdicts',
      actions: ['dynamodb:BatchGetItem', 'dynamodb:PutItem'],
      resources: [table(INTEL_TABLE_NAME)],
    }));
    // Both tables share the findings key.
    enricher.addToRolePolicy(new iam.PolicyStatement({
      sid: 'UseFindingsKeyThroughDynamoDB',
      actions: ['kms:Decrypt', 'kms:Encrypt', 'kms:GenerateDataKey', 'kms:DescribeKey'],
      resources: [cdk.Fn.importValue('CloudSentinelFindingsKeyArn')],
      conditions: {
        StringEquals: { 'kms:ViaService': `dynamodb.${this.region}.amazonaws.com` },
      },
    }));
    enricher.addToRolePolicy(new iam.PolicyStatement({
      sid: 'ReadProviderKeys',
      actions: ['secretsmanager:GetSecretValue'],
      resources: [keys.secretArn],
    }));

    // Every fifteen minutes, like the correlator and triage. Nothing orders
    // the three: an indicator a new incident names is looked up on the next
    // run, and the note the triage model writes is rewritten once the
    // verdict changes the incident's fingerprint.
    const schedule = new events.Rule(this, 'EnrichmentSchedule', {
      ruleName: 'cloudsentinel-enrichment',
      schedule: events.Schedule.rate(Duration.minutes(15)),
      targets: [new targets.LambdaFunction(enricher)],
    });
    // Nothing is routed to a function until its log group exists (see the
    // ingestion stack).
    schedule.node.addDependency(enricher.logGroup);

    suppressLambdaBaseline(this);
  }
}
