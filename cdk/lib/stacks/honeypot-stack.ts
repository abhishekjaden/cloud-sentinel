import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as logs from 'aws-cdk-lib/aws-logs';
import { NagSuppressions } from 'cdk-nag';
import { suppressLambdaBaseline } from '../nag-suppressions';

/**
 * The ports the honeypot leaves open. Each is a port internet scanners try
 * constantly; GuardDuty reports a probe of an open port by a known scanner as
 * Recon:EC2/PortProbeUnprotectedPort and repeated SSH logins as
 * UnauthorizedAccess:EC2/SSHBruteForce. Only 22 and 80 have anything
 * listening; the rest are open at the security group and closed at the host,
 * which is enough for the flow logs GuardDuty reads to show the attempt.
 */
export const HONEYPOT_PORTS = [22, 23, 80, 443, 3306, 3389, 5900, 8080];

/**
 * User data runs once, at an instance's first boot, so changing it does
 * nothing to an instance that already exists. Bumping this replaces the
 * instance, which is the only way a changed script takes effect.
 */
export const INSTANCE_GENERATION = 2;

/**
 * HoneypotStack — deploys to the workload account (743181156000), on demand.
 *
 * One small instance that exists to be attacked, so the platform sees real
 * findings about real attackers: the triage evaluation gets cases nobody
 * wrote, and the enricher gets addresses that are in the feeds
 * (docs/triage-eval-protocol.md).
 *
 * It is built to be worthless to whoever gets in. No key pair and no password
 * login, so SSH cannot succeed; no instance role, so there is no credential
 * to steal; IMDSv2 required, so the metadata service cannot be read through a
 * web bug; no outbound rule at all, so a compromised instance could not reach
 * the internet, the rest of the account, or anything else — the security
 * group drops every packet it sends. Its own VPC, one subnet, no NAT: nothing
 * of the platform's shares a network with it.
 *
 * Run it for a week or two, then `cdk destroy CloudSentinel-Honeypot`. About
 * $3 a month while it exists.
 */
export class HoneypotStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // One public subnet in one AZ and nothing else: no private subnet, no
    // NAT gateway, so the only route out is the internet gateway — which the
    // security group below then refuses to use.
    const vpc = new ec2.Vpc(this, 'Vpc', {
      ipAddresses: ec2.IpAddresses.cidr('10.99.0.0/24'),
      maxAzs: 1,
      natGateways: 0,
      subnetConfiguration: [{ name: 'public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 28 }],
    });

    // Every connection attempt, accepted or rejected, for the evaluation's
    // record of what the honeypot saw. GuardDuty reads flow logs on its own;
    // this copy is for people.
    const flowLogs = new logs.LogGroup(this, 'FlowLogs', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    vpc.addFlowLog('FlowLog', {
      destination: ec2.FlowLogDestination.toCloudWatchLogs(flowLogs),
      trafficType: ec2.FlowLogTrafficType.ALL,
    });

    const lure = new ec2.SecurityGroup(this, 'Lure', {
      vpc,
      description: 'CloudSentinel honeypot: open to the internet on scanned ports, no egress',
      // No egress at all. With this false and no rule added, the CDK emits a
      // placeholder rule that matches nothing, and the group drops everything
      // the instance tries to send.
      allowAllOutbound: false,
    });
    for (const port of HONEYPOT_PORTS) {
      lure.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(port), `scanned port ${port}`);
    }
    NagSuppressions.addResourceSuppressions(lure, [{
      id: 'AwsSolutions-EC23',
      reason:
        'This is a honeypot. Being reachable from the internet on commonly ' +
        'scanned ports is its purpose: the probes and brute-force attempts ' +
        'against it are the findings the triage evaluation and the enricher ' +
        'are fed. Nothing on the instance can be logged into or stolen, and ' +
        'it has no outbound rule, so a compromise could not reach anything.',
    }]);

    // Amazon Linux 2023 on Graviton: the cheapest instance that runs it, with
    // sshd listening and password login off by default. The web listener is
    // the standard library's, so nothing has to be installed — the instance
    // could not download anything anyway.
    const image = ec2.MachineImage.latestAmazonLinux2023({ cpuType: ec2.AmazonLinuxCpuType.ARM_64 });
    const userData = ec2.UserData.forLinux();
    userData.addCommands(
      'mkdir -p /srv/www',
      "cat > /srv/www/index.html <<'EOF'",
      '<!doctype html><title>Internal portal</title><h1>Internal portal</h1><p>Staff login has moved.</p>',
      'EOF',
      "cat > /etc/systemd/system/lure-web.service <<'EOF'",
      '[Unit]', 'Description=honeypot web listener', 'After=network.target',
      '[Service]', 'ExecStart=/usr/bin/python3 -m http.server 80 --directory /srv/www',
      // An unprivileged user cannot bind port 80 on its own; the one
      // capability that allows it is granted, and nothing else.
      'User=nobody', 'AmbientCapabilities=CAP_NET_BIND_SERVICE',
      'CapabilityBoundingSet=CAP_NET_BIND_SERVICE', 'NoNewPrivileges=yes', 'Restart=always',
      '[Install]', 'WantedBy=multi-user.target',
      'EOF',
      'systemctl daemon-reload',
      'systemctl enable --now lure-web.service',
    );

    // The L1 construct rather than ec2.Instance, which would create an
    // instance role on its own. This instance holds no credential of any kind.
    const instance = new ec2.CfnInstance(this, 'Instance', {
      imageId: image.getImage(this).imageId,
      instanceType: 't4g.nano',
      networkInterfaces: [{
        deviceIndex: '0',
        associatePublicIpAddress: true,
        subnetId: vpc.publicSubnets[0].subnetId,
        groupSet: [lure.securityGroupId],
      }],
      metadataOptions: { httpTokens: 'required', httpEndpoint: 'enabled', httpPutResponseHopLimit: 1 },
      blockDeviceMappings: [{
        deviceName: '/dev/xvda',
        ebs: { volumeSize: 8, volumeType: 'gp3', encrypted: true, deleteOnTermination: true },
      }],
      userData: cdk.Fn.base64(userData.render()),
      tags: [
        { key: 'Name', value: 'cloudsentinel-honeypot' },
        { key: 'Purpose', value: 'honeypot: attacked on purpose, holds nothing, no egress' },
      ],
    });
    // Both the subnet's route to the internet gateway and the gateway's
    // attachment must exist before the instance boots, or user data runs
    // before the subnet is reachable.
    instance.node.addDependency(vpc);
    instance.overrideLogicalId(`Instance${INSTANCE_GENERATION}`);
    NagSuppressions.addResourceSuppressions(instance, [
      {
        id: 'AwsSolutions-EC28',
        reason:
          'Detailed monitoring reports CPU and network every minute for a fee; ' +
          'what this instance is for is recorded by GuardDuty and the flow logs, ' +
          'not by its own metrics.',
      },
      {
        id: 'AwsSolutions-EC29',
        reason:
          'The instance is meant to be destroyed after a week or two with the ' +
          'stack. Termination protection would make the one intended operation ' +
          'on it a two-step one, and it protects nothing of value.',
      },
    ]);

    // The flow-log delivery role's policy carries the usual log-group suffix.
    suppressLambdaBaseline(this);

    new cdk.CfnOutput(this, 'InstanceId', { value: instance.ref });
    new cdk.CfnOutput(this, 'PublicIp', { value: instance.attrPublicIp });
  }
}
