import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
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
 *
 * Generation 4 (24 October 2026) adds the packet capture for the third run.
 */
export const INSTANCE_GENERATION = 4;

/**
 * Amazon's prefix list for S3 in each Region the project uses: the one
 * destination the honeypot's security group lets packets out to. The ids are
 * public constants, the same for every account; this one can be checked with
 * `aws ec2 describe-prefix-lists --filters Name=prefix-list-name,Values=com.amazonaws.us-east-1.s3`.
 * A lookup at synth time would need credentials for the workload account on
 * every machine that synthesizes, including CI; a constant does not.
 */
export const S3_PREFIX_LISTS: Record<string, string> = { 'us-east-1': 'pl-63a5400a' };

/** Every finished capture file lands under this prefix, one folder per instance. */
export const CAPTURE_PREFIX = 'captures/';

/**
 * HoneypotStack — deploys to the workload account (743181156000), on demand.
 *
 * One small instance that exists to be attacked, so the platform sees real
 * findings about real attackers: the triage evaluation gets cases nobody
 * wrote, the enricher gets addresses that are in the feeds
 * (docs/triage-eval-protocol.md), and — from the third run — the detector
 * gets flows from the one network it serves (docs/generalization-protocol.md).
 *
 * It is built to be worthless to whoever gets in. No key pair, and every
 * password locked: sshd takes password attempts — that is what makes brute
 * force happen where GuardDuty can see it — but root is refused and the only
 * user allowed to log in does not exist, so no attempt can succeed. IMDSv2
 * required, so the metadata service cannot be read through a web bug. Its
 * own VPC, one subnet, no NAT: nothing of the platform's shares a network
 * with it.
 *
 * Two of the first two runs' principles are deliberately relaxed in the
 * third, and this is the record of it. The instance held no credential of
 * any kind and could send nothing anywhere; now it holds one — a role that
 * can put objects under one prefix of one bucket and nothing else, usable
 * only through the VPC's own S3 endpoint — and its security group lets
 * packets out to Amazon's S3 address range on port 443 and to nothing else.
 * That is what it takes to get the packet headers off the instance before
 * the stack is destroyed; the second run's flow logs went with the stack. A
 * compromise, which no login allows, would gain the ability to write files
 * into the capture bucket: not to read or delete anything, and not to reach
 * the internet.
 *
 * What is captured is headers, never payload: the capture program cuts each
 * frame at the end of its transport header before writing it, so the
 * passwords attackers try are not kept. scripts/pcap_flows.py turns the
 * files into flows on the detector's schema.
 *
 * Run it for a week or two, then `cdk destroy CloudSentinel-Honeypot`. The
 * bucket is retained with its files. About ₹25 a day while it exists
 * (docs/triage-eval-protocol.md, section 1, has the second run's invoice).
 *
 * The first run (3–8 October 2026) refused password login at the key
 * exchange and drew no findings in four and a half days; scanners have little
 * reason to persist against an sshd that will not even ask
 * (docs/triage-eval-protocol.md). From the second run it asks, and fails.
 */
export class HoneypotStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const prefixList = S3_PREFIX_LISTS[this.region];
    if (!prefixList) {
      throw new Error(`No S3 prefix list is recorded for ${this.region}; add it to S3_PREFIX_LISTS in honeypot-stack.ts`);
    }

    // One public subnet in one AZ and nothing else: no private subnet, no
    // NAT gateway, so the only route out is the internet gateway — which the
    // security group below refuses to use for anything but S3.
    const vpc = new ec2.Vpc(this, 'Vpc', {
      ipAddresses: ec2.IpAddresses.cidr('10.99.0.0/24'),
      maxAzs: 1,
      natGateways: 0,
      subnetConfiguration: [{ name: 'public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 28 }],
    });

    // Where the captures and the flow logs go. Retained when the stack is
    // destroyed: the files are the point of the run, and the second run's
    // flow logs were lost with their log group. Deleted by hand, later, when
    // the record no longer needs them.
    const captures = new s3.Bucket(this, 'Captures', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: false,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    NagSuppressions.addResourceSuppressions(captures, [{
      id: 'AwsSolutions-S1',
      reason:
        'The bucket receives the honeypot instance\'s capture files and the ' +
        'VPC\'s flow logs and is read by the operator at the end of a run. ' +
        'Server access logs would record those few reads at the cost of a ' +
        'second bucket in a stack that is destroyed after each run.',
    }]);

    // The instance reaches S3 through the VPC's own endpoint and no other
    // way: the endpoint's policy admits only puts under the capture prefix,
    // the bucket refuses puts there from anywhere else, and the role below
    // can do nothing but those puts. Three statements of the same rule, each
    // enforced by a different service.
    const s3Endpoint = vpc.addGatewayEndpoint('S3', { service: ec2.GatewayVpcEndpointAwsService.S3 });
    s3Endpoint.addToPolicy(new iam.PolicyStatement({
      sid: 'PutCapturesOnly',
      principals: [new iam.AnyPrincipal()],
      actions: ['s3:PutObject'],
      resources: [captures.arnForObjects(`${CAPTURE_PREFIX}*`)],
    }));
    captures.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'CapturesOnlyThroughTheEndpoint',
      effect: iam.Effect.DENY,
      principals: [new iam.AnyPrincipal()],
      actions: ['s3:PutObject'],
      resources: [captures.arnForObjects(`${CAPTURE_PREFIX}*`)],
      conditions: { StringNotEquals: { 'aws:SourceVpce': s3Endpoint.vpcEndpointId } },
    }));

    // Every connection attempt, accepted or rejected, for the evaluation's
    // record of what the honeypot saw, and a second count of its flows to
    // check the captures against. GuardDuty reads flow logs on its own; this
    // copy is for people, and it outlives the stack with the bucket.
    vpc.addFlowLog('FlowLog', {
      destination: ec2.FlowLogDestination.toS3(captures, 'flow-logs/'),
      trafficType: ec2.FlowLogTrafficType.ALL,
      maxAggregationInterval: ec2.FlowLogMaxAggregationInterval.ONE_MINUTE,
    });

    const lure = new ec2.SecurityGroup(this, 'Lure', {
      vpc,
      description: 'CloudSentinel honeypot: open to the internet on scanned ports, egress to S3 only',
      allowAllOutbound: false,
    });
    for (const port of HONEYPOT_PORTS) {
      lure.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(port), `scanned port ${port}`);
    }
    // The one way out. Amazon's S3 address range on 443; the gateway endpoint
    // carries it, so the packets never cross the internet gateway.
    lure.addEgressRule(ec2.Peer.prefixList(prefixList), ec2.Port.tcp(443), 'S3, through the gateway endpoint');
    NagSuppressions.addResourceSuppressions(lure, [{
      id: 'AwsSolutions-EC23',
      reason:
        'This is a honeypot. Being reachable from the internet on commonly ' +
        'scanned ports is its purpose: the probes and brute-force attempts ' +
        'against it are the findings the triage evaluation and the enricher ' +
        'are fed. Nothing on the instance can be logged into or stolen, and ' +
        'its only outbound rule reaches S3 through the VPC endpoint, so a ' +
        'compromise could reach nothing else.',
    }]);

    // The one credential: puts under the capture prefix, through the
    // endpoint, and nothing else. No reads, no lists, no deletes.
    const writer = new iam.Role(this, 'CaptureWriter', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'CloudSentinel honeypot: may put capture files into one prefix of one bucket, via the VPC endpoint',
      inlinePolicies: {
        PutCaptures: new iam.PolicyDocument({
          statements: [new iam.PolicyStatement({
            actions: ['s3:PutObject'],
            resources: [captures.arnForObjects(`${CAPTURE_PREFIX}*`)],
            conditions: { StringEquals: { 'aws:SourceVpce': s3Endpoint.vpcEndpointId } },
          })],
        }),
      },
    });
    const profile = new iam.CfnInstanceProfile(this, 'CaptureProfile', { roles: [writer.roleName] });

    // Amazon Linux 2023 on Graviton: the cheapest instance that runs it, with
    // sshd listening. The web listener is the standard library's and the
    // capture is a standard-library program too, so nothing has to be
    // installed — the instance cannot reach a package repository anyway. The
    // AWS CLI the uploader uses is part of the image.
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
      // The capture: headers only, written as pcap, a new file every
      // fifteen minutes, as nobody with the one capability a raw socket needs.
      "cat > /usr/local/bin/capture.py <<'EOF'",
      ...CAPTURE_PROGRAM.split('\n'),
      'EOF',
      "cat > /usr/local/bin/capture-upload <<'EOF'",
      ...uploader(captures.bucketName, this.region).split('\n'),
      'EOF',
      'chmod 0755 /usr/local/bin/capture-upload',
      'install -d -o nobody -g nobody -m 0750 /var/lib/capture /var/lib/capture/live /var/lib/capture/done',
      "cat > /etc/systemd/system/capture.service <<'EOF'",
      '[Unit]', 'Description=honeypot headers-only packet capture', 'After=network-online.target',
      'Wants=network-online.target',
      '[Service]', 'ExecStart=/usr/bin/python3 /usr/local/bin/capture.py',
      // When the service stops — a reboot, a stop before the destroy — the
      // file being written is finished and sent with the rest. The "+" runs
      // that one step as root, like the timer's uploads, while the capture
      // itself stays nobody.
      'ExecStopPost=+/usr/local/bin/capture-upload final',
      'User=nobody', 'AmbientCapabilities=CAP_NET_RAW', 'CapabilityBoundingSet=CAP_NET_RAW',
      'NoNewPrivileges=yes', 'Restart=always', 'RestartSec=5',
      '[Install]', 'WantedBy=multi-user.target',
      'EOF',
      "cat > /etc/systemd/system/capture-upload.service <<'EOF'",
      '[Unit]', 'Description=honeypot capture upload', 'After=network-online.target',
      '[Service]', 'Type=oneshot', 'ExecStart=/usr/local/bin/capture-upload',
      'EOF',
      "cat > /etc/systemd/system/capture-upload.timer <<'EOF'",
      '[Unit]', 'Description=honeypot capture upload, every five minutes',
      '[Timer]', 'OnBootSec=3min', 'OnUnitActiveSec=5min', 'AccuracySec=30s',
      '[Install]', 'WantedBy=timers.target',
      'EOF',
      'systemctl daemon-reload',
      'systemctl enable --now lure-web.service capture.service capture-upload.timer',
      // SSH takes password attempts, so brute force happens, and lets none
      // succeed. Every password is locked (the image sets none; locking
      // makes it explicit), root is refused, keys are off, and the only user
      // allowed to log in does not exist. sshd uses the first value it reads
      // for each keyword, and this drop-in is read before the image's own.
      'passwd -l root',
      'passwd -l ec2-user',
      "cat > /etc/ssh/sshd_config.d/00-honeypot.conf <<'EOF'",
      'PasswordAuthentication yes',
      'KbdInteractiveAuthentication no',
      'PermitEmptyPasswords no',
      'PermitRootLogin no',
      'PubkeyAuthentication no',
      'AllowUsers honeypot-no-such-user',
      'MaxAuthTries 3',
      'LoginGraceTime 20',
      'EOF',
      'sshd -t && systemctl restart sshd',
      // The settings in force, and whether the capture is running, on the
      // serial console, so they can be read with get-console-output without
      // ever logging in.
      "sshd -T | grep -E '^(passwordauthentication|permitrootlogin|pubkeyauthentication|allowusers) ' | sed 's/^/honeypot-sshd: /' > /dev/console",
      "systemctl is-active capture.service capture-upload.timer | sed 's/^/honeypot-capture: /' > /dev/console",
    );

    // The L1 construct rather than ec2.Instance, which would create a role of
    // its own with more than the one statement above.
    const instance = new ec2.CfnInstance(this, 'Instance', {
      imageId: image.getImage(this).imageId,
      instanceType: 't4g.nano',
      iamInstanceProfile: profile.ref,
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
        { key: 'Purpose', value: 'honeypot: attacked on purpose, holds nothing, writes its captures to one bucket' },
      ],
    });
    // Both the subnet's route to the internet gateway and the gateway's
    // attachment must exist before the instance boots, or user data runs
    // before the subnet is reachable; the endpoint's route must exist before
    // the first upload is tried.
    instance.node.addDependency(vpc);
    instance.node.addDependency(s3Endpoint);
    instance.overrideLogicalId(`Instance${INSTANCE_GENERATION}`);
    NagSuppressions.addResourceSuppressions(instance, [
      {
        id: 'AwsSolutions-EC28',
        reason:
          'Detailed monitoring reports CPU and network every minute for a fee; ' +
          'what this instance is for is recorded by GuardDuty, the flow logs ' +
          'and its own capture, not by its own metrics.',
      },
      {
        id: 'AwsSolutions-EC29',
        reason:
          'The instance is meant to be destroyed after a week or two with the ' +
          'stack. Termination protection would make the one intended operation ' +
          'on it a two-step one, and it protects nothing of value.',
      },
    ]);

    // The flow-log delivery role's policy carries the usual log-group suffix,
    // and the writer's one statement names the bucket's objects with /*.
    suppressLambdaBaseline(this);

    new cdk.CfnOutput(this, 'InstanceId', { value: instance.ref });
    new cdk.CfnOutput(this, 'PublicIp', { value: instance.attrPublicIp });
    new cdk.CfnOutput(this, 'CaptureBucket', { value: captures.bucketName });
  }
}

/**
 * The capture program, written to the instance at first boot. Standard
 * library only (the image's Python is 3.9; nothing newer is used). It opens a
 * raw socket on every interface, and for each frame writes the pcap record
 * header and the frame cut at the end of its transport header — Ethernet, IP
 * and TCP/UDP/ICMP headers, never a byte of payload — then starts a new file
 * every fifteen minutes and moves the finished one where the uploader looks.
 */
export const CAPTURE_PROGRAM = `#!/usr/bin/python3
"""Headers-only packet capture for the CloudSentinel honeypot (generation 4)."""
import os
import socket
import struct
import time

ETH_P_ALL = 0x0003
SNAPLEN = 256            # the most a record can hold; a full set of headers is 134 bytes
LIVE = "/var/lib/capture/live"
DONE = "/var/lib/capture/done"
ROTATE_SECONDS = 900
FLUSH_SECONDS = 5


def header_end(frame):
    """Offset of the first payload byte: everything from there on is dropped."""
    n = len(frame)
    if n < 14:
        return n
    ethertype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if ethertype == 0x8100 and n >= 18:           # 802.1Q tag
        ethertype = struct.unpack("!H", frame[16:18])[0]
        off = 18
    if ethertype == 0x0800 and n >= off + 20:     # IPv4
        proto = frame[off + 9]
        off += (frame[off] & 0x0F) * 4
    elif ethertype == 0x86DD and n >= off + 40:   # IPv6, fixed header only
        proto = frame[off + 6]
        off += 40
    else:                                          # ARP and the like: the first bytes
        return min(n, 64)
    if proto == 6 and n >= off + 20:               # TCP: data offset
        return min(n, off + (frame[off + 12] >> 4) * 4)
    if proto in (17, 1, 58):                       # UDP, ICMP, ICMPv6
        return min(n, off + 8)
    return min(n, off)


def open_file():
    name = time.strftime("capture-%Y%m%dT%H%M%SZ.pcap", time.gmtime())
    path = os.path.join(LIVE, name)
    fh = open(path, "wb", buffering=1 << 16)
    fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, 1))   # pcap, microseconds, Ethernet
    return path, fh


def finish(path, fh):
    fh.close()
    os.replace(path, os.path.join(DONE, os.path.basename(path)))


def main():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.settimeout(FLUSH_SECONDS)
    path, fh = open_file()
    opened = flushed = time.time()
    while True:
        try:
            frame, _ = sock.recvfrom(65535)
            now = time.time()
            end = header_end(frame)
            fh.write(struct.pack("<IIII", int(now), int((now - int(now)) * 1e6), end, len(frame)) + frame[:end])
        except socket.timeout:
            now = time.time()
        if now - flushed >= FLUSH_SECONDS:
            fh.flush()
            flushed = now
        if now - opened >= ROTATE_SECONDS:
            finish(path, fh)
            path, fh = open_file()
            opened = now


if __name__ == "__main__":
    main()
`;

/**
 * The uploader, run every five minutes by a timer and once more when the
 * capture stops: every finished file goes to the bucket under the instance's
 * id (read from the board asset tag, which Nitro instances set to it) and is
 * deleted once S3 has it. `final` first finishes the file still being written.
 */
export function uploader(bucket: string, region: string): string {
  return `#!/bin/bash
# CloudSentinel honeypot: send finished capture files to the bucket.
set -u
if [ "\${1:-}" = "final" ]; then
  mv -f /var/lib/capture/live/*.pcap /var/lib/capture/done/ 2>/dev/null
fi
ID=$(cat /sys/devices/virtual/dmi/id/board_asset_tag 2>/dev/null || hostname)
for f in /var/lib/capture/done/*.pcap; do
  [ -e "$f" ] || continue
  aws s3 cp "$f" "s3://${bucket}/${CAPTURE_PREFIX}$ID/$(basename "$f")" --region ${region} --only-show-errors && rm -f "$f"
done
`;
}
