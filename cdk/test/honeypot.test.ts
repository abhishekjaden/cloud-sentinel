/**
 * The honeypot is attacked on purpose, so what matters is what an attacker who
 * succeeds would get: nothing worth having. These tests pin the properties
 * that make it worthless — no login that can succeed, one credential that can
 * only put files into one prefix of one bucket through the VPC's own endpoint,
 * one way out and that only to S3 — and keep it in its own network, away from
 * everything the platform owns. From generation 4 they also pin what the
 * capture keeps: headers, never payload, in files that outlive the stack.
 */
import * as cdk from 'aws-cdk-lib/core';
import { Template } from 'aws-cdk-lib/assertions';
import { ACCOUNTS, env } from '../lib/config';
import {
  CAPTURE_PREFIX, CAPTURE_PROGRAM, HONEYPOT_PORTS, INSTANCE_GENERATION, HoneypotStack, S3_PREFIX_LISTS, uploader,
} from '../lib/stacks/honeypot-stack';

// The flow-log destination adds the delivery service's bucket statements only
// under this flag, which cdk.json sets for every real synth; the test app sets
// it too, and a test below checks cdk.json still has it.
const LOGGING_POLICY_FLAG = '@aws-cdk/aws-s3:createDefaultLoggingPolicy';
const app = new cdk.App({ context: { [LOGGING_POLICY_FLAG]: true } });
const stack = new HoneypotStack(app, 'TestHoneypot', { env: env(ACCOUNTS.workload) });
const t = Template.fromStack(stack);
const only = (type: string) => {
  const found = Object.values(t.findResources(type)) as any[];
  expect(found).toHaveLength(1);
  return found[0].Properties;
};
/** The rendered user data: the bucket name and the Region are tokens, so the
 * template holds a Join; its literal parts are what the tests read. */
const render = (node: any): string => {
  if (typeof node === 'string') return node;
  if (node['Fn::Join']) return node['Fn::Join'][1].map(render).join(node['Fn::Join'][0]);
  if (node.Ref) return `\${${node.Ref}}`;
  return JSON.stringify(node);
};
const script = () => render(only('AWS::EC2::Instance').UserData['Fn::Base64']);

describe('the honeypot instance', () => {
  const instance = only('AWS::EC2::Instance');

  test('has no key pair and exactly one credential: the capture writer', () => {
    expect(instance.KeyName).toBeUndefined();
    expect(instance.IamInstanceProfile).toEqual({ Ref: expect.stringMatching(/^CaptureProfile/) });
    expect(Object.keys(t.findResources('AWS::IAM::InstanceProfile'))).toHaveLength(1);
    expect(Object.keys(t.findResources('AWS::IAM::Role')).filter((id) => !id.startsWith('VpcFlowLog'))).toHaveLength(1);
  });

  test('requires IMDSv2 with a hop limit of one, so metadata cannot be read through a web bug', () => {
    expect(instance.MetadataOptions).toEqual({
      HttpEndpoint: 'enabled', HttpTokens: 'required', HttpPutResponseHopLimit: 1,
    });
  });

  test('is small, encrypted and disposable', () => {
    expect(instance.InstanceType).toBe('t4g.nano');
    const [root] = instance.BlockDeviceMappings;
    expect(root.Ebs).toEqual(expect.objectContaining({ Encrypted: true, DeleteOnTermination: true }));
    expect(instance.DisableApiTermination).toBeUndefined();
  });

  test('serves its lure page as nobody, with the one capability that binding port 80 needs', () => {
    const s = script();
    expect(s).toContain('http.server 80');
    expect(s).toContain('User=nobody');
    expect(s).toContain('AmbientCapabilities=CAP_NET_BIND_SERVICE');
    expect(s).toContain('NoNewPrivileges=yes');
    // The script never installs or downloads anything: the only thing it can
    // reach is S3, and only to write.
    expect(s).not.toMatch(/dnf|yum|curl|wget|pip/);
  });

  test('takes SSH password attempts, so brute force happens, and lets none succeed', () => {
    // The first run refused passwords at the key exchange and drew no findings
    // in four and a half days. Asking for a password is what keeps a scanner
    // trying; every way an attempt could succeed is closed separately.
    const s = script();
    expect(s).toContain('/etc/ssh/sshd_config.d/00-honeypot.conf');
    expect(s).toContain('PasswordAuthentication yes');
    expect(s).toContain('PermitEmptyPasswords no');
    expect(s).toContain('PermitRootLogin no');
    expect(s).toContain('PubkeyAuthentication no');
    expect(s).toContain('AllowUsers honeypot-no-such-user');
    expect(s).toContain('passwd -l root');
    expect(s).toContain('passwd -l ec2-user');
    // Nothing gives any account a password, and no account is created.
    expect(s).not.toMatch(/chpasswd|useradd|adduser|passwd (?!-l )/);
    // A config that fails validation never replaces the running one.
    expect(s).toContain('sshd -t && systemctl restart sshd');
  });

  test('is replaced, not merely updated, when its first-boot script changes', () => {
    const [id] = Object.keys(t.findResources('AWS::EC2::Instance'));
    expect(id).toBe(`Instance${INSTANCE_GENERATION}`);
    expect(INSTANCE_GENERATION).toBe(4);
  });

  test('lives in the workload account, never beside the platform', () => {
    expect(stack.account).toBe(ACCOUNTS.workload);
  });
});

describe('the capture', () => {
  test('runs as nobody with the one capability a raw socket needs, and finishes its file when stopped', () => {
    const s = script();
    expect(s).toContain('ExecStart=/usr/bin/python3 /usr/local/bin/capture.py');
    expect(s).toContain('AmbientCapabilities=CAP_NET_RAW');
    expect(s).toContain('CapabilityBoundingSet=CAP_NET_RAW');
    expect(s).toContain('ExecStopPost=+/usr/local/bin/capture-upload final');
    expect(s).toContain('install -d -o nobody -g nobody -m 0750 /var/lib/capture');
    expect(s).toContain('systemctl enable --now lure-web.service capture.service capture-upload.timer');
  });

  test('keeps headers and never payload, in files that rotate every fifteen minutes', () => {
    // The record written is the frame cut at header_end: the TCP data offset,
    // the fixed UDP/ICMP header, or 64 bytes of a non-IP frame.
    expect(CAPTURE_PROGRAM).toContain('frame[:end]');
    expect(CAPTURE_PROGRAM).toContain('(frame[off + 12] >> 4) * 4');
    expect(CAPTURE_PROGRAM).toContain('ROTATE_SECONDS = 900');
    expect(CAPTURE_PROGRAM).toContain('0xA1B2C3D4');
    expect(CAPTURE_PROGRAM).not.toMatch(/import (?!os|socket|struct|time)/);   // standard library, nothing else
    expect(script()).toContain(CAPTURE_PROGRAM.split('\n')[1]);
  });

  test('uploads finished files under the instance id and deletes them only once S3 has them', () => {
    const s = uploader('bucket-name', 'us-east-1');
    expect(s).toContain(`s3://bucket-name/${CAPTURE_PREFIX}$ID/$(basename "$f")`);
    expect(s).toContain('--region us-east-1');
    expect(s).toMatch(/aws s3 cp .* && rm -f "\$f"/);
    expect(s).toContain('/sys/devices/virtual/dmi/id/board_asset_tag');
    expect(script()).toContain('OnUnitActiveSec=5min');
  });
});

describe('the capture writer', () => {
  const role = Object.values(t.findResources('AWS::IAM::Role')).find(
    (r: any) => r.Properties.Description?.includes('capture files')) as any;

  test('may put objects under the capture prefix through the endpoint, and do nothing else', () => {
    expect(role.Properties.AssumeRolePolicyDocument.Statement[0].Principal).toEqual({ Service: 'ec2.amazonaws.com' });
    expect(role.Properties.ManagedPolicyArns).toBeUndefined();
    const [policy] = role.Properties.Policies;
    const [statement] = policy.PolicyDocument.Statement;
    expect(policy.PolicyDocument.Statement).toHaveLength(1);
    expect(statement.Action).toBe('s3:PutObject');
    expect(JSON.stringify(statement.Resource)).toContain(`/${CAPTURE_PREFIX}*`);
    expect(statement.Condition).toEqual({ StringEquals: { 'aws:SourceVpce': { Ref: expect.stringMatching(/^VpcS3/) } } });
  });
});

describe('the capture bucket', () => {
  const bucket = only('AWS::S3::Bucket');
  const policy = only('AWS::S3::BucketPolicy').PolicyDocument.Statement as any[];

  test('is retained with its files when the stack is destroyed, and is never public', () => {
    const [id, resource] = Object.entries(t.findResources('AWS::S3::Bucket'))[0] as [string, any];
    expect(id).toMatch(/^Captures/);
    expect(resource.DeletionPolicy).toBe('Retain');
    expect(bucket.PublicAccessBlockConfiguration).toEqual({
      BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true,
    });
    expect(bucket.BucketEncryption.ServerSideEncryptionConfiguration[0].ServerSideEncryptionByDefault.SSEAlgorithm)
      .toBe('AES256');
  });

  test('refuses plain HTTP and refuses puts under the capture prefix from anywhere but the endpoint', () => {
    expect(policy.some((s) => s.Effect === 'Deny' && s.Condition?.Bool?.['aws:SecureTransport'] === 'false')).toBe(true);
    const gate = policy.find((s) => s.Sid === 'CapturesOnlyThroughTheEndpoint');
    expect(gate.Effect).toBe('Deny');
    expect(gate.Action).toBe('s3:PutObject');
    expect(gate.Condition).toEqual({ StringNotEquals: { 'aws:SourceVpce': { Ref: expect.stringMatching(/^VpcS3/) } } });
  });

  test('receives the flow logs too, every minute, so the record outlives the stack', () => {
    // The delivery service may write under flow-logs/ and read the ACL; the CDK
    // adds both statements under the createDefaultLoggingPolicy flag, which
    // cdk.json sets. Without them the flow log reports an access error.
    const cdkJson = JSON.parse(require('fs').readFileSync(require('path').join(__dirname, '..', 'cdk.json'), 'utf8'));
    expect(cdkJson.context[LOGGING_POLICY_FLAG]).toBe(true);
    const delivery = policy.filter((s) => s.Principal?.Service === 'delivery.logs.amazonaws.com');
    expect(delivery.map((s) => s.Action).sort()).toEqual([['s3:GetBucketAcl', 's3:ListBucket'], 's3:PutObject']);
    expect(JSON.stringify(delivery.find((s) => s.Action === 's3:PutObject').Resource)).toContain('flow-logs/AWSLogs/');
    const flow = only('AWS::EC2::FlowLog');
    expect(flow).toEqual(expect.objectContaining({
      TrafficType: 'ALL', ResourceType: 'VPC', LogDestinationType: 's3', MaxAggregationInterval: 60,
    }));
    expect(JSON.stringify(flow.LogDestination)).toContain('flow-logs/');
    expect(t.findResources('AWS::Logs::LogGroup')).toEqual({});
  });
});

describe('the lure security group', () => {
  const group = only('AWS::EC2::SecurityGroup');

  test('is open from the whole IPv4 internet on the scanned ports and nothing else', () => {
    const rules = group.SecurityGroupIngress.map((r: any) => [r.IpProtocol, r.FromPort, r.ToPort, r.CidrIp]);
    expect(rules).toEqual(HONEYPOT_PORTS.map((p) => ['tcp', p, p, '0.0.0.0/0']));
    expect(group.SecurityGroupIngress.some((r: any) => r.CidrIpv6)).toBe(false);
  });

  test('lets packets out to S3 on 443 and nowhere else, so a compromised instance can reach nothing but the bucket', () => {
    // A prefix-list rule is its own resource; the group itself carries no
    // egress rule, not even the placeholder the CDK writes for a group with
    // none.
    expect(group.SecurityGroupEgress).toBeUndefined();
    const egress = Object.values(t.findResources('AWS::EC2::SecurityGroupEgress')) as any[];
    expect(egress).toHaveLength(1);
    expect(egress[0].Properties).toEqual(expect.objectContaining({
      IpProtocol: 'tcp', FromPort: 443, ToPort: 443, DestinationPrefixListId: S3_PREFIX_LISTS['us-east-1'],
    }));
    expect(egress[0].Properties.CidrIp ?? egress[0].Properties.CidrIpv6).toBeUndefined();
  });
});

describe('the honeypot network', () => {
  test('is one public subnet with no NAT and no private subnet', () => {
    expect(Object.keys(t.findResources('AWS::EC2::Subnet'))).toHaveLength(1);
    expect(t.findResources('AWS::EC2::NatGateway')).toEqual({});
    t.hasResourceProperties('AWS::EC2::VPC', { CidrBlock: '10.99.0.0/24' });
  });

  test('reaches S3 through a gateway endpoint whose policy admits only puts under the capture prefix', () => {
    const endpoint = only('AWS::EC2::VPCEndpoint');
    expect(endpoint.VpcEndpointType).toBe('Gateway');
    expect(endpoint.ServiceName).toEqual({ 'Fn::Join': ['', ['com.amazonaws.', { Ref: 'AWS::Region' }, '.s3']] });
    const [statement] = endpoint.PolicyDocument.Statement;
    expect(endpoint.PolicyDocument.Statement).toHaveLength(1);
    expect(statement.Action).toBe('s3:PutObject');
    expect(JSON.stringify(statement.Resource)).toContain(`/${CAPTURE_PREFIX}*`);
  });

  test('refuses to synthesize for a Region whose S3 prefix list is not recorded', () => {
    expect(() => new HoneypotStack(new cdk.App(), 'Elsewhere', { env: { account: ACCOUNTS.workload, region: 'eu-west-1' } }))
      .toThrow(/No S3 prefix list is recorded for eu-west-1/);
  });
});
