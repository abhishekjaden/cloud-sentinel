/**
 * The honeypot is attacked on purpose, so what matters is what an attacker who
 * succeeds would get: nothing. These tests pin the properties that make it
 * worthless — no credential, no login, no way out — and keep it in its own
 * network, away from everything the platform owns.
 */
import * as cdk from 'aws-cdk-lib/core';
import { Template } from 'aws-cdk-lib/assertions';
import { ACCOUNTS, env } from '../lib/config';
import { HONEYPOT_PORTS, HoneypotStack } from '../lib/stacks/honeypot-stack';

const app = new cdk.App();
const stack = new HoneypotStack(app, 'TestHoneypot', { env: env(ACCOUNTS.workload) });
const t = Template.fromStack(stack);
const only = (type: string) => {
  const found = Object.values(t.findResources(type)) as any[];
  expect(found).toHaveLength(1);
  return found[0].Properties;
};

describe('the honeypot instance', () => {
  const instance = only('AWS::EC2::Instance');

  test('holds no credential: no instance role, no key pair', () => {
    expect(instance.IamInstanceProfile).toBeUndefined();
    expect(instance.KeyName).toBeUndefined();
    // Nothing in the stack could give it one later, either.
    expect(t.findResources('AWS::IAM::InstanceProfile')).toEqual({});
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

  test('lives in the workload account, never beside the platform', () => {
    expect(stack.account).toBe(ACCOUNTS.workload);
  });
});

describe('the lure security group', () => {
  const group = only('AWS::EC2::SecurityGroup');

  test('is open from the whole IPv4 internet on the scanned ports and nothing else', () => {
    const rules = group.SecurityGroupIngress.map((r: any) => [r.IpProtocol, r.FromPort, r.ToPort, r.CidrIp]);
    expect(rules).toEqual(HONEYPOT_PORTS.map((p) => ['tcp', p, p, '0.0.0.0/0']));
    expect(group.SecurityGroupIngress.some((r: any) => r.CidrIpv6)).toBe(false);
  });

  test('allows no egress at all, so a compromised instance can reach nothing', () => {
    // The CDK writes one placeholder rule that matches no real traffic when a
    // group has egress disabled and no rules added.
    expect(group.SecurityGroupEgress).toEqual([expect.objectContaining({ CidrIp: '255.255.255.255/32' })]);
  });
});

describe('the honeypot network', () => {
  test('is one public subnet with no NAT and no private subnet', () => {
    expect(Object.keys(t.findResources('AWS::EC2::Subnet'))).toHaveLength(1);
    expect(t.findResources('AWS::EC2::NatGateway')).toEqual({});
    t.hasResourceProperties('AWS::EC2::VPC', { CidrBlock: '10.99.0.0/24' });
  });

  test('records every connection attempt, accepted or rejected', () => {
    t.hasResourceProperties('AWS::EC2::FlowLog', { TrafficType: 'ALL', ResourceType: 'VPC' });
  });
});
