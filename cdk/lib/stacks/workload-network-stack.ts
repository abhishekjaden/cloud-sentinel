import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import { Network } from '../constructs/network';

/**
 * WorkloadNetworkStack — deploys to the workload account (743181156000).
 * Provides the VPC, subnets, NAT, and Flow Logs that the backend,
 * ML targets, and (later) attack-sim resources run in.
 */
export class WorkloadNetworkStack extends cdk.Stack {
  public readonly network: Network;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    this.network = new Network(this, 'Network');

    new cdk.CfnOutput(this, 'VpcId', {
      value: this.network.vpc.vpcId,
      description: 'CloudSentinel workload VPC ID',
    });
  }
}
