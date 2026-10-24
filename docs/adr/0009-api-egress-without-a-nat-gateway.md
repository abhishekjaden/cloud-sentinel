# ADR 0009: The API task gets its own address instead of a NAT gateway

## Status
Deferred, 2026-10-24, by the author. The Api stack runs on demand — a few
hours a week, torn down between sessions — and at that duty cycle the
gateway costs cents a session; the saving below is a saving on always-on
serving, which is not the plan at v2.0.0. The decision is taken up when
always-on serving is wanted: the change then ships with the Api stack, a
CDK test pins the new placement, and this status becomes *Accepted* with
the date. The numbers stand as written.

## Context
The Api stack places the one Fargate task in a private subnet of a two-AZ
VPC and gives it a NAT gateway for everything it reaches outward: the ECR
image at start-up, DynamoDB, CloudWatch Logs and X-Ray, and Cognito's JWKS
endpoint, from which the API fetches the signing keys it verifies every
token against. The load balancer sits in the public subnets and is the only
way in; the WAF sits in front of it.

The gateway is the single largest line of the serving layer. From the
September invoice (`docs/evaluation.md`, section 2), the API cost about
$2.25 a day while up: the NAT gateway $1.08, the load balancer $0.54, three
public IPv4 addresses $0.34, the task itself $0.28. The gateway is half; at
list price it is $0.045 an hour plus $0.045 a gigabyte processed, so about
$33 a month always on before data. The platform's cost ceiling is ₹5,000 a
month, and always-on serving is $93 a month net against that ceiling, which
is why the stack is deployed on demand and torn down between sessions.

What the gateway buys: the task has no address of its own, so nothing on the
internet can address it, whatever its security group says.

## Decision
Proposed: run the task in the public subnets with a public IPv4 address
(`assignPublicIp: true`) and no NAT gateway (`natGateways: 0`), with the
task's security group unchanged — it admits inbound traffic from the load
balancer's security group only. Keep the flow logs. Nothing else in the
stack moves.

## Rationale
- **The saving is the gateway's whole cost.** About $1.08 a day while up,
  or about $32 a month always on. The address line does not move: the
  gateway's public address goes and the task's arrives, three addresses
  either way. With the shard decision in ADR 0010 the always-on figure falls
  from about $93 to about $50 a month; on its own, from $93 to about $61.
- **The exposure it adds is bounded by the same control that already bounds
  the load balancer.** A public address is reachable only on ports the
  security group opens, and the task's group opens none to the internet;
  the inbound rule names the load balancer's group. The threat model's
  position does not change: the load balancer remains the only path to
  application data, and the WAF remains in front of it.
- **The alternative that keeps the task private costs more, not less.**
  Interface endpoints for ECR (two), CloudWatch Logs, X-Ray and Cognito are
  about $7.30 a month each at $0.01 an hour, before data; five of them cost
  more than the gateway they replace. The DynamoDB gateway endpoint is free
  and is worth adding either way, so that table traffic never leaves the
  VPC.

What is given up: the property that the task cannot be addressed from the
internet at all, independent of configuration. With a public address, a
mistaken security-group rule would expose the container's port; today it
would expose nothing. The infrastructure tests pin the group's rules, which
is the mitigation, and it is a test, not a topology.

## Consequences
- Always-on serving at about $61 a month net on this change alone; the Api
  stack's daily cost while up falls from about $2.25 to about $1.17.
- A CDK test asserts the task's `AssignPublicIp`, the absence of any NAT
  gateway in the template, and that the task's security group has exactly
  one inbound rule, from the load balancer's group.
- `docs/threat-model.md`, boundary B2, records the task's public address and
  the rule that bounds it; `docs/well-architected-review.md`, the cost
  pillar, records the saving against the measured figure.
- The flow logs continue to record what the task talks to, now including the
  internet gateway; the log group's retention is unchanged.
