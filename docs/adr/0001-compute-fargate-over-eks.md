# ADR 0001: ECS Fargate over EKS for the backend compute layer

## Status
Accepted

## Context
CloudSentinel's backend is a single containerized service (FastAPI: REST +
WebSocket) that must scale horizontally behind a load balancer under analyst
load. It has no multi-service orchestration, service-mesh, or pod-scheduling
requirements.

## Decision
Run the backend on ECS Fargate, not EKS.

## Rationale
- The workload is a single service. Kubernetes' value (complex orchestration,
  ecosystem, fine-grained scheduling, portability) is unused here.
- Fargate removes node management and carries no control-plane fee.
- Target-tracking auto-scaling on Fargate covers the scaling requirement
  directly.
- Choosing the right-sized tool, and being able to justify not reaching for
  Kubernetes, is the stronger engineering signal for this workload.

## Consequences
- Faster to ship; lower operational surface.
- If the architecture later grew to many interdependent services, EKS would be
  reconsidered.
- Kubernetes fluency is demonstrated elsewhere (KCNA, prior container work),
  so this project need not re-prove it.
