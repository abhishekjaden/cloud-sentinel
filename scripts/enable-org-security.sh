#!/usr/bin/env bash
# CloudSentinel - org-wide member auto-enable for security services.
# Run with the AUDIT (delegated admin) profile. Idempotent: safe to re-run.
# All member accounts (current + future, incl. workload) auto-enroll.
set -euo pipefail

PROFILE="cs-audit"
REGION="us-east-1"

echo "==> GuardDuty: auto-enable members"
DETECTOR_ID=$(aws guardduty list-detectors --profile "$PROFILE" --region "$REGION" --query 'DetectorIds[0]' --output text)
aws guardduty update-organization-configuration --detector-id "$DETECTOR_ID" --auto-enable-organization-members ALL --profile "$PROFILE" --region "$REGION"
echo "    detector $DETECTOR_ID set to auto-enable ALL"

echo "==> Security Hub: auto-enable members + default standards"
aws securityhub update-organization-configuration --auto-enable --auto-enable-standards DEFAULT --profile "$PROFILE" --region "$REGION"

echo "==> Macie: auto-enable members"
aws macie2 update-organization-configuration --auto-enable --profile "$PROFILE" --region "$REGION"

echo "==> Inspector v2: auto-enable members (EC2, ECR, Lambda)"
aws inspector2 update-organization-configuration --auto-enable ec2=true,ecr=true,lambda=true --profile "$PROFILE" --region "$REGION"

echo "==> Detective: auto-enable members"
GRAPH_ARN=$(aws detective list-graphs --profile "$PROFILE" --region "$REGION" --query 'GraphList[0].Arn' --output text)
if [ "$GRAPH_ARN" != "None" ] && [ -n "$GRAPH_ARN" ]; then
  aws detective update-organization-configuration --graph-arn "$GRAPH_ARN" --auto-enable --profile "$PROFILE" --region "$REGION"
  echo "    graph $GRAPH_ARN set to auto-enable"
else
  echo "    no Detective graph yet - skipping"
fi

echo "==> Done. All available services set to auto-enable org members."
