/**
 * Physical names shared between stacks.
 *
 * The observability stack watches resources that other stacks own. It finds
 * them by name, the same way the stacks already share tables, rather than
 * through cross-stack references: an exported value cannot change while
 * another stack imports it, so exports would let the watching stack block
 * updates to the stacks it watches. Both sides import the names from here.
 */

/** The platform's own Lambda functions. */
export const FUNCTION_NAMES = {
  normalizer: 'CloudSentinel-Normalizer',
  correlator: 'CloudSentinel-Correlator',
  router: 'CloudSentinel-RemediationRouter',
  executor: 'CloudSentinel-RemediationExecutor',
  approvalRecorder: 'CloudSentinel-ApprovalRecorder',
  triage: 'CloudSentinel-Triage',
  enricher: 'CloudSentinel-Enricher',
} as const;

export const FINDINGS_STREAM_NAME = 'cloudsentinel-findings';

/**
 * Where Lambda reports batches the normalizer could not process, after its
 * retries. A message here is a finding CloudSentinel lost, which is what the
 * findings-stored objective alarms on.
 */
export const FAILED_FINDINGS_QUEUE_NAME = 'cloudsentinel-failed-findings';

/** One EventBridge rule per finding source, each routing into the stream. */
export const INGESTION_RULE_NAMES = {
  GuardDuty: 'cloudsentinel-guardduty-findings',
  SecurityHub: 'cloudsentinel-securityhub-findings',
  Inspector: 'cloudsentinel-inspector-findings',
} as const;

export const REMEDIATION_RULE_NAME = 'cloudsentinel-highsev-remediation';
export const TRIAGE_TABLE_NAME = 'cloudsentinel-triage';
/** Threat-intelligence verdicts by indicator, written only by the enricher. */
export const INTEL_TABLE_NAME = 'cloudsentinel-intel';
/** The providers' API keys, as a JSON secret the operator fills in. */
export const INTEL_SECRET_NAME = 'cloudsentinel/threat-intel';
export const STATE_MACHINE_NAME = 'cloudsentinel-remediation';
export const ALARM_TOPIC_NAME = 'cloudsentinel-alarms';

/**
 * Namespace for the metrics the Lambda handlers publish themselves, as
 * Embedded Metric Format log lines. The handler tests pin the same value.
 */
export const METRIC_NAMESPACE = 'CloudSentinel';

/**
 * The CDK bootstrap qualifier, which names the bootstrap roles in every
 * account: the CI/CD stack grants assumption of them, and the control-change
 * watch excludes CloudFormation acting through the execution role.
 */
export const CDK_QUALIFIER = 'hnb659fds';
