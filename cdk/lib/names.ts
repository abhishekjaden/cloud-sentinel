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
export const STATE_MACHINE_NAME = 'cloudsentinel-remediation';
export const ALARM_TOPIC_NAME = 'cloudsentinel-alarms';

/**
 * Namespace for the metrics the Lambda handlers publish themselves, as
 * Embedded Metric Format log lines. The handler tests pin the same value.
 */
export const METRIC_NAMESPACE = 'CloudSentinel';
