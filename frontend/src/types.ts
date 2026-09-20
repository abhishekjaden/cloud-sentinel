// API response types — match the FastAPI backend shapes.

export interface Finding {
  pk: string;
  sk: string;
  finding_id: string;
  source: string;
  account_id: string;
  finding_type: string;
  raw_severity_label: string;
  severity_bucket: string;
  severity: number;
  region: string;
  title: string;
  created_at: string;
  resource?: string;
}

export interface FindingsResponse {
  count: number;
  findings: Finding[];
}

export interface Stats {
  total: number;
  by_severity_bucket: Record<string, number>;
  by_source: Record<string, number>;
}

/** Findings correlated into one attack: same resource, close together in time. */
export interface Incident {
  incident_id: string;
  account_id: string;
  resource: string;
  first_seen: string;
  last_seen: string;
  duration_seconds: number;
  finding_count: number;
  max_severity: number;
  /** Kill-chain order, earliest stage first. */
  attack_stages: string[];
  multi_stage: boolean;
  finding_types: string[];
  status: string;
  /** Built from GuardDuty sample findings rather than live traffic. */
  sample: boolean;
  /** Advisory note from the triage model; null until one has been written. */
  triage?: Triage | null;
}

/**
 * A triage note written by a language model. Advisory: nothing in the
 * platform acts on it. A note the model got wrong in shape is reported only as
 * rejected, with no content.
 */
export interface Triage {
  status: "complete" | "invalid_output";
  triaged_at: string;
  summary?: string;
  assessed_severity?: "critical" | "high" | "medium" | "low" | "informational";
  confidence?: "high" | "medium" | "low";
  likely_test_data?: boolean;
  injection_suspected?: boolean;
  reasons?: string[];
  next_steps?: string[];
  model_id?: string;
}

export interface IncidentsResponse {
  count: number;
  multi_stage: number;
  incidents: Incident[];
}

export interface RemediationExecution {
  name: string;
  status: string;
  started: string;
  stopped: string | null;
}

export interface RemediationsResponse {
  count: number;
  summary: Record<string, number>;
  executions: RemediationExecution[];
}

export interface PredictResponse {
  attack_probability: number;
  prediction: string;
  threshold: number;
}

export interface Approval {
  approval_id: string;
  status: string;
  created_at: string;
  finding_id: string;
  playbook: string;
  resource?: string;
  execution_arn?: string;
  decided_by?: string;
  decided_at?: string;
}

export interface ApprovalsResponse {
  count: number;
  approvals: Approval[];
}

export interface DecisionResponse {
  approval_id: string;
  status: string;
  decided_by: string;
  decided_at: string;
}
