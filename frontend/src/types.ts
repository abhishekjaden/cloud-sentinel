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
