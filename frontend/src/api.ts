import axios from "axios";
import type {
  FindingsResponse, Stats, RemediationsResponse, PredictResponse,
  ApprovalsResponse, DecisionResponse,
} from "./types";
import { loadApiBaseUrl } from "./config";
import { getToken } from "./auth";

async function client() {
  const baseURL = await loadApiBaseUrl();
  const token = getToken();
  return axios.create({
    baseURL,
    timeout: 15000,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
}

export async function getStats(): Promise<Stats> {
  const c = await client();
  const { data } = await c.get<Stats>("/stats");
  return data;
}

export async function getFindings(limit = 50, severityBucket?: string): Promise<FindingsResponse> {
  const c = await client();
  const params: Record<string, string | number> = { limit };
  if (severityBucket) params.severity_bucket = severityBucket;
  const { data } = await c.get<FindingsResponse>("/findings", { params });
  return data;
}

export async function getRemediations(limit = 20): Promise<RemediationsResponse> {
  const c = await client();
  const { data } = await c.get<RemediationsResponse>("/remediations", { params: { limit } });
  return data;
}

export async function predict(features: number[]): Promise<PredictResponse> {
  const c = await client();
  const { data } = await c.post<PredictResponse>("/predict", { features });
  return data;
}

export async function getApprovals(status = "pending"): Promise<ApprovalsResponse> {
  const c = await client();
  const { data } = await c.get<ApprovalsResponse>("/approvals", { params: { status } });
  return data;
}

/** Resume or abandon a staged remediation. The API attributes the decision to
 *  the authenticated principal; the caller cannot supply an identity. */
export async function decideApproval(
  approvalId: string,
  decision: "approve" | "reject",
  note?: string,
): Promise<DecisionResponse> {
  const c = await client();
  const { data } = await c.post<DecisionResponse>(
    `/approvals/${approvalId}/decide`, { decision, note },
  );
  return data;
}
