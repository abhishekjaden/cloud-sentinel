import axios from "axios";
import type {
  FindingsResponse, Stats, RemediationsResponse, PredictResponse,
} from "./types";
import { loadApiBaseUrl } from "./config";

async function client() {
  const baseURL = await loadApiBaseUrl();
  return axios.create({ baseURL, timeout: 15000 });
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
