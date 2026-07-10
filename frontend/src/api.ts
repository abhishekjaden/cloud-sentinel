import axios from "axios";
import type {
  FindingsResponse, Stats, RemediationsResponse, PredictResponse,
} from "./types";

const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const client = axios.create({ baseURL: BASE_URL, timeout: 15000 });

export async function getStats(): Promise<Stats> {
  const { data } = await client.get<Stats>("/stats");
  return data;
}

export async function getFindings(limit = 50, severityBucket?: string): Promise<FindingsResponse> {
  const params: Record<string, string | number> = { limit };
  if (severityBucket) params.severity_bucket = severityBucket;
  const { data } = await client.get<FindingsResponse>("/findings", { params });
  return data;
}

export async function getRemediations(limit = 20): Promise<RemediationsResponse> {
  const { data } = await client.get<RemediationsResponse>("/remediations", { params: { limit } });
  return data;
}

export async function predict(features: number[]): Promise<PredictResponse> {
  const { data } = await client.post<PredictResponse>("/predict", { features });
  return data;
}
