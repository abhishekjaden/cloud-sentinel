/**
 * Display logic for correlated incidents, kept apart from the component so it
 * can be tested without rendering.
 */
import type { Incident, Intel } from "./types";


/**
 * Severity bucket for a 0–100 score. The thresholds mirror the normalizer's,
 * so an incident reads the same as the findings it was built from.
 */
export function severityBucket(score: number): string {
  if (score >= 90) return "CRITICAL";
  if (score >= 70) return "HIGH";
  if (score >= 40) return "MEDIUM";
  if (score >= 1) return "LOW";
  return "INFO";
}

/** How long an attack ran, at a glance: "37s", "4m 10s", "2h 5m", "3d 4h". */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return s % 60 ? `${m}m ${s % 60}s` : `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return m % 60 ? `${h}h ${m % 60}m` : `${h}h`;
  const d = Math.floor(h / 24);
  return h % 24 ? `${d}d ${h % 24}h` : `${d}d`;
}

/**
 * How many findings an incident holds and how long they spanned. The correlator
 * stores whole seconds, so findings raised in the same instant — typical of a
 * sample batch — have a span of 0, which reads as broken if printed as "0s".
 */
export function describeSpan(count: number, seconds: number): string {
  if (count === 1) return "1 finding";
  if (seconds < 1) return `${count} findings within a second`;
  return `${count} findings over ${formatDuration(seconds)}`;
}

/** Kill-chain stage as an analyst reads it: "command-and-control" → "command and control". */
export function stageLabel(stage: string): string {
  return stage.replace(/-/g, " ");
}

/**
 * A Bedrock model ID as a reader would say it:
 * "us.anthropic.claude-haiku-4-5-20251001-v1:0" -> "Claude Haiku 4.5".
 * An ID in another form is shown as given rather than guessed at.
 */
export function modelLabel(id: string | undefined): string {
  if (!id) return "unknown model";
  const m = /claude-(haiku|sonnet|opus|fable)-(\d+)(?:-(\d{1,2}))?(?:-|$)/.exec(id);
  if (!m) return id;
  const family = m[1][0].toUpperCase() + m[1].slice(1);
  return `Claude ${family} ${m[3] ? `${m[2]}.${m[3]}` : m[2]}`;
}

/** Each indicator an incident names, addresses first, in the order recorded. */
export function indicatorsOf(incident: Incident): Array<{ kind: "ip" | "domain"; value: string }> {
  const found = incident.indicators;
  if (!found) return [];
  return [
    ...(found.ips ?? []).map((value) => ({ kind: "ip" as const, value })),
    ...(found.domains ?? []).map((value) => ({ kind: "domain" as const, value })),
  ];
}

/**
 * How a verdict reads on a chip, and the tone it is styled in. An indicator
 * the enricher has not reached yet says so rather than looking clean, and
 * "not listed" is deliberately not "clean": the feeds not having heard of an
 * address is not evidence about it.
 */
export function describeVerdict(intel: Intel | undefined): { text: string; tone: string; detail: string } {
  if (!intel) return { text: "not yet checked", tone: "pending", detail: "No threat-intelligence lookup has run for this indicator yet." };
  const parts: string[] = [];
  if (intel.abuseipdb) {
    parts.push(`AbuseIPDB: ${intel.abuseipdb.confidence}% confidence, ${intel.abuseipdb.reports} reports`
      + (intel.abuseipdb.country ? `, ${intel.abuseipdb.country}` : "")
      + (intel.abuseipdb.tor ? ", Tor exit" : ""));
  }
  if (intel.otx) parts.push(`OTX: ${intel.otx.pulses} pulse${intel.otx.pulses === 1 ? "" : "s"}`);
  if (intel.providers_failed?.length) parts.push(`${intel.providers_failed.join(", ")} did not answer`);
  const detail = parts.length ? parts.join(" · ") : "No provider answered.";
  switch (intel.verdict) {
    case "malicious": return { text: "malicious", tone: "malicious", detail };
    case "suspicious": return { text: "suspicious", tone: "suspicious", detail };
    case "not-listed": return { text: "not listed", tone: "unlisted", detail: `${detail} — not listed is not clean.` };
    default: return { text: "unknown", tone: "pending", detail };
  }
}

/** The file name a downloaded report gets, from the incident's ID. */
export function reportFilename(incidentId: string): string {
  return `cloudsentinel-incident-${incidentId.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 12)}.pdf`;
}

/** Hand a fetched file to the browser's download flow. */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
