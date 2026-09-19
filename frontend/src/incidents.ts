/**
 * Display logic for correlated incidents, kept apart from the component so it
 * can be tested without rendering.
 */

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

/** Kill-chain stage as an analyst reads it: "command-and-control" → "command and control". */
export function stageLabel(stage: string): string {
  return stage.replace(/-/g, " ");
}
