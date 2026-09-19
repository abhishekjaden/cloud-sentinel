import type { IncidentsResponse } from "../types";
import { formatDuration, severityBucket, stageLabel } from "../incidents";

/**
 * Correlated incidents: several findings against one resource, close together
 * in time, shown as one attack with its stages in kill-chain order. This is
 * where an analyst starts — fewer items than the findings list, each already
 * telling a story.
 *
 * Takes its own error rather than sharing the dashboard's: a failure here must
 * not blank the panels that loaded.
 */
export function IncidentsPanel({ data, error }: {
  data: IncidentsResponse | null;
  error: string | null;
}) {
  if (error) return <p className="error-text">Could not load incidents: {error}</p>;
  if (!data) return <p className="muted">Loading incidents...</p>;

  const samples = data.incidents.filter((i) => i.sample).length;

  return (
    <div className="incidents-panel">
      <div className="summary-row">
        <div className="summary-pill">
          <span className="summary-count">{data.count}</span>
          <span className="summary-status">INCIDENTS</span>
        </div>
        <div className="summary-pill status-multistage">
          <span className="summary-count">{data.multi_stage}</span>
          <span className="summary-status">MULTI-STAGE</span>
        </div>
        {samples > 0 && (
          <div className="summary-pill status-sample">
            <span className="summary-count">{samples}</span>
            <span className="summary-status">FROM SAMPLES</span>
          </div>
        )}
      </div>

      {data.incidents.length === 0 ? (
        <p className="muted">No correlated incidents.</p>
      ) : (
        <ul className="incident-list">
          {data.incidents.map((i) => {
            const bucket = severityBucket(i.max_severity);
            return (
              <li key={i.incident_id} className="incident-card">
                <div className="incident-head">
                  <span className={`sev-badge sev-${bucket.toLowerCase()}`}>{bucket}</span>
                  <span className="incident-resource">{i.resource}</span>
                  {i.multi_stage && <span className="incident-tag tag-multi">MULTI-STAGE</span>}
                  {i.sample && (
                    <span className="incident-tag tag-sample"
                      title="Built from GuardDuty sample findings, not live traffic">
                      SAMPLE
                    </span>
                  )}
                </div>
                <ol className="stage-chain" aria-label="Attack stages in kill-chain order">
                  {i.attack_stages.map((s) => (
                    <li key={s}><span className="stage-pill">{stageLabel(s)}</span></li>
                  ))}
                </ol>
                <div className="incident-meta">
                  {i.finding_count === 1
                    ? "1 finding"
                    : `${i.finding_count} findings over ${formatDuration(i.duration_seconds)}`}
                  {" · first seen "}
                  {new Date(i.first_seen).toLocaleString()}
                </div>
              </li>
            );
          })}
        </ul>
      )}
      <p className="hint muted">
        Findings on one resource form one incident until a gap of more than 30 minutes.
      </p>
    </div>
  );
}
