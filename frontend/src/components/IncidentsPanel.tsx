import type { IncidentsResponse, Triage } from "../types";
import { describeSpan, modelLabel, severityBucket, stageLabel } from "../incidents";

/**
 * The model's triage note for one incident. Labelled advisory, because it is:
 * the computed severity and stages above it are the record, and nothing acts
 * on this. Rendered as plain text throughout — the note is model output
 * derived from attacker-influenced findings.
 */
function TriageNote({ note }: { note: Triage | null | undefined }) {
  if (!note) {
    return <p className="triage triage-none">AI triage: not yet run.</p>;
  }
  if (note.status !== "complete") {
    return (
      <p className="triage triage-none">
        AI triage: the model's answer was rejected; it is retried when the incident changes.
      </p>
    );
  }
  return (
    <section className="triage" aria-label="Advisory triage by a language model">
      <div className="triage-head">
        <span className="triage-title">AI triage · advisory</span>
        {note.assessed_severity && (
          <span className="triage-assessed">assessed {note.assessed_severity}</span>
        )}
        {note.confidence && <span className="triage-confidence">{note.confidence} confidence</span>}
        {note.injection_suspected && (
          <span className="incident-tag tag-injection"
            title="The findings contain text addressed to an AI system, itself a sign of an attacker. Read this note with extra care.">
            POSSIBLE PROMPT INJECTION
          </span>
        )}
        {note.likely_test_data && <span className="incident-tag tag-sample">LOOKS LIKE TEST DATA</span>}
      </div>
      <p className="triage-summary">{note.summary}</p>
      {note.next_steps && note.next_steps.length > 0 && (
        <ol className="triage-steps" aria-label="Suggested next steps">
          {note.next_steps.map((step, n) => <li key={n}>{step}</li>)}
        </ol>
      )}
      {note.reasons && note.reasons.length > 0 && (
        <details className="triage-reasons">
          <summary>Why</summary>
          <ul>{note.reasons.map((reason, n) => <li key={n}>{reason}</li>)}</ul>
        </details>
      )}
      <div className="triage-meta">
        {modelLabel(note.model_id)} · {new Date(note.triaged_at).toLocaleString()}
      </div>
    </section>
  );
}

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
                  {describeSpan(i.finding_count, i.duration_seconds)}
                  {" · first seen "}
                  {new Date(i.first_seen).toLocaleString()}
                </div>
                <TriageNote note={i.triage} />
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
