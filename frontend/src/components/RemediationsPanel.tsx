import type { RemediationsResponse } from "../types";

const STATUS_CLASS: Record<string, string> = {
  RUNNING: "status-running",
  SUCCEEDED: "status-succeeded",
  FAILED: "status-failed",
  TIMED_OUT: "status-timedout",
  ABORTED: "status-aborted",
};

export function RemediationsPanel({ data }: { data: RemediationsResponse }) {
  return (
    <div className="remediations-panel">
      <div className="summary-row">
        {Object.entries(data.summary).map(([status, count]) => (
          <div key={status} className={`summary-pill ${STATUS_CLASS[status] || ""}`}>
            <span className="summary-count">{count}</span>
            <span className="summary-status">{status}</span>
          </div>
        ))}
      </div>

      <ul className="exec-list">
        {data.executions.length === 0 ? (
          <li className="muted">No remediation executions yet.</li>
        ) : (
          data.executions.map((e) => (
            <li key={e.name} className="exec-item">
              <span className={`exec-dot ${STATUS_CLASS[e.status] || ""}`} />
              <div className="exec-info">
                <span className="exec-name">{e.name}</span>
                <span className="exec-time">{new Date(e.started).toLocaleString()}</span>
              </div>
              <span className="exec-status">{e.status}</span>
            </li>
          ))
        )}
      </ul>
      <p className="hint muted">RUNNING = awaiting human approval at the gate</p>
    </div>
  );
}
