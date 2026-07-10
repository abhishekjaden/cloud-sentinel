import { useState } from "react";
import type { Finding } from "../types";

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState<string>("ALL");

  const shown = filter === "ALL"
    ? findings
    : findings.filter((f) => f.severity_bucket === filter);

  const sorted = [...shown].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity_bucket) - SEV_ORDER.indexOf(b.severity_bucket),
  );

  return (
    <div className="findings-table">
      <div className="filter-row">
        {["ALL", ...SEV_ORDER].map((s) => (
          <button
            key={s}
            className={`filter-chip ${filter === s ? "active" : ""} sev-${s.toLowerCase()}`}
            onClick={() => setFilter(s)}
          >
            {s}
          </button>
        ))}
      </div>

      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Source</th>
              <th>Title</th>
              <th>Region</th>
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 ? (
              <tr><td colSpan={4} className="muted">No findings match.</td></tr>
            ) : (
              sorted.map((f, i) => (
                <tr key={f.finding_id + i}>
                  <td>
                    <span className={`sev-badge sev-${f.severity_bucket.toLowerCase()}`}>
                      {f.severity_bucket}
                    </span>
                  </td>
                  <td>{f.source}</td>
                  <td className="title-cell" title={f.title}>{f.title}</td>
                  <td>{f.region}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
