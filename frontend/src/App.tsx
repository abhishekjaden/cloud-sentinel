import { useEffect, useState } from "react";
import { getStats, getFindings, getRemediations } from "./api";
import type { Stats, Finding, RemediationsResponse } from "./types";
import { StatsOverview } from "./components/StatsOverview";
import { FindingsTable } from "./components/FindingsTable";
import { RemediationsPanel } from "./components/RemediationsPanel";
import { PredictPanel } from "./components/PredictPanel";
import "./App.css";

export default function App() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [remediations, setRemediations] = useState<RemediationsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  async function loadAll() {
    try {
      setLoading(true);
      const [s, f, r] = await Promise.all([
        getStats(),
        getFindings(50),
        getRemediations(20),
      ]);
      setStats(s);
      setFindings(f.findings);
      setRemediations(r);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load data");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAll();
    const id = setInterval(loadAll, 30000); // auto-refresh every 30s
    return () => clearInterval(id);
  }, []);

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <span className="logo">◈</span>
          <div>
            <h1>CloudSentinel</h1>
            <p className="subtitle">Cloud Security Operations Center</p>
          </div>
        </div>
        <button className="refresh" onClick={loadAll} disabled={loading}>
          {loading ? "Loading…" : "↻ Refresh"}
        </button>
      </header>

      {error && <div className="error-banner">API error: {error}</div>}

      <main className="grid">
        <section className="panel span-2">
          <h2>Overview</h2>
          {stats ? <StatsOverview stats={stats} /> : <p className="muted">Loading stats…</p>}
        </section>

        <section className="panel span-2">
          <h2>Security Findings</h2>
          <FindingsTable findings={findings} />
        </section>

        <section className="panel">
          <h2>Remediation Activity</h2>
          {remediations ? (
            <RemediationsPanel data={remediations} />
          ) : (
            <p className="muted">Loading…</p>
          )}
        </section>

        <section className="panel">
          <h2>Threat Detection (ML)</h2>
          <PredictPanel />
        </section>
      </main>

      <footer className="footer">
        <span>CloudSentinel · AWS-native SOC platform</span>
        {stats && <span>{stats.total} findings monitored</span>}
      </footer>
    </div>
  );
}
