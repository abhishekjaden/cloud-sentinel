import { useEffect, useState } from "react";
import { getStats, getFindings, getRemediations } from "./api";
import type { Stats, Finding, RemediationsResponse } from "./types";
import { StatsOverview } from "./components/StatsOverview";
import { FindingsTable } from "./components/FindingsTable";
import { RemediationsPanel } from "./components/RemediationsPanel";
import { PredictPanel } from "./components/PredictPanel";
import { isAuthenticated, login, logout, handleRedirect } from "./auth";
import "./App.css";

export default function App() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [remediations, setRemediations] = useState<RemediationsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [authed, setAuthed] = useState(false);
  const [authChecking, setAuthChecking] = useState(true);

  async function loadAll() {
    try {
      setLoading(true);
      const [s, f, r] = await Promise.all([getStats(), getFindings(50), getRemediations(20)]);
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
    (async () => {
      await handleRedirect();
      const ok = isAuthenticated();
      setAuthed(ok);
      setAuthChecking(false);
      if (ok) loadAll();
    })();
  }, []);

  useEffect(() => {
    if (!authed) return;
    const id = setInterval(loadAll, 30000);
    return () => clearInterval(id);
  }, [authed]);

  if (authChecking) {
    return (
      <div className="app login-screen">
        <p className="muted">Checking session...</p>
      </div>
    );
  }

  if (!authed) {
    return (
      <div className="app login-screen">
        <div className="login-card">
          <h1>CloudSentinel</h1>
          <p className="subtitle">Cloud Security Operations Center</p>
          <p className="muted">Authorised operators only.</p>
          <button className="refresh" onClick={() => login()}>Sign in</button>
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <span className="logo">&#9672;</span>
          <div>
            <h1>CloudSentinel</h1>
            <p className="subtitle">Cloud Security Operations Center</p>
          </div>
        </div>
        <div className="header-actions">
          <button className="refresh" onClick={loadAll} disabled={loading}>
            {loading ? "Loading..." : "Refresh"}
          </button>
          <button className="logout" onClick={() => logout()}>Sign out</button>
        </div>
      </header>

      {error && <div className="error-banner">API error: {error}</div>}

      <main className="grid">
        <section className="panel span-2">
          <h2>Overview</h2>
          {stats ? <StatsOverview stats={stats} /> : <p className="muted">Loading stats...</p>}
        </section>

        <section className="panel span-2">
          <h2>Security Findings</h2>
          <FindingsTable findings={findings} />
        </section>

        <section className="panel">
          <h2>Remediation Activity</h2>
          {remediations ? <RemediationsPanel data={remediations} /> : <p className="muted">Loading...</p>}
        </section>

        <section className="panel">
          <h2>Threat Detection (ML)</h2>
          <PredictPanel />
        </section>
      </main>

      <footer className="footer">
        <span>CloudSentinel &middot; AWS-native SOC platform</span>
        {stats && <span>{stats.total} findings monitored</span>}
      </footer>
    </div>
  );
}
