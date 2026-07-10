import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import type { Stats } from "../types";

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#e5484d",
  HIGH: "#f76808",
  MEDIUM: "#ffb224",
  LOW: "#46a758",
  INFO: "#6e7681",
};

export function StatsOverview({ stats }: { stats: Stats }) {
  const sevData = Object.entries(stats.by_severity_bucket).map(([name, value]) => ({ name, value }));
  const srcData = Object.entries(stats.by_source).map(([name, value]) => ({ name, value }));

  return (
    <div className="stats-overview">
      <div className="stat-cards">
        <div className="stat-card">
          <span className="stat-num">{stats.total}</span>
          <span className="stat-label">Total Findings</span>
        </div>
        <div className="stat-card critical">
          <span className="stat-num">{stats.by_severity_bucket.CRITICAL || 0}</span>
          <span className="stat-label">Critical</span>
        </div>
        <div className="stat-card high">
          <span className="stat-num">{stats.by_severity_bucket.HIGH || 0}</span>
          <span className="stat-label">High</span>
        </div>
      </div>

      <div className="charts">
        <div className="chart">
          <h3>By Severity</h3>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={sevData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={65} label>
                {sevData.map((d) => (
                  <Cell key={d.name} fill={SEV_COLORS[d.name] || "#6e7681"} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="chart">
          <h3>By Source</h3>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={srcData}>
              <XAxis dataKey="name" stroke="#8b949e" fontSize={12} />
              <YAxis stroke="#8b949e" fontSize={12} />
              <Tooltip />
              <Bar dataKey="value" fill="#388bfd" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
