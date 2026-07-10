import { useState } from "react";
import { predict } from "../api";
import type { PredictResponse } from "../types";

export function PredictPanel() {
  const [result, setResult] = useState<PredictResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function runSample(kind: "benign" | "random") {
    setLoading(true);
    setError(null);
    try {
      const features = kind === "benign"
        ? Array(78).fill(0)
        : Array.from({ length: 78 }, () => Math.random() * 100);
      const r = await predict(features);
      setResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Prediction failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="predict-panel">
      <p className="muted">
        Score a network flow through the trained XGBoost intrusion-detection model
        (binary classifier, AUC 0.9999).
      </p>
      <div className="predict-actions">
        <button onClick={() => runSample("benign")} disabled={loading}>
          Test benign flow
        </button>
        <button onClick={() => runSample("random")} disabled={loading}>
          Test random flow
        </button>
      </div>

      {loading && <p className="muted">Scoring…</p>}
      {error && <p className="error-text">{error}</p>}

      {result && !loading && (
        <div className={`predict-result ${result.prediction === "ATTACK" ? "attack" : "benign"}`}>
          <span className="predict-label">{result.prediction}</span>
          <span className="predict-prob">
            {(result.attack_probability * 100).toFixed(2)}% attack probability
          </span>
        </div>
      )}
    </div>
  );
}
