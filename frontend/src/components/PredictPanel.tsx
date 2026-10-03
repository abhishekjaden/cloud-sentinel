import { useState } from "react";
import { predict } from "../api";
import { describeFamily, percent, topFamilies } from "../predict";
import type { PredictResponse } from "../types";

/** The verdict, the family beside it, and the margin behind the family. */
export function PredictResult({ result }: { result: PredictResponse }) {
  const attack = result.prediction === "ATTACK";
  return (
    <div className={`predict-result ${attack ? "attack" : "benign"}`}>
      <span className="predict-label">{result.prediction}</span>
      <span className="predict-prob">
        {(result.attack_probability * 100).toFixed(2)}% attack probability
      </span>
      <span className="predict-family">{describeFamily(result)}</span>
      <span className="predict-margin">
        {topFamilies(result.family_probabilities).map(([name, p]) => (
          <span key={name} className="predict-margin-item">
            {name} {percent(p)}
          </span>
        ))}
      </span>
    </div>
  );
}

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
        Score a network flow through the trained XGBoost models. The binary
        detector gives the verdict; the eight-class model names the most likely
        attack family (held-out macro-F1 0.959, uneven across classes).
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

      {result && !loading && <PredictResult result={result} />}
    </div>
  );
}
