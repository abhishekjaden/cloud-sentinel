import { useState } from "react";
import type { Approval } from "../types";
import { decideApproval } from "../api";

/**
 * Pending remediation approvals.
 *
 * Approving here resumes a paused Step Functions execution, which then takes a
 * destructive action against a live resource. Two consequences follow: the
 * confirm step is deliberate rather than decorative, and failures are surfaced
 * rather than swallowed — an operator who believes an action succeeded when it
 * did not is worse off than one who sees an error.
 */
function waitingFor(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(ms / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  return hrs < 24 ? `${hrs}h ${mins % 60}m` : `${Math.floor(hrs / 24)}d`;
}

function targetOf(approval: Approval): string {
  if (!approval.resource) return "—";
  try {
    const parsed = JSON.parse(approval.resource);
    return parsed.instance_id || parsed.access_key_id || parsed.bucket || approval.resource;
  } catch {
    return approval.resource;
  }
}

export function ApprovalsPanel({
  approvals,
  onDecided,
}: {
  approvals: Approval[];
  onDecided: () => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decided, setDecided] = useState<string | null>(null);

  async function decide(id: string, decision: "approve" | "reject") {
    setBusy(id);
    setError(null);
    setConfirming(null);
    try {
      const result = await decideApproval(id, decision);
      setDecided(`${result.status} by ${result.decided_by}`);
      onDecided();
    } catch (e: unknown) {
      // 409 means someone already decided; 410 means the workflow timed out.
      // Both are worth showing verbatim rather than as a generic failure.
      const err = e as { response?: { data?: { detail?: string }; status?: number } };
      setError(err.response?.data?.detail ?? "the decision could not be recorded");
    } finally {
      setBusy(null);
    }
  }

  if (approvals.length === 0) {
    return (
      <div className="approvals-panel">
        <p className="muted">Nothing awaiting approval.</p>
        {decided && <p className="approval-decided">{decided}</p>}
      </div>
    );
  }

  return (
    <div className="approvals-panel">
      {error && <p className="approval-error">{error}</p>}
      {decided && <p className="approval-decided">{decided}</p>}

      <ul className="approval-list">
        {approvals.map((a) => (
          <li key={a.approval_id} className="approval-card">
            <div className="approval-head">
              <span className="approval-playbook">{a.playbook}</span>
              <span className="approval-age muted">waiting {waitingFor(a.created_at)}</span>
            </div>

            <div className="approval-body">
              <span className="approval-finding">{a.finding_id}</span>
              <span className="approval-target">target: {targetOf(a)}</span>
            </div>

            {confirming === a.approval_id ? (
              <div className="approval-confirm">
                <span className="approval-warning">
                  This runs the {a.playbook} playbook against {targetOf(a)}.
                </span>
                <div className="approval-actions">
                  <button
                    className="btn-cancel"
                    onClick={() => setConfirming(null)}
                    disabled={busy === a.approval_id}
                  >
                    Cancel
                  </button>
                  <button
                    className="btn-approve-confirm"
                    onClick={() => decide(a.approval_id, "approve")}
                    disabled={busy === a.approval_id}
                  >
                    {busy === a.approval_id ? "Approving…" : "Confirm remediation"}
                  </button>
                </div>
              </div>
            ) : (
              <div className="approval-actions">
                <button
                  className="btn-reject"
                  onClick={() => decide(a.approval_id, "reject")}
                  disabled={busy === a.approval_id}
                >
                  Reject
                </button>
                <button
                  className="btn-approve"
                  onClick={() => setConfirming(a.approval_id)}
                  disabled={busy === a.approval_id}
                >
                  Approve
                </button>
              </div>
            )}
          </li>
        ))}
      </ul>

      <p className="hint muted">
        Decisions are recorded against your Cognito identity.
      </p>
    </div>
  );
}
