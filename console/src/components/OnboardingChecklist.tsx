import { displayValue } from "./DisplayValue";
import { Link } from "react-router-dom";
import { Pill, useData } from "./ui";

const TONE: Record<string, string> = { done: "good", todo: "warn", failed: "bad", optional: "muted" };
const LABEL: Record<string, string> = { done: "done", todo: "to do", failed: "failing", optional: "optional" };

// One customer's onboarding, computed from what really exists: leave it and come back, it picks up where it is.
export function OnboardingChecklist({ tenantId, compact = false }: { tenantId: string; compact?: boolean }) {
  const { data, error } = useData<any>(`onboarding/${tenantId}`);
  if (error) return <p className="small muted">{error}</p>;
  if (!data) return <p className="small muted">Loading…</p>;
  const steps = compact ? data.steps.filter((s: any) => s.status !== "done") : data.steps;
  return (
    <div>
      <div className="small" style={{ marginBottom: 8 }}>
        <b>{data.done} of {data.total}</b> required steps done{data.failed ? <>, <span style={{ color: "#f87171" }}>{data.failed} failing</span></> : null}
        {data.ready && <> · <Pill value="ready" tone="good" /></>}
      </div>
      {steps.length === 0 && <p className="small muted">Everything is in place.</p>}
      {steps.map((s: any) => (
        <div key={s.key} className="row small" style={{ padding: "5px 0", borderBottom: "1px solid var(--line)", gap: 8, alignItems: "flex-start" }}>
          <span style={{ minWidth: 70 }}><Pill value={LABEL[s.status] || s.status} tone={TONE[s.status]} /></span>
          <div style={{ flex: 1 }}>
            <b>{displayValue(s.title)}</b>{!s.required && <span className="muted"> (optional)</span>}
            <div className="muted">{displayValue(s.detail)}</div>
          </div>
          {s.status !== "done" && <Link to={s.link} className="small">Go</Link>}
        </div>
      ))}
    </div>
  );
}
