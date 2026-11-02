import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ErrorNote, PageHead, Pill, useData } from "../components/ui";
import { OnboardingChecklist } from "../components/OnboardingChecklist";

export default function Onboarding() {
  const { data, error } = useData<any[]>("onboarding", {}, [], true);
  const [open, setOpen] = useState<string | null>(null);
  return (
    <>
      <PageHead title="Customer onboarding" subtitle="Each customer's setup, checked against what really exists: details and agreement, staff access, policy, agents, Microsoft 365, backups, vulnerability scanning, monitoring and compliance. Unfinished and failing customers come first." />
      <ErrorNote error={error} />
      <div className="card">
        {data && data.length === 0 && <p className="muted">No customers yet. Create one from CRM.</p>}
        {(data || []).map((c) => (
          <div key={c.tenantId} style={{ borderBottom: "1px solid var(--line)", padding: "8px 0" }}>
            <div className="row" style={{ cursor: "pointer", gap: 10 }} onClick={() => setOpen(open === c.tenantId ? null : c.tenantId)}>
              <b style={{ flex: 1 }}>{displayValue(c.name)}</b>
              {c.failed > 0 && <Pill value={`${c.failed} failing`} tone="bad" />}
              {c.ready ? <Pill value="ready" tone="good" /> : <span className="small muted">{c.done}/{c.total} · next: {displayValue(c.next)}</span>}
              <Link to={`/crm/accounts/${c.tenantId}`} className="small" onClick={(e) => e.stopPropagation()}>Customer</Link>
            </div>
            {open === c.tenantId && <div style={{ marginTop: 8 }}><OnboardingChecklist tenantId={c.tenantId} /></div>}
          </div>
        ))}
      </div>
    </>
  );
}
