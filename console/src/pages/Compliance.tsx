import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { useApp } from "../app-context";
import { Meter, PageHead, Pill, TenantSelect, useData } from "../components/ui";

export default function Compliance() {
  const { tenantId, me } = useApp();
  const [tenant, setTenant] = useState(tenantId || me?.user.tenantId || "");
  const { data } = useData<any>("compliance", { tenant_id: tenant }, [tenant]);
  const [open, setOpen] = useState<string | null>("cyber-essentials");
  return (
    <>
      <PageHead title="Compliance" subtitle="Live posture against Cyber Essentials, CIS v8, NIST CSF 2.0, Essential Eight and ISO 27001, from real policy and fleet evidence."
                actions={<TenantSelect value={tenant} onChange={setTenant} allowAll={false} />} />
      <div className="grid k3">
        {data?.frameworks.map((f: any) => (
          <button key={f.framework} className="card" style={{ textAlign: "left", display: "block", borderColor: open === f.framework ? "var(--blue)" : undefined }}
                  onClick={() => setOpen(f.framework)}>
            <div className="small muted">{displayValue(f.name)}</div>
            <div style={{ fontSize: 28, fontWeight: 750 }}>{displayValue(f.score)}%</div>
            <Meter value={f.score} />
            <div className="small muted" style={{ marginTop: 6 }}>{displayValue(f.passed)} of {displayValue(f.total)} controls passing</div>
          </button>
        ))}
      </div>
      {data?.frameworks.filter((f: any) => f.framework === open).map((f: any) => (
        <div key={f.framework} className="card" style={{ marginTop: 16 }}>
          <h2>{displayValue(f.name)}</h2>
          {f.controls.map((c: any) => (
            <div key={c.id} className="row" style={{ alignItems: "flex-start", padding: "8px 0", borderBottom: "1px solid #172138" }}>
              <Pill value={c.passed ? "pass" : "gap"} tone={c.passed ? "good" : "bad"} />
              <div><b>{displayValue(c.id)}</b> {displayValue(c.title)}<div className="small muted">{displayValue(c.evidence.join(" · "))}</div></div>
            </div>
          ))}
        </div>
      ))}
    </>
  );
}
