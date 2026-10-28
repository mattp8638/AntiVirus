import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ago } from "../api";
import { useApp } from "../app-context";
import { PageHead, Pill, Sev, Table, useListData } from "../components/ui";

export default function Incidents() {
  const { tenantId, tenantName } = useApp();
  const navigate = useNavigate();
  const [status, setStatus] = useState("");
  const { data } = useListData<any>("incidents", { tenant_id: tenantId, status });
  return (
    <>
      <PageHead title="Incidents" subtitle="Correlated attacks with a guided response playbook, automated actions and a linked PSA ticket." />
      <div className="row" style={{ marginBottom: 12 }}>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="">Any status</option>{["open", "investigating", "contained", "resolved", "closed"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>
      <div className="card">
        <Table rows={data} onRow={(r) => navigate(`/incidents/${r.id}`)} empty="No incidents."
               columns={[{ key: "severity", label: "Sev", render: (r) => <Sev level={r.severity} /> },
                         { key: "title", label: "Incident", render: (r) => <><b>{displayValue(r.title)}</b><div className="small muted">{displayValue(r.playbook || "no playbook")}</div></> },
                         { key: "tenantId", label: "Tenant", render: (r) => tenantName(r.tenantId) },
                         { key: "alertCount", label: "Alerts" },
                         { key: "mitre", label: "MITRE", render: (r) => r.mitre.filter((m: string) => m.startsWith("T")).slice(0, 4).join(", ") },
                         { key: "assignee", label: "Owner", render: (r) => r.assignee || "—" },
                         { key: "status", label: "Status", render: (r) => <Pill value={r.status} /> },
                         { key: "createdAt", label: "Opened", render: (r) => ago(r.createdAt) }]} />
      </div>
    </>
  );
}
