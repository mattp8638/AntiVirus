import { displayValue } from "../components/DisplayValue";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ago, api, money } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, PageHead, Pill, Stat, Table, useAction, useData } from "../components/ui";
import { CrmEditor } from "./Crm";

const TIMELINE_TONE: Record<string, string> = { ticket: "warn", invoice: "muted", opportunity: "good", task: "blue" };

export default function CrmAccount() {
  const { id = "" } = useParams();
  const { can } = useApp();
  const [days, setDays] = useState(90);
  const { data, error, reload } = useData<any>(`crm/accounts/${id}`, { days }, [days]);
  const [editing, setEditing] = useState<{ kind: string; row: any } | null>(null);
  const { run } = useAction();
  const a = data?.account;
  const p = data?.profitability;

  const setOwner = async () => {
    const owner = window.prompt("Account owner (name or email of the person responsible)", a?.accountOwner ?? "");
    if (owner === null) return;
    await run(() => api(`crm/accounts/${id}`, { method: "PATCH", body: { accountOwner: owner } }), "Owner updated");
    reload();
  };
  const blank = (kind: string, extra: any = {}) => setEditing({ kind, row: { accountTenantId: id, ...extra } });

  return (
    <>
      <PageHead title={a?.name ?? "Account"}
                subtitle={a ? <>Plan {displayValue(a.plan)} · {displayValue(data.devices)} devices · owner <b>{displayValue(a.accountOwner || "unassigned")}</b>
                  {can("crm") && <> · <button className="small" onClick={setOwner}>Change owner</button></>}</> : undefined}
                actions={can("crm") && <span style={{ display: "inline-flex", gap: 6 }}>
                  <button onClick={() => blank("activities", { kind: "call", direction: "outbound" })}>Log activity</button>
                  <button onClick={() => blank("activities", { kind: "task" })}>Add task</button>
                  <button className="primary" onClick={() => blank("opportunities", { kind: "Upsell", stage: "Prospecting" })}>New opportunity</button>
                </span>} />
      <ErrorNote error={error} />
      <div className="grid k4">
        <Stat label="Contracted MRR" value={data ? money(data.mrr) : "—"} />
        <Stat label={`Revenue (${days} days)`} value={p ? money(p.revenue) : "—"} hint={p ? `${p.invoiceCount} invoices · ${money(p.outstanding)} outstanding` : undefined} />
        <Stat label={`Margin (${days} days)`} value={p ? money(p.margin) : "—"} accent={!p || !p.revenue ? undefined : p.margin < 0 ? "red" : "green"}
              hint={p ? `${p.marginPercent == null ? "—" : `${p.marginPercent}%`} · ${p.labourHours}h labour at ${money(p.labourCostRate)}/h` : undefined} />
        <Stat label="Open tickets" value={data?.openTickets ?? "—"} hint={p && p.unbilledTime ? `${money(p.unbilledTime)} unbilled time` : undefined} />
      </div>
      <div className="row" style={{ margin: "8px 0", gap: 6 }}>
        <span className="small muted">Period</span>
        {[30, 90, 365].map((d) => <button key={d} className={`small ${d === days ? "primary" : ""}`} onClick={() => setDays(d)}>{d} days</button>)}
      </div>

      <div className="grid k2" style={{ marginTop: 6 }}>
        <div className="card">
          <h3>Timeline</h3>
          <Table rows={data?.timeline.map((t: any) => ({ ...t, id: `${t.type}:${t.ref}` }))} empty="No history yet."
                 columns={[{ key: "type", label: "", render: (t) => <Pill value={t.type} tone={TIMELINE_TONE[t.type] ?? "muted"} /> },
                           { key: "title", label: "What", render: (t) => <><b>{displayValue(t.title)}</b>{t.open && <> <Pill value="open" tone="warn" /></>}
                             {t.detail && <div className="small muted">{displayValue(t.detail)}</div>}</> },
                           { key: "at", label: "When", render: (t) => <>{ago(t.at)}{t.by && <div className="small muted">{displayValue(t.by)}</div>}</> }]} />
        </div>
        <div>
          <div className="card">
            <h3>Opportunities</h3>
            <Table rows={data?.opportunities} onRow={(o) => setEditing({ kind: "opportunities", row: o })} empty="No deals for this account."
                   columns={[{ key: "name", label: "Deal", render: (o) => <><b>{displayValue(o.name)}</b><div className="small muted">{displayValue(o.kind)}</div></> },
                             { key: "stage", label: "Stage", render: (o) => <Pill value={o.stage} tone={o.stage === "Won" ? "good" : o.stage === "Lost" ? "bad" : "blue"} /> },
                             { key: "value", label: "Value", className: "right", render: (o) => <>{money(o.value)}{o.monthlyValue ? <div className="small muted">+ {money(o.monthlyValue)}/mo</div> : null}</> }]} />
          </div>
          <div className="card" style={{ marginTop: 14 }}>
            <h3>Contacts</h3>
            <Table rows={data?.contacts} onRow={(c) => setEditing({ kind: "contacts", row: c })} empty="No contacts."
                   columns={[{ key: "name", label: "Name", render: (c) => <><b>{displayValue(c.name)}</b> {c.isPrimary && <Pill value="primary" tone="blue" />}<div className="small muted">{displayValue(c.title)}</div></> },
                             { key: "email", label: "Email" }, { key: "phone", label: "Phone" }]} />
          </div>
          <div className="card" style={{ marginTop: 14 }}>
            <h3>Microsoft 365 licences</h3>
            {!data?.m365 ? <p className="muted">No Microsoft 365 connection for this customer. <Link to="/m365">Connect one</Link> to see licence use.</p>
              : <>
                <p className="small muted">{displayValue(data.m365.assigned)} of {displayValue(data.m365.purchased)} assigned · {displayValue(data.m365.unused)} unused · synced {ago(data.m365.syncedAt)}</p>
                <Table rows={data.m365.skus.map((s: any) => ({ ...s, id: s.sku }))} empty="No licences in the last sync."
                       columns={[{ key: "sku", label: "Licence", render: (s) => <span className="mono">{displayValue(s.sku)}</span> },
                                 { key: "purchased", label: "Bought", className: "right" }, { key: "assigned", label: "Assigned", className: "right" },
                                 { key: "unused", label: "Unused", className: "right", render: (s) => s.unused ? <b style={{ color: "#fcd34d" }}>{displayValue(s.unused)}</b> : 0 }]} />
              </>}
          </div>
          <div className="card" style={{ marginTop: 14 }}>
            <h3>Agreements</h3>
            <Table rows={data?.contracts} empty="No agreements."
                   columns={[{ key: "name", label: "Agreement" }, { key: "plan", label: "Plan" },
                             { key: "active", label: "Status", render: (c) => <Pill value={c.active ? "active" : "ended"} tone={c.active ? "good" : "muted"} /> }]} />
          </div>
        </div>
      </div>
      {editing && <CrmEditor kind={editing.kind} row={editing.row} onClose={() => { setEditing(null); reload(); }} />}
    </>
  );
}
