import { useState } from "react";
import { ago, api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { ErrorNote, Modal, PageHead, Pill, Stat, Table, Tabs, TenantSelect, useAction, useData, useListData } from "../../components/ui";
import { confirmDialog, noticeDialog } from "../../components/dialogs";

const AUTO_TONE: Record<string, string> = { passing: "good", failing: "bad", manual: "muted" };
const TIER_TONE: Record<string, string> = { low: "good", medium: "blue", high: "warn", critical: "bad", unrated: "muted" };
const RESULT_TONE: Record<string, string> = { compliant: "good", remediated: "good", noncompliant: "bad", failed: "bad", error: "warn", pending: "muted" };

export default function Assurance() {
  const { tenantId } = useApp();
  const [tab, setTab] = useState("Controls");
  return (
    <>
      <PageHead title="Continuous compliance"
                subtitle="Live control signals mapped across every framework, evidence collected automatically, endpoint baselines enforced on devices, and supplier risk kept current." />
      <Tabs tabs={["Controls", "Evidence automation", "Baselines", "Suppliers"]} active={tab} onChange={setTab} />
      {tab !== "Suppliers" && !tenantId ? <div className="card empty">Choose a customer to see their controls, evidence and baselines.</div> : <>
        {tab === "Controls" && <Controls tenantId={tenantId!} />}
        {tab === "Evidence automation" && <Automation tenantId={tenantId!} />}
        {tab === "Baselines" && <Baselines tenantId={tenantId!} />}
      </>}
      {tab === "Suppliers" && <Suppliers />}
    </>
  );
}

function Controls({ tenantId }: { tenantId: string }) {
  const { data, error } = useListData<any>("grc-assurance/crosswalk", { tenant_id: tenantId });
  const [open, setOpen] = useState<any>(null);
  const failing = data?.filter((c) => c.automated === "failing").length ?? 0;
  return (
    <>
      <ErrorNote error={error} />
      <div className="grid k3">
        <Stat label="Common controls" value={data?.length ?? 0} />
        <Stat label="Passing live checks" value={data?.filter((c) => c.automated === "passing").length ?? 0} accent="green" />
        <Stat label="Failing live checks" value={failing} accent={failing ? "red" : undefined} />
      </div>
      <div className="card">
        <Table rows={data ?? undefined} onRow={setOpen}
               columns={[
                 { key: "title", label: "Control", render: (c) => <><b>{displayValue(c.title)}</b><div className="small muted">{c.id}</div></> },
                 { key: "automated", label: "Live checks", render: (c) => <Pill value={c.automated} tone={AUTO_TONE[c.automated]} /> },
                 { key: "frameworks", label: "Frameworks", render: (c) => <span className="small">{Array.from(new Set(c.mappings.map((m: any) => m.frameworkName))).join(", ")}</span> },
                 { key: "progress", label: "Adopted requirements", className: "right", render: (c) => c.adoptedRequirements ? `${c.implemented}/${c.adoptedRequirements} implemented` : <span className="muted">none adopted</span> },
               ]} />
      </div>
      {open && <ControlModal control={open} tenantId={tenantId} onClose={() => setOpen(null)} />}
    </>
  );
}

function ControlModal({ control, tenantId, onClose }: { control: any; tenantId: string; onClose: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const propagate = async (m: any) => {
    const r = await run(() => api<any>("grc-assurance/crosswalk/propagate", { body: { tenantId, framework: m.framework, requirementId: m.requirementId } }));
    if (r) noticeDialog(r.updated.length ? `Marked implemented: ${r.updated.map((u: any) => `${u.framework} ${u.requirementId}`).join(", ")}` : "Nothing else to update.");
  };
  return (
    <Modal wide title={`${control.id} · ${control.title}`} onClose={onClose}>
      <p className="small muted">{displayValue(control.description)}</p>
      <h4>Live checks</h4>
      {control.signals.length ? control.signals.map((s: any) => (
        <div key={s.key} className="small" style={{ marginBottom: 6 }}>
          <Pill value={s.passed === null ? "no data" : s.passed ? "pass" : "fail"} tone={s.passed === null ? "muted" : s.passed ? "good" : "bad"} /> <b>{displayValue(s.label)}</b>
          <ul style={{ margin: "2px 0 0 18px" }}>{s.evidence.slice(0, 6).map((e: string, i: number) => <li key={i}>{displayValue(e)}</li>)}</ul>
        </div>)) : <p className="small muted">This control is evidenced manually (documents, records).</p>}
      <h4>Requirements it satisfies</h4>
      <Table rows={control.mappings.map((m: any, i: number) => ({ ...m, id: i }))}
             columns={[
               { key: "frameworkName", label: "Framework", render: (m) => <>{displayValue(m.frameworkName)}{!m.adopted && <span className="small muted"> (not adopted)</span>}</> },
               { key: "requirementId", label: "Requirement", render: (m) => <><b>{m.requirementId}</b> <span className="small">{displayValue(m.title)}</span></> },
               { key: "status", label: "Status", render: (m) => <Pill value={m.status} tone={m.status === "implemented" ? "good" : m.status === "in_progress" ? "warn" : "muted"} /> },
               { key: "act", label: "", className: "right", render: (m) => can("grc") && m.adopted && m.status === "implemented" &&
                   <button className="small" disabled={busy} title="Mark the same control implemented in the customer's other frameworks, with the same evidence" onClick={() => propagate(m)}>Apply across frameworks</button> },
             ]} />
    </Modal>
  );
}

function Automation({ tenantId }: { tenantId: string }) {
  const { can } = useApp();
  const { data, error, reload } = useData<any>("grc-assurance/automation", { tenant_id: tenantId });
  const { run, busy } = useAction();
  if (error) return <ErrorNote error={error} />;
  if (!data) return <div className="empty">Loading…</div>;
  const signals = Object.entries(data.signals || {}) as [string, any][];
  return (
    <>
      <div className="card">
        <p className="small muted">Every hour Fenrir re-checks each control. When a result changes (and at least daily) it writes an evidence record, hashed and linked to every requirement the control satisfies in the frameworks this customer has adopted. A check that goes from passing to failing opens a compliance-drift ticket.</p>
        <div className="row" style={{ gap: 8 }}>
          <Pill value={data.enabled ? "continuous collection on" : "off"} tone={data.enabled ? "good" : "muted"} />
          {data.lastCollectedAt && <span className="small muted">last run {ago(data.lastCollectedAt + "Z")}</span>}
          {can("grc") && <>
            <button disabled={busy} onClick={async () => { if (await run(() => api(`grc-assurance/automation/${tenantId}`, { method: "PUT", body: { enabled: !data.enabled } }))) reload(); }}>{data.enabled ? "Turn off" : "Turn on"}</button>
            <button className="primary" disabled={busy} onClick={async () => { const r = await run(() => api<any>(`grc-assurance/automation/${tenantId}/collect`, { method: "POST" }), "Evidence collected"); if (r) reload(); }}>Collect now</button>
          </>}
        </div>
        {signals.length > 0 && <div className="row" style={{ gap: 6, flexWrap: "wrap", marginTop: 10 }}>
          {signals.map(([key, s]) => <Pill key={key} value={s.label} tone={s.passed === null ? "muted" : s.passed ? "good" : "bad"} />)}
        </div>}
      </div>
      <div className="card">
        <h3>Automated evidence</h3>
        <Table rows={data.evidence} empty="No automated evidence yet. Collect now, or turn continuous collection on."
               columns={[
                 { key: "title", label: "Evidence", render: (e) => <details><summary><b>{displayValue(e.title)}</b></summary><pre className="small" style={{ whiteSpace: "pre-wrap" }}>{displayValue(e.description)}</pre><div className="small mono muted">sha256 {e.sha256}</div></details> },
                 { key: "status", label: "Result", render: (e) => <Pill value={e.status} tone={AUTO_TONE[e.status]} /> },
                 { key: "createdAt", label: "Captured", render: (e) => fmtTime(e.createdAt) },
                 { key: "validUntil", label: "Valid until", render: (e) => fmtTime(e.validUntil) },
               ]} />
      </div>
    </>
  );
}

function Baselines({ tenantId }: { tenantId: string }) {
  const { can } = useApp();
  const { data, error, reload } = useData<any>("grc-assurance/baselines", { tenant_id: tenantId });
  const { run, busy } = useAction();
  if (error) return <ErrorNote error={error} />;
  if (!data) return <div className="empty">Loading…</div>;
  const assign = async (key: string, mode: string) => { if (await run(() => api(`grc-assurance/baselines/${key}/${tenantId}`, { method: "PUT", body: { mode } }), mode === "enforce" ? "Baseline enforced" : "Baseline in audit mode")) reload(); };
  const remove = async (key: string) => { if (await confirmDialog("Stop checking this baseline?") && await run(() => api(`grc-assurance/baselines/${key}/${tenantId}`, { method: "DELETE" }), "Baseline removed")) reload(); };
  return (
    <>
      {data.catalogue.map((b: any) => {
        const current = data.assigned?.[b.key];
        const report = data.report?.find((r: any) => r.key === b.key);
        return (
          <div className="card" key={b.key}>
            <div className="row" style={{ justifyContent: "space-between" }}>
              <div><h3 style={{ margin: 0 }}>{displayValue(b.name)} {current && <Pill value={current.mode} tone={current.mode === "enforce" ? "blue" : "warn"} />}</h3>
                <div className="small muted">{displayValue(b.description)}</div></div>
              {can("grc") && can("configure") && <span className="row" style={{ gap: 6 }}>
                {current?.mode !== "audit" && <button className="ghost" disabled={busy} onClick={() => assign(b.key, "audit")}>Audit</button>}
                {current?.mode !== "enforce" && can("scripts") && <button className="primary" disabled={busy} onClick={() => assign(b.key, "enforce")}>Enforce</button>}
                {current && <button className="danger" disabled={busy} onClick={() => remove(b.key)}>Remove</button>}
              </span>}
            </div>
            {report ? <>
              <p className="small">{report.compliance === null ? "No devices on this platform." : `${report.compliantDevices} of ${report.deviceCount} devices compliant (${report.compliance}%).`}
                {" "}Policy: {report.policy.filter((p: any) => !p.passed).map((p: any) => p.path).join(", ") || "all expected settings in place"}.</p>
              <Table rows={report.devices.map((d: any) => ({ ...d, id: d.deviceId }))}
                     columns={[{ key: "hostname", label: "Device", render: (d) => <b>{displayValue(d.hostname)}</b> },
                               ...b.items.map((item: any) => ({ key: item.package, label: item.name, render: (d: any) => <Pill value={d.items[item.package]} tone={RESULT_TONE[d.items[item.package]]} /> }))]} />
            </> : <p className="small muted">{b.items.length} checks: {b.items.map((i: any) => i.name).join(", ")}.</p>}
          </div>
        );
      })}
    </>
  );
}

function Suppliers() {
  const { tenantId, tenantName, can } = useApp();
  const { data, error, reload } = useListData<any>("grc-assurance/vendors", { tenant_id: tenantId });
  const [editing, setEditing] = useState<any>(null);
  const [open, setOpen] = useState<any>(null);
  return (
    <>
      <ErrorNote error={error} />
      {can("grc") && <button className="primary" style={{ marginBottom: 12 }} onClick={() => setEditing({ tenantId: tenantId || "", criticality: "medium", dataAccess: "none" })}>Add supplier</button>}
      <div className="card">
        <Table rows={data ?? undefined} onRow={setOpen} empty="No suppliers registered."
               columns={[
                 { key: "name", label: "Supplier", render: (v) => <><b>{displayValue(v.name)}</b><div className="small muted">{tenantName(v.tenantId)} · {displayValue(v.domain || "no domain")}</div></> },
                 { key: "criticality", label: "Criticality", render: (v) => <>{v.criticality}<div className="small muted">{v.dataAccess} data</div></> },
                 { key: "riskTier", label: "Residual risk", render: (v) => <><Pill value={v.riskTier} tone={TIER_TONE[v.riskTier]} /><div className="small muted">{v.riskScore ?? "-"} / inherent {v.inherentRisk}</div></> },
                 { key: "scores", label: "Questionnaire / posture", render: (v) => `${v.questionnaireScore ?? "-"} / ${v.postureScore ?? "-"}` },
                 { key: "nextReviewAt", label: "Next review", render: (v) => <span className={v.reviewDue ? "error" : ""}>{fmtTime(v.nextReviewAt)}</span> },
               ]} />
      </div>
      {editing && <SupplierEditor value={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); reload(); }} />}
      {open && <SupplierDetail vendor={open} onClose={() => { setOpen(null); reload(); }} onEdit={() => { setEditing(open); setOpen(null); }} />}
    </>
  );
}

function SupplierEditor({ value, onClose, onSaved }: { value: any; onClose: () => void; onSaved: () => void }) {
  const { run, busy } = useAction();
  const [form, setForm] = useState<any>({ ...value, documents: value.documents || [] });
  const set = (key: string) => (e: { target: { value: string } }) => setForm({ ...form, [key]: e.target.value });
  const save = async () => {
    const body = { tenantId: form.tenantId, name: form.name, domain: form.domain, services: form.services, criticality: form.criticality,
                   dataAccess: form.dataAccess, contactName: form.contactName, contactEmail: form.contactEmail, owner: form.owner, documents: form.documents };
    if (await run(() => (form.id ? api(`grc-assurance/vendors/${form.id}`, { method: "PATCH", body }) : api("grc-assurance/vendors", { body })), "Supplier saved")) onSaved();
  };
  const setDoc = (i: number, key: string, v: string) => setForm({ ...form, documents: form.documents.map((d: any, j: number) => (j === i ? { ...d, [key]: v } : d)) });
  return (
    <Modal wide title={form.id ? `Edit ${form.name}` : "Add supplier"} onClose={onClose}
           footer={<button className="primary" disabled={busy || !form.name || !form.tenantId} onClick={save}>Save</button>}>
      <div className="form-grid">
        {!form.id && <TenantSelect value={form.tenantId} allowAll={false} label="Customer" onChange={(id) => setForm({ ...form, tenantId: id })} />}
        <label className="field">Name<input value={form.name || ""} onChange={set("name")} /></label>
        <label className="field">Domain<input value={form.domain || ""} onChange={set("domain")} placeholder="supplier.com" /></label>
        <label className="field">Service provided<input value={form.services || ""} onChange={set("services")} /></label>
        <label className="field">Criticality<select value={form.criticality} onChange={set("criticality")}>{["low", "medium", "high", "critical"].map((c) => <option key={c}>{c}</option>)}</select></label>
        <label className="field">Data it can reach<select value={form.dataAccess} onChange={set("dataAccess")}>
          <option value="none">None</option><option value="internal">Internal</option><option value="personal">Personal data</option><option value="special">Special category data</option></select></label>
        <label className="field">Security contact<input value={form.contactName || ""} onChange={set("contactName")} /></label>
        <label className="field">Contact email (questionnaires)<input type="email" value={form.contactEmail || ""} onChange={set("contactEmail")} /></label>
        <label className="field">Owner<input value={form.owner || ""} onChange={set("owner")} /></label>
      </div>
      <h4>Certificates and contracts</h4>
      {form.documents.map((d: any, i: number) => (
        <div className="form-grid" key={i}>
          <label className="field">Type<input value={d.type || ""} onChange={(e) => setDoc(i, "type", e.target.value)} placeholder="ISO 27001 certificate" /></label>
          <label className="field">Reference<input value={d.name || ""} onChange={(e) => setDoc(i, "name", e.target.value)} /></label>
          <label className="field">Expires<input type="date" value={(d.expiresAt || "").slice(0, 10)} onChange={(e) => setDoc(i, "expiresAt", e.target.value)} /></label>
        </div>))}
      <button className="small" onClick={() => setForm({ ...form, documents: [...form.documents, { type: "", name: "", expiresAt: "" }] })}>Add document</button>
    </Modal>
  );
}

function SupplierDetail({ vendor, onClose, onEdit }: { vendor: any; onClose: () => void; onEdit: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const [v, setV] = useState(vendor);
  const [link, setLink] = useState<string | null>(null);
  const { data: assessments, reload } = useListData<any>(`grc-assurance/vendors/${vendor.id}/assessments`);
  const scan = async () => { const r = await run(() => api<any>(`grc-assurance/vendors/${v.id}/scan`, { method: "POST" }), "Posture scanned"); if (r) setV(r); };
  const send = async () => { const r = await run(() => api<any>(`grc-assurance/vendors/${v.id}/assessments`, { body: {} }), v.contactEmail ? `Questionnaire sent to ${v.contactEmail}` : "Questionnaire link created"); if (r) { setLink(r.link); reload(); } };
  const checks = v.posture?.checks || {};
  return (
    <Modal wide title={v.name} onClose={onClose}
           footer={can("grc") && <><button onClick={onEdit}>Edit</button><button disabled={busy || !v.domain} onClick={scan}>Scan posture</button><button className="primary" disabled={busy} onClick={send}>Send questionnaire</button></>}>
      <div className="grid k3">
        <Stat label="Residual risk" value={<Pill value={v.riskTier} tone={TIER_TONE[v.riskTier]} />} hint={`score ${v.riskScore ?? "-"} (inherent ${v.inherentRisk})`} />
        <Stat label="Questionnaire" value={v.questionnaireScore ?? "-"} hint={v.lastAssessedAt ? `answered ${fmtTime(v.lastAssessedAt)}` : "not answered"} />
        <Stat label="External posture" value={v.postureScore ?? "-"} hint={v.lastScannedAt ? `scanned ${fmtTime(v.lastScannedAt)}` : "not scanned"} />
      </div>
      {link && <p className="small">Questionnaire link (single use): <code style={{ wordBreak: "break-all" }}>{link}</code></p>}
      {v.posture?.findings?.length > 0 && <><h4>Posture findings</h4><ul className="small">{v.posture.findings.map((f: string, i: number) => <li key={i}>{displayValue(f)}</li>)}</ul></>}
      {checks.certificate && <p className="small muted">TLS certificate: {checks.certificate.valid ? `valid, ${checks.certificate.daysLeft} days left` : `invalid (${checks.certificate.error})`} · SPF {checks.spf ? "yes" : "no"} · DMARC {String(checks.dmarc ?? "-")} · HSTS {checks.hsts ? "yes" : "no"}</p>}
      <h4>Questionnaires</h4>
      <Table rows={assessments ?? undefined} empty="None sent yet."
             columns={[{ key: "status", label: "Status", render: (a) => <Pill value={a.status} tone={a.status === "completed" ? "good" : a.status === "sent" ? "blue" : "muted"} /> },
                       { key: "recipient", label: "Sent to" }, { key: "sentAt", label: "Sent", render: (a) => fmtTime(a.sentAt) },
                       { key: "score", label: "Score", render: (a) => a.score ?? "-" },
                       { key: "findings", label: "Findings", render: (a) => (a.findings || []).map((f: any) => <div key={f.question} className="small"><Pill value={f.severity} tone={f.severity === "high" ? "bad" : "warn"} /> {displayValue(f.text)} <i>({f.answer}{f.comment ? `: ${f.comment}` : ""})</i></div>) }]} />
      {v.documents?.length > 0 && <><h4>Documents</h4><ul className="small">{v.documents.map((d: any, i: number) => <li key={i}>{displayValue(d.type)} {displayValue(d.name)}: expires {fmtTime(d.expiresAt)}</li>)}</ul></>}
    </Modal>
  );
}
