// Firewall configuration assessment (VULN-13): upload an exported configuration; Fenrir keeps only the findings and
// the file's SHA-256, never the file, and never asks for the firewall's credentials.
import { useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { PageHead, Pill, Table, useAction, useData } from "../components/ui";

const TONE: Record<string, string> = { critical: "bad", high: "bad", medium: "warn", low: "neutral", info: "neutral" };

export default function FirewallAssessments() {
  const { tenantId } = useApp();
  const { run, busy } = useAction();
  const { data: caps } = useData<any>("firewall-assessments/capabilities");
  const { data: rows, reload } = useData<any[]>(tenantId ? "firewall-assessments" : null, { tenantId: tenantId || undefined }, [tenantId]);
  const [form, setForm] = useState({ label: "", firmware: "", minimumFirmware: "" });
  const [file, setFile] = useState<File | null>(null);
  const [open, setOpen] = useState<any>(null);
  const submit = async () => {
    if (!file) return;
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    const out = await run(() => api<any>("firewall-assessments", { body: { tenantId, ...form, label: form.label || file.name, contentBase64: btoa(binary) } }), "Assessed");
    if (out) { setOpen(out); reload(); }
  };
  return (
    <>
      <PageHead title="Firewall configuration" subtitle="Assess a firewall's saved configuration: rules open to the internet, management exposure, weak VPN cryptography, SNMP, UPnP, logging and firmware. Fenrir never asks for the firewall's password and does not keep the uploaded file." />
      {caps && <p className="small muted">Supported: {Object.values(caps.vendors).map((v: any) => `${v.name} (${v.format})`).join("; ")}. {caps.unsupported}</p>}
      {!tenantId ? <div className="card empty">Choose a customer.</div> : <>
        <div className="card"><div className="form-grid">
          <label className="field">Configuration file<input type="file" accept=".xml" onChange={(e) => setFile(e.target.files?.[0] || null)} /></label>
          <label className="field">Name<input value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} /></label>
          <label className="field">Firmware version (from the dashboard)<input value={form.firmware} onChange={(e) => setForm({ ...form, firmware: e.target.value })} /></label>
          <label className="field">Oldest supported version<input value={form.minimumFirmware} onChange={(e) => setForm({ ...form, minimumFirmware: e.target.value })} /></label>
        </div><button className="primary" disabled={busy || !file} onClick={submit}>Assess</button></div>
        <Table rows={rows || []} empty="No assessments yet." onRow={(r: any) => setOpen(r)} columns={[
          { key: "label", label: "Firewall" }, { key: "vendor", label: "Type" },
          { key: "summary", label: "Findings", render: (r: any) => ["critical", "high", "medium"].filter((s) => r.summary[s]).map((s) => <Pill key={s} value={`${r.summary[s]} ${s}`} tone={TONE[s]} />) },
          { key: "createdAt", label: "Assessed", render: (r: any) => fmtTime(r.createdAt) },
        ]} />
        {open && <div className="card">
          <div className="row"><h3 style={{ flex: 1, margin: 0 }}>{open.label}</h3><button className="link" onClick={() => setOpen(null)}>Close</button></div>
          <p className="small muted">File SHA-256 {open.fileSha256} · firmware {open.firmware.version || "unknown"} ({open.firmware.status})</p>
          <Table rows={open.findings} empty="No findings for the checks Fenrir supports." columns={[
            { key: "severity", label: "", render: (x: any) => <Pill value={x.severity} tone={TONE[x.severity]} /> },
            { key: "title", label: "Finding" }, { key: "evidence", label: "Setting", render: (x: any) => <code className="small">{x.evidence}</code> },
            { key: "advice", label: "Fix", render: (x: any) => <span className="small">{x.advice}</span> },
          ]} />
          <h4>Not checked</h4>{open.untested.map((u: any, i: number) => <div key={i} className="small">{u.check}: {u.reason}</div>)}
        </div>}
      </>}
    </>
  );
}
