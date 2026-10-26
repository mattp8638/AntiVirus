import { useState } from "react";
import { api } from "../../api";
import { useApp } from "../../app-context";
import { emptyTargets, JobDetail, TargetPicker } from "../../components/rmm";
import { Modal, PageHead, Pill, Table, useAction, useData } from "../../components/ui";

const INSTALLERS: Record<string, string[]> = { windows: ["winget", "choco", "msi", "exe"], linux: ["apt", "dnf", "snap"], macos: ["brew", "pkg"] };

export default function Software() {
  const { can } = useApp();
  const { data, reload } = useData<any[]>("rmm/software");
  const [deploying, setDeploying] = useState<any>(null);
  const [editing, setEditing] = useState<any>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [platform, setPlatform] = useState("");
  return (
    <>
      <PageHead title="Software deployment" subtitle="Install, update or remove applications across devices: winget, Chocolatey, signed MSI/EXE, apt, dnf and snap."
                actions={can("configure") && <button className="primary" onClick={() => setEditing({ platform: "windows", installer: "winget", name: "", identifier: "", keepUpdated: true })}>Add package</button>} />
      <div className="row" style={{ marginBottom: 12 }}>
        <select value={platform} onChange={(e) => setPlatform(e.target.value)}><option value="">All platforms</option><option value="windows">Windows</option><option value="linux">Linux</option><option value="macos">macOS</option></select>
      </div>
      <div className="card">
        <Table rows={data?.filter((p) => !platform || p.platform === platform)} onRow={(p) => !p.builtin && setEditing(p)} empty="No packages."
               columns={[{ key: "name", label: "Application", render: (p) => <><b>{p.name}</b><div className="small muted">{p.publisher}</div></> },
                         { key: "platform", label: "Platform" },
                         { key: "installer", label: "Installer", render: (p) => <span className="mono small">{p.installer}</span> },
                         { key: "identifier", label: "Package", render: (p) => <span className="mono small">{p.identifier}</span> },
                         { key: "keepUpdated", label: "", render: (p) => <>{p.builtin && <Pill value="built-in" tone="blue" />} {p.keepUpdated && <Pill value="kept updated" tone="good" />}</> },
                         { key: "deploy", label: "", render: (p) => can("configure") && <span className="row">
                             <button className="small primary" onClick={(e) => { e.stopPropagation(); setDeploying({ pkg: p, action: "install" }); }}>Deploy</button>
                             <button className="small" onClick={(e) => { e.stopPropagation(); setDeploying({ pkg: p, action: "uninstall" }); }}>Remove</button></span> }]} />
      </div>
      {deploying && <Deploy pkg={deploying.pkg} action={deploying.action} onClose={() => setDeploying(null)} onStarted={(id) => { setDeploying(null); setJobId(id); }} />}
      {editing && <PackageEditor pkg={editing} onClose={() => { setEditing(null); reload(); }} />}
      {jobId && <JobDetail jobId={jobId} onClose={() => setJobId(null)} />}
    </>
  );
}

function Deploy({ pkg, action, onClose, onStarted }: { pkg: any; action: string; onClose: () => void; onStarted: (id: string) => void }) {
  const [targets, setTargets] = useState({ ...emptyTargets(), platforms: [pkg.platform] });
  const { run, busy } = useAction();
  return (
    <Modal title={`${action === "install" ? "Deploy" : "Remove"} ${pkg.name}`} onClose={onClose}
           footer={<><button onClick={onClose}>Cancel</button><button className={action === "install" ? "primary" : "danger"} disabled={busy} onClick={async () => {
             const job = await run(() => api<any>(`rmm/software/${pkg.id}/deploy`, { body: { targets, action } }), "Deployment queued");
             if (job) onStarted(job.id);
           }}>{action === "install" ? "Deploy" : "Remove"}</button></>}>
      <TargetPicker value={targets} onChange={setTargets} platforms={[pkg.platform]} />
      <p className="small muted">Only {pkg.platform} devices receive it.</p>
    </Modal>
  );
}

function PackageEditor({ pkg, onClose }: { pkg: any; onClose: () => void }) {
  const [form, setForm] = useState<any>({ ...pkg });
  const { run, busy } = useAction();
  const save = async () => {
    const body = { name: form.name, publisher: form.publisher, platform: form.platform, installer: form.installer, identifier: form.identifier,
                   sha256: form.sha256 || "", installArgs: form.installArgs || "", uninstallArgs: form.uninstallArgs || "", keepUpdated: form.keepUpdated };
    if (await run(() => (form.id ? api(`rmm/software/${form.id}`, { method: "PATCH", body }) : api("rmm/software", { body })), "Package saved")) onClose();
  };
  const direct = ["msi", "exe", "pkg"].includes(form.installer);
  return (
    <Modal title={form.id ? form.name : "Add package"} onClose={onClose}
           footer={<>{form.id && <button className="danger" onClick={async () => { if (await run(() => api(`rmm/software/${form.id}`, { method: "DELETE" }), "Deleted")) onClose(); }}>Delete</button>}
                   <button className="primary" disabled={busy || !form.name || !form.identifier} onClick={save}>Save</button></>}>
      <div className="form-grid">
        <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
        <label className="field">Publisher<input value={form.publisher || ""} onChange={(e) => setForm({ ...form, publisher: e.target.value })} /></label>
        <label className="field">Platform<select value={form.platform} onChange={(e) => setForm({ ...form, platform: e.target.value, installer: INSTALLERS[e.target.value][0] })}>
          <option value="windows">Windows</option><option value="linux">Linux</option><option value="macos">macOS</option></select></label>
        <label className="field">Installer<select value={form.installer} onChange={(e) => setForm({ ...form, installer: e.target.value })}>{INSTALLERS[form.platform].map((i) => <option key={i}>{i}</option>)}</select></label>
      </div>
      <label className="field" style={{ marginTop: 10 }}>{direct ? "Download URL (https)" : "Package id"}<input value={form.identifier} onChange={(e) => setForm({ ...form, identifier: e.target.value })}
             placeholder={direct ? "https://vendor.example/app.msi" : form.installer === "winget" ? "Vendor.App" : "package-name"} /></label>
      {direct && <label className="field" style={{ marginTop: 10 }}>SHA-256 of the installer<input value={form.sha256 || ""} onChange={(e) => setForm({ ...form, sha256: e.target.value.trim() })} className="mono" /></label>}
      {direct && <label className="field" style={{ marginTop: 10 }}>Silent install arguments<input value={form.installArgs || ""} onChange={(e) => setForm({ ...form, installArgs: e.target.value })} placeholder="/qn /norestart" /></label>}
      <label className="small" style={{ display: "block", marginTop: 10 }}><input type="checkbox" checked={form.keepUpdated} onChange={(e) => setForm({ ...form, keepUpdated: e.target.checked })} /> Keep it updated through third-party patching</label>
    </Modal>
  );
}
