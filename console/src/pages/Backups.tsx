// Device backup: image backups of servers, PCs and Hyper-V hosts with the Fenrir backup agent (backup/ in this
// repository). Repository passphrases and share passwords are sealed in this browser to each machine's key; the
// server keeps only the sealed copies and can never open a backup.
import { Fragment, useMemo, useState } from "react";
import { api, ago, fmtTime, getToken } from "../api";
import { useApp } from "../app-context";
import { newRecoveryKey, seal, sealSupported, type Sealed } from "../backup-seal";
import { FileBrowser } from "./BackupFiles";
import { confirmDialog, promptDialog } from "../components/dialogs";
import { ErrorNote, Modal, PageHead, Pill, Stat, Table, Tabs, TenantSelect, useAction, useAutoRefresh, useData, useListData } from "../components/ui";

export interface BackupAgent {
  id: string; tenantId: string; deviceId: string | null; name: string; hostname: string; role: string;
  os: { family?: string; name?: string; version?: string; arch?: string }; agentVersion: string; online: boolean;
  lastSeenAt: string | null; publicKey: string; capabilities: string[]; vmCount: number; disks: string[];
  diskInfo?: { path: string; size: number; model: string; serial: string; system: boolean; inUse: boolean }[];
  firmware?: "uefi" | "bios" | null; secureBoot?: boolean | null;
  runningVms?: { sessionId: string; imageId: string; startedUnix: number; vncPort: number }[];
  lastBackup: { jobId: string; state: string; at: string; error: string | null } | null;
  runningJob: { id: string; label: string; state: string; progress: any } | null;
}
interface Repo {
  id: string; tenantId: string; name: string; path: string; repoUuid: string; status: string; statusMessage: string | null;
  images: number; storedBytes: number; lastImage: number | null; hold: boolean; holdReason: string | null; holdSince: string | null;
  maintenanceAgentId: string | null; pruneEveryDays: number; lastPruneAt: string | null; anomalies: number;
  bootAgentId: string | null; bootEveryDays: number; lastVerifiedBoot: string | null; shareAuth: string; shareUser: string | null;
  isShare: boolean; agents: { id: string; name: string; viaGateway?: boolean }[];
  s3?: S3Settings | null;
  gateway: { agentId: string; name: string; online: boolean; port: number; address: string | null; addresses: string[] } | null;
}
interface Job {
  id: string; agentId: string; agentName: string; repositoryId: string | null; label: string; state: string; kind: any;
  createdAt: string; finishedAt: string | null; progress: any; result: any; error: string | null; warnings: string[]; requestedBy: string;
}
interface Plan {
  id: string; name: string; agentId: string; agentName: string; repositoryId: string; job: any; label: string;
  schedule: any; retention: any; enabled: boolean; nextRunAt: string | null; lastRunAt: string | null;
}
interface Image {
  imageId: string; repositoryId: string; agentId: string | null; hostname: string; created: number; kind: string;
  consistency: string; capturedBytes: number; storedNewBytes: number; disks: any[]; label: string | null; vmName: string | null;
  anomaly: string | null; lastBootCheck: { outcome: string; at: string; message: string } | null;
}

const FINAL = ["succeeded", "warning", "failed", "cancelled"];
const STATE_TONE: Record<string, string> = { succeeded: "good", warning: "warn", failed: "bad", cancelled: "muted", queued: "muted", dispatched: "blue", running: "blue" };
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

export function bytes(n: number | null | undefined): string {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  let v = n, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${u[i]}`;
}
const unixTime = (t: number | null) => (t ? new Date(t * 1000).toLocaleString() : "—");
const isSharePath = (p: string) => /^(\\\\|\/\/|smb:\/\/)/i.test(p.trim());
const StatePill = ({ state }: { state: string }) => <Pill value={state} tone={STATE_TONE[state] ?? "muted"} />;

function progressText(p: any): string {
  if (!p) return "";
  const pct = p.bytes_total ? ` ${Math.floor((100 * (p.bytes_done || 0)) / p.bytes_total)}%` : "";
  return `${p.phase || ""}${pct}`.trim();
}

/** Poll a job until it finishes (connection tests, repository creation). */
async function waitForJob(id: string, tries = 90): Promise<Job | null> {
  for (let i = 0; i < tries; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const j = await api<Job>(`backup/jobs/${id}`);
    if (FINAL.includes(j.state)) return j;
  }
  return null;
}

export default function Backups() {
  const { tenantId } = useApp();
  const [tab, setTab] = useState("Overview");
  const q = { tenantId: tenantId || undefined };
  const overview = useData<any>("backup/overview", q, [tenantId]);
  const agents = useListData<BackupAgent>("backup/agents", q, [tenantId]);
  const repos = useListData<Repo>("backup/repositories", q, [tenantId]);
  const reloadAll = () => { overview.reload(); agents.reload(); repos.reload(); };
  useAutoRefresh(reloadAll, 15000);
  const [adding, setAdding] = useState(false);
  const { can } = useApp();
  return (
    <>
      <PageHead title="Backups" subtitle="Image backups of servers, PCs and Hyper-V hosts into repositories you own: a NAS, a file server or a local disk. Encrypted on the machine; this server never sees the keys."
        actions={can("configure") && <button className="primary" onClick={() => setAdding(true)}>Add machines</button>} />
      {!sealSupported() && <div className="card warn-card">This browser cannot encrypt repository secrets (Web Crypto X25519 is needed). Use a current Chrome, Edge, Firefox or Safari over HTTPS.</div>}
      <Tabs tabs={["Overview", "Machines", "Repositories", "Plans", "Images & restore", "Activity"]} active={tab} onChange={setTab} />
      <ErrorNote error={overview.error || agents.error || repos.error} />
      {tab === "Overview" && <Overview data={overview.data} agents={agents.data} />}
      {tab === "Machines" && <Machines agents={agents.data} repos={repos.data ?? []} reload={reloadAll} />}
      {tab === "Repositories" && <Repositories repos={repos.data} agents={agents.data ?? []} reload={reloadAll} />}
      {tab === "Plans" && <Plans agents={agents.data ?? []} repos={repos.data ?? []} />}
      {tab === "Images & restore" && <Images agents={agents.data ?? []} repos={repos.data ?? []} />}
      {tab === "Activity" && <Activity />}
      {adding && <AddMachines onClose={() => { setAdding(false); reloadAll(); }} />}
    </>
  );
}

function Overview({ data, agents }: { data: any; agents: BackupAgent[] | null }) {
  if (!data) return <div className="empty">Loading…</div>;
  const failing = (agents ?? []).filter((a) => a.lastBackup && a.lastBackup.state === "failed");
  return (
    <>
      {data.holds.map((h: any) => (
        <div key={h.id} className="card warn-card" style={{ marginBottom: 12 }}>
          <b>{h.name} is on hold</b> since {fmtTime(h.since)}: {h.reason}. Old backups are not deleted until the hold is released.
        </div>
      ))}
      <div className="grid k4" style={{ marginBottom: 14 }}>
        <Stat label="Machines" value={`${data.online}/${data.machines} online`} />
        <Stat label="Last 24 hours" value={`${data.last24h.succeeded} ok`} hint={`${data.last24h.warning} with warnings, ${data.last24h.failed} failed`} accent={data.last24h.failed ? "bad" : undefined} />
        <Stat label="Repositories" value={data.repositories} hint={data.onHold ? `${data.onHold} on hold` : "none on hold"} />
        <Stat label="Stored" value={bytes(data.storedBytes)} hint={`${data.images} images`} />
      </div>
      <div className="card">
        <h3>Needs attention</h3>
        {failing.length === 0 && !data.holds.length ? <div className="muted">Nothing: every machine's last backup succeeded.</div> : (
          <Table rows={failing} columns={[
            { key: "name", label: "Machine" },
            { key: "at", label: "Failed", render: (a) => ago(a.lastBackup?.at) },
            { key: "error", label: "Reason", render: (a) => <span className="small">{a.lastBackup?.error}</span> },
          ]} />
        )}
      </div>
    </>
  );
}

// ---------------------------------------------------------------- machines

function Machines({ agents, repos, reload }: { agents: BackupAgent[] | null; repos: Repo[]; reload: () => void }) {
  const [open, setOpen] = useState<BackupAgent | null>(null);
  const { tenantName } = useApp();
  return (
    <div className="card">
      <Table rows={agents} onRow={setOpen} empty="No machines yet. Use Add machines to install the backup agent."
        columns={[
          { key: "name", label: "Machine", render: (a) => <><b>{a.name}</b>{a.name !== a.hostname && <div className="small muted">{a.hostname}</div>}</> },
          { key: "tenant", label: "Customer", render: (a) => tenantName(a.tenantId) },
          { key: "os", label: "System", render: (a) => <span className="small">{a.os.name || a.os.family} {a.os.version} · {a.role === "hyperv" ? `Hyper-V host (${a.vmCount} VMs)` : a.role === "recovery" ? "recovery session (restores only)" : a.role}</span> },
          { key: "online", label: "Status", render: (a) => a.runningJob ? <Pill value={`${a.runningJob.label} ${progressText(a.runningJob.progress)}`} tone="blue" /> : <Pill value={a.online ? "online" : "offline"} tone={a.online ? "good" : "muted"} /> },
          { key: "last", label: "Last backup", render: (a) => a.lastBackup ? <><StatePill state={a.lastBackup.state} /> <span className="small muted">{ago(a.lastBackup.at)}</span></> : <span className="muted small">never</span> },
        ]} />
      {open && <MachineModal agent={open} repos={repos} onClose={() => { setOpen(null); reload(); }} />}
    </div>
  );
}

function MachineModal({ agent, repos, onClose }: { agent: BackupAgent; repos: Repo[]; onClose: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const detail = useData<any>(`backup/agents/${agent.id}`);
  const mine = repos.filter((r) => r.agents.some((a) => a.id === agent.id) && r.status === "ready");
  const [repo, setRepo] = useState(mine[0]?.id ?? "");
  const kind = agent.capabilities.includes("backup_hyperv") ? { type: "backup_hyperv", vm_ids: [] } : agent.capabilities.includes("backup_system") ? { type: "backup_system" } : null;
  const start = (k: any) => run(() => api("backup/agents/" + agent.id + "/jobs", { body: { kind: k, repositoryId: repo } }), "Queued: the machine picks it up within a minute");
  const inv = detail.data?.inventory;
  return (
    <Modal wide title={agent.name} onClose={onClose}
      footer={can("configure") && <>
        <button disabled={busy} onClick={async () => { const n = await promptDialog("Display name", agent.name); if (n !== null) await run(() => api(`backup/agents/${agent.id}`, { method: "PATCH", body: { name: n } }), "Renamed"); }}>Rename</button>
        <button className="danger" disabled={busy} onClick={async () => {
          if (await confirmDialog(`Remove ${agent.name}? It can no longer reach the server; its backups are kept. Uninstall the agent on the machine too.`, { danger: true }))
            await run(() => api(`backup/agents/${agent.id}`, { method: "DELETE" }), "Machine removed").then(onClose);
        }}>Remove</button>
      </>}>
      <div className="small muted" style={{ marginBottom: 10 }}>
        {agent.os.name} {agent.os.version} ({agent.os.arch}) · agent {agent.agentVersion} · {agent.online ? "online" : `last seen ${ago(agent.lastSeenAt)}`}
      </div>
      {can("respond") && (
        <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
          <select value={repo} onChange={(e) => setRepo(e.target.value)}>
            {mine.length === 0 && <option value="">No repository yet</option>}
            {mine.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
          {kind && <button className="primary" disabled={busy || !repo} onClick={() => start(kind)}>Back up now</button>}
          <button disabled={busy || !repo} onClick={() => start({ type: "verify", level: "sample", sample_percent: 5 })}>Verify (5% sample)</button>
          <button disabled={busy || !repo} onClick={() => start({ type: "list_images" })}>Refresh images</button>
        </div>
      )}
      {inv?.disks?.length > 0 && <div className="small" style={{ marginBottom: 8 }}>Disks: {inv.disks.map((d: any) => `${d.path} (${bytes(d.size)}${d.system ? ", system" : ""})`).join(" · ")}</div>}
      {inv?.vms?.length > 0 && <div className="small" style={{ marginBottom: 8 }}>VMs: {inv.vms.map((v: any) => `${v.name} (${v.state})`).join(" · ")}</div>}
      {inv?.notes?.map((n: string, i: number) => <div key={i} className="small muted">{n}</div>)}
      {inv?.running_vms?.length > 0 && (
        <div className="card" style={{ marginTop: 10 }}>
          <b>VMs running from backups</b>
          {inv.running_vms.map((v: any) => (
            <div key={v.session_id} className="row small" style={{ gap: 8 }}>
              Image {v.image_id.slice(0, 8)} since {unixTime(v.started_unix)}{v.vnc_port ? ` · console on the host at 127.0.0.1:${v.vnc_port}` : ""}
              {can("scripts") && <button className="small" onClick={() => run(() => api(`backup/agents/${agent.id}/vms/${v.session_id}/stop`, { body: {} }), "Stopping the VM")}>Stop</button>}
            </div>
          ))}
        </div>
      )}
      <h3 style={{ marginTop: 14 }}>Recent jobs</h3>
      <JobsTable rows={detail.data?.jobs ?? null} />
    </Modal>
  );
}

// ---------------------------------------------------------------- add machines

function AddMachines({ onClose }: { onClose: () => void }) {
  const { tenantId } = useApp();
  const [tenant, setTenant] = useState(tenantId);
  const [role, setRole] = useState("server");
  const [days, setDays] = useState(7);
  const [result, setResult] = useState<any>(null);
  const { run, busy } = useAction();
  const create = async () => setResult(await run(() => api("backup/enrollments", { body: { tenantId: tenant, role, days } })));
  const copy = (s: string) => navigator.clipboard?.writeText(s);
  return (
    <Modal wide title="Add machines to backup" onClose={onClose}>
      {!result ? (
        <>
          <div className="form-grid">
            <label className="field">Customer<TenantSelect value={tenant} onChange={setTenant} allowAll={false} /></label>
            <label className="field">These machines are
              <select value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="server">Servers</option><option value="workstation">Desktops and laptops</option><option value="hyperv">Hyper-V hosts (back up their VMs)</option>
                <option value="recovery">Recovery media (bare-metal restore)</option>
              </select>
            </label>
            <label className="field">Link valid for (days)<input type="number" min={1} max={90} value={days} onChange={(e) => setDays(Number(e.target.value))} /></label>
          </div>
          <p className="small">Machines installed with the Fenrir agent installer (Deploy agents) already have device backup: they appear here on their own. Use these links for machines that should only be backed up.</p>
          <p className="small muted">One link installs any number of machines until it expires. Each installs the backup agent as a protected system service (FenrirBackupAgent on Windows) that only administrators can stop or remove. It is separate from the Fenrir security agent and does not touch it.</p>
          {role === "recovery" && <p className="small">Recovery media is a bootable USB stick or ISO for a machine that no longer starts, or new hardware. Started from it, the machine appears under Machines as a recovery session (restores only); restore a backup onto its disk from Images &amp; restore. Works with Secure Boot on.</p>}
          <button className="primary" disabled={busy || !tenant} onClick={create}>{role === "recovery" ? "Create recovery media" : "Create install links"}</button>
        </>
      ) : (
        <>
          <p className="small">Expires {fmtTime(result.expiresAt)}. Treat these links like a password: anyone with one can add a machine to this customer.</p>
          {result.recovery && (result.recovery.available ? (
            <div className="card" style={{ marginBottom: 10 }}>
              <div className="row" style={{ gap: 8 }}>
                <a className="btn primary" href={result.recovery.iso} download>Download fenrir-recovery.iso{result.recovery.size ? ` (${bytes(result.recovery.size)})` : ""}</a>
                <a className="btn" href={result.recovery.settings} download>Settings file only</a>
              </div>
              <ol className="small" style={{ marginTop: 8 }}>
                <li>Write the ISO to a USB stick (balenaEtcher, Rufus in DD mode, or dd), or attach it to a VM as a DVD.</li>
                <li>Start the machine from it (boot menu: usually F12, F11, F8 or Esc). Wired networks connect by themselves; Wi-Fi and fixed addresses are under Network settings on its screen.</li>
                <li>It appears under Machines as a recovery session. In Images &amp; restore, restore a backup with it as the machine and its disk as the target.</li>
              </ol>
              <p className="small muted">The ISO carries this server's address and an enrolment code for recovery sessions until it expires. A session cannot read any backup until you give it access. With a stick from elsewhere, put the settings file in the root of any USB stick and choose "Look for server settings on a USB stick" on the recovery screen.</p>
            </div>
          ) : <div className="card warn-card">The recovery ISO is not on this server yet: place fenrir-recovery.iso from the Fenrir-Backup build in the backup agents folder under recovery/ (see docs/DEVICE_BACKUP.md).</div>)}
          {Object.entries(result.links ?? {}).map(([key, l]: [string, any]) => (
            <div key={key} className="card" style={{ marginBottom: 10, opacity: l.available ? 1 : 0.6 }}>
              <div className="row" style={{ justifyContent: "space-between" }}><b>{l.name}</b>{!l.available && <Pill value="not built on this server yet" tone="warn" />}</div>
              {l.setup && <div className="row" style={{ gap: 8, marginTop: 6 }}><a className="btn primary" href={l.setup} download>Download {l.setupFile}</a><span className="small muted">Double-click and approve the administrator prompt.</span></div>}
              <div className="small muted" style={{ marginTop: 6 }}>{l.setup ? "Or paste into an elevated PowerShell:" : "Run as root:"}</div>
              <div className="row" style={{ gap: 6 }}><code className="mono" style={{ flex: 1, overflowX: "auto", whiteSpace: "nowrap" }}>{l.oneLiner}</code><button className="small" onClick={() => copy(l.oneLiner)}>Copy</button></div>
            </div>
          ))}
          {result.uninstall && <p className="small muted">To uninstall later: {Object.entries(result.uninstall).map(([k, u]: [string, any]) => <Fragment key={k}><a href={u}>{k}</a>{" "}</Fragment>)}</p>}
        </>
      )}
    </Modal>
  );
}

// ---------------------------------------------------------------- repositories

interface Signin { mode: "none" | "password" | "machine"; domain: string; username: string; password: string }
const noSignin = (): Signin => ({ mode: "password", domain: "", username: "", password: "" });
const signinUser = (s: Signin) => (s.domain.trim() && !s.username.includes("\\") && !s.username.includes("@") ? `${s.domain.trim()}\\${s.username.trim()}` : s.username.trim());
const signinOk = (s: Signin) => s.mode !== "password" || (s.username.trim() !== "" && s.password !== "");
const sealSignin = (a: BackupAgent, s: Signin) => seal(a.publicKey, JSON.stringify({ domain: s.domain.trim(), username: s.username.trim(), password: s.password }));

function SigninFields({ value, onChange }: { value: Signin; onChange: (s: Signin) => void }) {
  return (
    <>
      <div className="tabs" style={{ marginBottom: 8 }}>
        <button className={value.mode === "password" ? "active" : ""} onClick={() => onChange({ ...value, mode: "password" })}>Username and password</button>
        <button className={value.mode === "machine" ? "active" : ""} onClick={() => onChange({ ...value, mode: "machine" })}>Computer account</button>
        <button className={value.mode === "none" ? "active" : ""} onClick={() => onChange({ ...value, mode: "none" })}>No sign-in</button>
      </div>
      {value.mode === "password" && (
        <div className="form-grid">
          <label className="field">Domain (optional)<input value={value.domain} onChange={(e) => onChange({ ...value, domain: e.target.value })} placeholder="CORP, or empty for a NAS account" autoComplete="off" /></label>
          <label className="field">Username<input value={value.username} onChange={(e) => onChange({ ...value, username: e.target.value })} placeholder="backup-svc" autoComplete="off" /></label>
          <label className="field">Password<input type="password" value={value.password} onChange={(e) => onChange({ ...value, password: e.target.value })} autoComplete="new-password" /></label>
        </div>
      )}
      <p className="small muted">
        {value.mode === "password" && "Encrypted in this browser for each machine; the server never sees it. Use an account only this share accepts. Machines connect only while a job runs, out of sight of logged-in users."}
        {value.mode === "machine" && "Domain-joined Windows machines reach the share as their computer account (DOMAIN\\NAME$). Give those accounts, or an AD group of them, change rights on the share. No password is stored."}
        {value.mode === "none" && "The share must already accept the machines as they are (guest access or an existing session)."}
      </p>
    </>
  );
}

interface S3Settings { endpoint: string; region: string; path_style: boolean; lock_mode: "governance" | "compliance" | null; lock_days: number }
interface S3Form { endpoint: string; region: string; bucket: string; prefix: string; pathStyle: boolean; lockMode: "none" | "governance" | "compliance"; lockDays: number; accessKey: string; secretKey: string }
const emptyS3 = (): S3Form => ({ endpoint: "https://s3.eu-west-2.amazonaws.com", region: "eu-west-2", bucket: "", prefix: "fenrir", pathStyle: false, lockMode: "compliance", lockDays: 30, accessKey: "", secretKey: "" });
const s3Path = (f: S3Form) => `s3://${f.bucket.trim()}${f.prefix.trim() ? "/" + f.prefix.trim().replace(/^\/+|\/+$/g, "") : ""}`;
const s3Settings = (f: S3Form): S3Settings => ({ endpoint: f.endpoint.trim().replace(/\/+$/, ""), region: f.region.trim() || "us-east-1", path_style: f.pathStyle, lock_mode: f.lockMode === "none" ? null : f.lockMode, lock_days: f.lockMode === "none" ? 0 : f.lockDays });
const s3Signin = (f: S3Form): Signin => ({ mode: "password", domain: "", username: f.accessKey.trim(), password: f.secretKey });
const s3Ok = (f: S3Form) => /^https?:\/\/[^/\s]+$/.test(f.endpoint.trim().replace(/\/+$/, "")) && /^[a-z0-9.-]{3,63}$/.test(f.bucket.trim()) && !!f.accessKey.trim() && !!f.secretKey && (f.lockMode === "none" || (f.lockDays > 7 && f.lockDays <= 36500));

function S3Fields({ value: f, onChange }: { value: S3Form; onChange: (f: S3Form) => void }) {
  const set = (p: Partial<S3Form>) => onChange({ ...f, ...p });
  return (
    <div className="form-grid">
      <label className="field">Endpoint<input value={f.endpoint} onChange={(e) => set({ endpoint: e.target.value })} placeholder="https://s3.eu-west-2.amazonaws.com" /></label>
      <label className="field">Region<input value={f.region} onChange={(e) => set({ region: e.target.value })} placeholder="eu-west-2 (us-east-1 for most others)" /></label>
      <label className="field">Bucket (created with Object Lock enabled)<input value={f.bucket} onChange={(e) => set({ bucket: e.target.value.toLowerCase() })} /></label>
      <label className="field">Folder in the bucket<input value={f.prefix} onChange={(e) => set({ prefix: e.target.value })} /></label>
      <label className="field">Access key ID<input value={f.accessKey} onChange={(e) => set({ accessKey: e.target.value })} autoComplete="off" /></label>
      <label className="field">Secret access key<input type="password" value={f.secretKey} onChange={(e) => set({ secretKey: e.target.value })} autoComplete="new-password" /></label>
      <label className="field">Immutable backups (Object Lock)<select value={f.lockMode} onChange={(e) => set({ lockMode: e.target.value as S3Form["lockMode"] })}>
        <option value="compliance">Compliance: nobody can delete a backup early</option>
        <option value="governance">Governance: only special admin rights can</option>
        <option value="none">Off</option>
      </select></label>
      {f.lockMode !== "none" && <label className="field">Keep each backup locked for (days, more than 7)<input type="number" min={8} max={36500} value={f.lockDays} onChange={(e) => set({ lockDays: Number(e.target.value) })} /></label>}
      <label className="row small" style={{ gap: 6 }}><input type="checkbox" checked={f.pathStyle} onChange={(e) => set({ pathStyle: e.target.checked })} /> Path-style addresses (MinIO and most self-hosted storage)</label>
    </div>
  );
}

function TestConnection({ agent, path, signin, s3 }: { agent?: BackupAgent; path: string; signin: Signin | null; s3?: S3Settings | null }) {
  const [state, setState] = useState<{ busy?: boolean; job?: Job | null; err?: string; key?: string }>({});
  const key = JSON.stringify([agent?.id, path.trim(), signin, s3]);
  const go = async () => {
    if (!agent) return;
    setState({ busy: true, key });
    try {
      const sealedShare = signin && signin.mode === "password" ? await sealSignin(agent, signin) : null;
      const { id } = await api<{ id: string }>(`backup/agents/${agent.id}/check-access`, { body: { path, sealedShare, s3: s3 ?? null } });
      const job = await waitForJob(id);
      setState(job ? { job, key } : { err: `${agent.name} did not answer in time. Is it online?`, key });
    } catch (e) { setState({ err: (e as Error).message, key }); }
  };
  const cur = state.key === key ? state : {};
  const r = cur.job?.result;
  return (
    <div style={{ margin: "8px 0" }}>
      <button className="small" disabled={!agent || !path.trim() || !!state.busy || (signin !== null && !signinOk(signin))} onClick={go}>
        {state.busy ? "Testing…" : `Test connection${agent ? ` from ${agent.name}` : ""}`}
      </button>
      {cur.err && <div className="small" style={{ color: "#fca5a5" }}>{cur.err}</div>}
      {cur.job?.state === "failed" && <div className="small" style={{ color: "#fca5a5" }}>{cur.job.error}</div>}
      {cur.job && r && cur.job.state !== "failed" && (
        <div className="small" style={{ color: "#86efac" }}>
          {r.s3 ? `Object storage: ${r.note}.` : <>{r.share ? "Signed in to the share and wrote a test file." : "Wrote a test file."} {r.repository ? "A repository is already there." : r.exists ? "The folder exists." : "The folder will be created."}</>}
          {r.free_bytes != null && ` Free: ${bytes(r.free_bytes)} of ${bytes(r.total_bytes)}.`}
          {cur.job.warnings.map((w, i) => <div key={i}>{w}</div>)}
        </div>
      )}
    </div>
  );
}

function Repositories({ repos, agents, reload }: { repos: Repo[] | null; agents: BackupAgent[]; reload: () => void }) {
  const { can, tenantName } = useApp();
  const { run, busy } = useAction();
  const [creating, setCreating] = useState(false);
  const [grant, setGrant] = useState<Repo | null>(null);
  const [share, setShare] = useState<Repo | null>(null);
  const [gateway, setGateway] = useState<Repo | null>(null);
  const act = (fn: () => Promise<unknown>, msg: string) => run(fn, msg).then(reload);
  const name = (id: string | null) => agents.find((a) => a.id === id)?.name ?? "—";
  return (
    <>
      {can("configure") && <button className="primary" style={{ marginBottom: 12 }} onClick={() => setCreating(true)}>New repository</button>}
      {repos == null && <div className="empty">Loading…</div>}
      {repos?.length === 0 && <div className="card empty">No repositories. A repository is a folder on a NAS, file server or disk that holds the encrypted backups.</div>}
      {repos?.map((r) => {
        const members = agents.filter((a) => r.agents.some((x) => x.id === a.id));
        const bootHosts = members.filter((a) => a.capabilities.some((c) => c === "boot_kvm" || c === "boot_hyperv"));
        return (
          <div key={r.id} className={`card${r.hold ? " warn-card" : ""}`} style={{ marginBottom: 12 }}>
            <div className="row" style={{ justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
              <div><b>{r.name}</b> <span className="small muted">{tenantName(r.tenantId)}</span><div className="mono small">{r.path}</div></div>
              <div className="row" style={{ gap: 6 }}><StatePill state={r.status} />{r.hold && <Pill value="on hold" tone="bad" />}</div>
            </div>
            {r.statusMessage && <div className="small" style={{ color: "#fca5a5" }}>{r.statusMessage}</div>}
            {r.hold && <div className="small" style={{ marginTop: 6 }}><b>Hold</b> since {fmtTime(r.holdSince)}: {r.holdReason}. Retention and space reclamation wait until it is released.</div>}
            <div className="small" style={{ marginTop: 6 }}>
              {r.images} images · {bytes(r.storedBytes)} stored · last {unixTime(r.lastImage)} · machines: {r.agents.map((a) => a.name).join(", ") || "none"}
              {r.isShare && <> · share sign-in: {r.shareAuth === "password" ? r.shareUser : r.shareAuth === "machine" ? "computer account" : "none"}</>}
              {r.s3 && <> · object storage, key {r.shareUser} · {r.s3.lock_mode ? `Object Lock ${r.s3.lock_mode}, ${r.s3.lock_days} days` : "no Object Lock"}</>}
            </div>
            {r.gateway && (
              <div className="small" style={{ marginTop: 4 }}>
                Gateway: <b>{r.gateway.name}</b> {r.gateway.online ? "" : <Pill value="offline" tone="bad" />} serves it to{" "}
                {r.agents.filter((a) => a.viaGateway).map((a) => a.name).join(", ") || "no machines yet"}
                {" "}· {r.gateway.port ? `direct on ${[...r.gateway.addresses].join(", ") || `port ${r.gateway.port}`}, else relayed` : "relayed through this server"}
              </div>
            )}
            <div className="small muted">Reclaim space every {r.pruneEveryDays || "—"} days on {name(r.maintenanceAgentId)} (last {fmtTime(r.lastPruneAt) || "never"}) · boot verification {r.bootEveryDays ? `every ${r.bootEveryDays} days on ${name(r.bootAgentId)}, last verified ${fmtTime(r.lastVerifiedBoot) || "never"}` : "off"}</div>
            <div className="row" style={{ gap: 6, marginTop: 8, flexWrap: "wrap" }}>
              {can("configure") && <button className="small" onClick={() => setGrant(r)}>Give a machine access</button>}
              {can("configure") && (r.isShare || r.s3) && <button className="small" onClick={() => setShare(r)}>{r.s3 ? "Change access keys" : "Change share sign-in"}</button>}
              {can("configure") && <button className="small" onClick={() => setGateway(r)}>{r.gateway ? "Gateway settings" : "Serve through a gateway"}</button>}
              {!r.hold && can("respond") && <button className="small" disabled={busy} onClick={async () => { const why = await promptDialog("Reason for the hold (legal hold, investigation…)", ""); if (why !== null) act(() => api(`backup/repositories/${r.id}/hold`, { body: { hold: true, reason: why } }), "Hold placed"); }}>Place on hold</button>}
              {r.hold && can("destructive") && <button className="small danger" disabled={busy} onClick={async () => { if (await confirmDialog("Release the hold? Retention will delete old images again. Make sure the machine is clean first.")) act(() => api(`backup/repositories/${r.id}/hold`, { body: { hold: false } }), "Hold released"); }}>Release hold</button>}
              {can("respond") && <button className="small" disabled={busy || !r.maintenanceAgentId} onClick={() => act(() => api(`backup/repositories/${r.id}/prune`, { body: { dryRun: true } }), "Dry run queued: see Activity")}>Estimate reclaimable space</button>}
              {can("destructive") && <button className="small" disabled={busy || r.hold || !r.maintenanceAgentId} onClick={async () => { if (await confirmDialog("Delete data no image uses any more? This cannot be undone.")) act(() => api(`backup/repositories/${r.id}/prune`, { body: { dryRun: false } }), "Space reclamation queued"); }}>Reclaim space now</button>}
              {can("configure") && <select className="small" value={r.maintenanceAgentId ?? ""} onChange={(e) => act(() => api(`backup/repositories/${r.id}/maintenance`, { body: { agentId: e.target.value } }), "Maintenance machine set")} title="Machine that reclaims space">
                {members.map((a) => <option key={a.id} value={a.id}>Maintenance: {a.name}</option>)}
              </select>}
              {can("configure") && <button className="small" onClick={async () => { const d = await promptDialog("Reclaim space every how many days? (0 = never)", String(r.pruneEveryDays)); if (d !== null) act(() => api(`backup/repositories/${r.id}/maintenance`, { body: { pruneEveryDays: Number(d) } }), "Saved"); }}>Reclaim interval</button>}
              {can("configure") && bootHosts.length > 0 && <button className="small" onClick={async () => {
                const d = await promptDialog(`Boot-test each machine's newest image every how many days on ${bootHosts[0].name}? (0 = off)`, String(r.bootEveryDays || 7));
                if (d !== null) act(() => api(`backup/repositories/${r.id}/boot-verification`, { body: Number(d) > 0 ? { agentId: bootHosts[0].id, everyDays: Number(d) } : {} }), "Boot verification saved");
              }}>Boot verification</button>}
              {can("configure") && <button className="small danger" onClick={async () => { if (await confirmDialog(`Forget ${r.name}? The server forgets it; the backup data on the storage is not touched.`)) act(() => api(`backup/repositories/${r.id}`, { method: "DELETE" }), "Repository forgotten"); }}>Forget</button>}
            </div>
            {r.agents.length > 0 && can("configure") && (
              <div className="small muted" style={{ marginTop: 6 }}>Remove access: {r.agents.map((a) => <button key={a.id} className="small ghost" onClick={() => act(() => api(`backup/repositories/${r.id}/access/${a.id}`, { method: "DELETE" }), "Access removed")}>{a.name} ✕</button>)}</div>
            )}
          </div>
        );
      })}
      {creating && <CreateRepo agents={agents} onClose={() => { setCreating(false); reload(); }} />}
      {grant && <GrantAccess repo={grant} agents={agents} onClose={() => { setGrant(null); reload(); }} />}
      {share && <ShareSignin repo={share} agents={agents} onClose={() => { setShare(null); reload(); }} />}
      {gateway && <GatewayDialog repo={gateway} agents={agents} onClose={() => { setGateway(null); reload(); }} />}
    </>
  );
}

function CreateRepo({ agents, onClose }: { agents: BackupAgent[]; onClose: () => void }) {
  const { run, busy } = useAction();
  const recovery = useMemo(() => newRecoveryKey(), []);
  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [path, setPath] = useState("");
  const [pass, setPass] = useState("");
  const [pass2, setPass2] = useState("");
  const [members, setMembers] = useState<string[]>([]);
  const [creator, setCreator] = useState("");
  const [signin, setSignin] = useState<Signin>(noSignin());
  const [kind, setKind] = useState<"folder" | "s3">("folder");
  const [s3, setS3] = useState<S3Form>(emptyS3());
  const [saved, setSaved] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const isS3 = kind === "s3";
  const tenant = agents.find((a) => a.id === (creator || members[0]))?.tenantId;
  const pool = agents.filter((a) => !tenant || a.tenantId === tenant);
  const share = !isS3 && isSharePath(path);
  const location = isS3 ? s3Path(s3) : path;
  const ok = name.trim() && (isS3 ? s3Ok(s3) : path.trim()) && pass.length >= 12 && pass === pass2 && members.length > 0 && members.includes(creator) && (!share || signinOk(signin));
  const download = () => {
    const blob = new Blob([recovery.fileContents], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `fenrir-recovery-${name.replace(/[^\w-]+/g, "-").toLowerCase()}-${recovery.repoId.slice(0, 8)}.json`;
    a.click();
  };
  const create = async () => {
    const res = await run(async () => {
      const access = await Promise.all(members.map(async (id) => {
        const a = agents.find((x) => x.id === id)!;
        const secret = JSON.stringify({ passphrase: pass, recovery_key: id === creator ? recovery.fileContents : null });
        return { agentId: id, sealed: await seal(a.publicKey, secret), sealedShare: isS3 ? await sealSignin(a, s3Signin(s3)) : share && signin.mode === "password" ? await sealSignin(a, signin) : null };
      }));
      return api<{ id: string; initJobId: string }>("backup/repositories", { body: {
        name, path: location, repoUuid: recovery.repoId, initAgentId: creator, access,
        share_auth: isS3 ? "password" : share ? signin.mode : "none",
        share_user: isS3 ? s3.accessKey.trim() : share && signin.mode === "password" ? signinUser(signin) : null,
        s3: isS3 ? s3Settings(s3) : null } });
    });
    if (!res) return;
    setStatus("Creating the repository on the machine…");
    const job = await waitForJob(res.initJobId);
    setStatus(job ? (job.state === "failed" ? `Failed: ${job.error}` : "Ready.") : "Still waiting for the machine: check Activity.");
  };
  return (
    <Modal wide title="New repository" onClose={onClose}>
      {step === 0 && (
        <>
          <div className="form-grid">
            <label className="field">Name<input value={name} onChange={(e) => setName(e.target.value)} placeholder="Office NAS" /></label>
            <label className="field">Stored on<select value={kind} onChange={(e) => setKind(e.target.value as "folder" | "s3")}><option value="folder">A folder or network share</option><option value="s3">S3 object storage (AWS, Wasabi, B2, R2, MinIO…)</option></select></label>
            {!isS3 && <label className="field">Folder (on the machines)<input value={path} onChange={(e) => setPath(e.target.value)} placeholder={"\\\\nas\\backups\\fenrir or /mnt/backup"} /></label>}
            <label className="field">Passphrase (12+ characters)<input type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" /></label>
            <label className="field">Confirm passphrase<input type="password" value={pass2} onChange={(e) => setPass2(e.target.value)} autoComplete="new-password" /></label>
          </div>
          <h3 style={{ marginTop: 12 }}>Machines that use it</h3>
          {pool.map((a) => (
            <label key={a.id} className="row small" style={{ gap: 6 }}>
              <input type="checkbox" checked={members.includes(a.id)} onChange={(e) => { const m = e.target.checked ? [...members, a.id] : members.filter((x) => x !== a.id); setMembers(m); if (!m.includes(creator)) setCreator(m[0] ?? ""); }} />
              {a.name} {!a.online && <span className="muted">(offline)</span>}
              {members.includes(a.id) && <label className="small muted" style={{ marginLeft: 8 }}><input type="radio" checked={creator === a.id} onChange={() => setCreator(a.id)} /> creates it</label>}
            </label>
          ))}
          {isS3 && <><h3 style={{ marginTop: 12 }}>Object storage</h3><S3Fields value={s3} onChange={setS3} />
            {s3.lockMode === "compliance" && <p className="small">Every backup stays undeletable for at least {s3.lockDays} days: not by ransomware with these keys, not by the storage account owner, not by Fenrir. Old backups go only after their lock ends; maintenance renews the locks of backups still in use.</p>}</>}
          {share && <><h3 style={{ marginTop: 12 }}>Network share sign-in</h3><SigninFields value={signin} onChange={setSignin} /></>}
          {isS3 ? (s3Ok(s3) && <TestConnection agent={agents.find((a) => a.id === creator)} path={location} signin={s3Signin(s3)} s3={s3Settings(s3)} />)
            : <TestConnection agent={agents.find((a) => a.id === creator)} path={path} signin={share ? signin : null} />}
          <p className="small muted">The passphrase is encrypted in this browser for each chosen machine. This server stores only the encrypted copies and can never open the backups.</p>
          <button className="primary" disabled={!ok} onClick={() => setStep(1)}>Next: recovery key</button>
        </>
      )}
      {step === 1 && (
        <>
          <p>If the passphrase is ever lost, this file is the only other way into the repository. It was made in this browser and has not been sent anywhere. Keep it offline, away from the backed-up machines.</p>
          <button onClick={download}>Download recovery key</button>
          <label className="row small" style={{ gap: 6, marginTop: 10 }}><input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} /> I have stored the recovery key safely. Without the passphrase or this key nobody can restore these backups.</label>
          <div className="row" style={{ gap: 8, marginTop: 12 }}>
            <button onClick={() => setStep(0)}>Back</button>
            <button className="primary" disabled={!saved || busy || !!status} onClick={create}>Create repository</button>
          </div>
          {status && <p role="status">{status}</p>}
        </>
      )}
    </Modal>
  );
}

function GatewayDialog({ repo, agents, onClose }: { repo: Repo; agents: BackupAgent[]; onClose: () => void }) {
  const { run, busy } = useAction();
  // The gateway needs its own direct access (it is the one machine that reaches the NAS).
  const pool = agents.filter((a) => repo.agents.some((x) => x.id === a.id && !x.viaGateway) && a.capabilities.includes("gateway"));
  const [id, setId] = useState(repo.gateway?.agentId ?? pool[0]?.id ?? "");
  const [direct, setDirect] = useState(repo.gateway ? repo.gateway.port > 0 : true);
  const [port, setPort] = useState(repo.gateway?.port || 8475);
  const [address, setAddress] = useState(repo.gateway?.address ?? "");
  const save = () => run(() => api(`backup/repositories/${repo.id}/gateway`, { body: { agentId: id, port: direct ? port : 0, address: address.trim() || null } }), "Gateway saved").then((r) => r !== undefined && onClose());
  const stop = () => run(() => api(`backup/repositories/${repo.id}/gateway`, { body: {} }), "Gateway removed").then((r) => r !== undefined && onClose());
  return (
    <Modal wide title={`Serve ${repo.name} through a gateway`} onClose={onClose}
      footer={<>{repo.gateway && <button className="danger" disabled={busy} onClick={stop}>Stop serving</button>}<button className="primary" disabled={busy || !id} onClick={save}>Save</button></>}>
      <p className="small">One machine inside the network (where the NAS is) serves this repository to machines you choose elsewhere:
        laptops at home, a branch office. They connect to it directly when they can reach it (same network, VPN or a forwarded port),
        and through this server otherwise, so no port has to be opened.</p>
      <p className="small muted">Everything is encrypted between the two machines; this server only passes on what it cannot read. Machines
        reaching the repository through the gateway can add backups and restore, but cannot delete them, so ransomware on a laptop
        cannot erase its history. Retention and space reclamation run on the gateway.</p>
      {pool.length === 0 ? <p className="small">No machine with direct access to {repo.path} can be a gateway yet. Give the machine next to the NAS access first (and let its backup agent update).</p> : (
        <div className="form-grid">
          <label className="field">Gateway machine<select value={id} onChange={(e) => setId(e.target.value)}>{pool.map((a) => <option key={a.id} value={a.id}>{a.name}{a.online ? "" : " (offline)"}</option>)}</select></label>
          <label className="field">Direct connections
            <span className="row small" style={{ gap: 6, fontWeight: 400 }}><input type="checkbox" checked={direct} onChange={(e) => setDirect(e.target.checked)} /> Listen on port
              <input type="number" min={1024} max={65535} value={port} disabled={!direct} onChange={(e) => setPort(Number(e.target.value))} style={{ width: 90 }} /></span>
          </label>
          <label className="field">Address from outside (optional)<input value={address} placeholder="backup.example.com:8475" onChange={(e) => setAddress(e.target.value)} /></label>
        </div>
      )}
      {direct && <p className="small muted">Allow inbound TCP {port} on the gateway machine's firewall for the networks that should connect directly. Without it, or from anywhere else, machines use the relay.</p>}
      <p className="small muted">Then give each remote machine access with "Through the gateway" ticked.</p>
    </Modal>
  );
}

function GrantAccess({ repo, agents, onClose }: { repo: Repo; agents: BackupAgent[]; onClose: () => void }) {
  const { run, busy } = useAction();
  const pool = agents.filter((a) => a.tenantId === repo.tenantId && !repo.agents.some((x) => x.id === a.id));
  const [id, setId] = useState(pool[0]?.id ?? "");
  const [pass, setPass] = useState("");
  const [signin, setSignin] = useState<Signin>({ ...noSignin(), username: repo.shareUser ?? "" });
  const [via, setVia] = useState(!!repo.gateway);
  const needsShare = repo.shareAuth === "password" && !via;
  const go = () => run(async () => {
    const a = agents.find((x) => x.id === id)!;
    const sealed: Sealed = await seal(a.publicKey, JSON.stringify({ passphrase: pass, recovery_key: null }));
    await api(`backup/repositories/${repo.id}/access`, { body: { agentId: id, sealed, viaGateway: via, sealedShare: needsShare ? await sealSignin(a, signin) : null } });
  }, "Access given").then(onClose);
  return (
    <Modal title={`Give a machine access to ${repo.name}`} onClose={onClose}
      footer={<button className="primary" disabled={busy || !id || pass.length < 1 || (needsShare && !signinOk(signin))} onClick={go}>Give access</button>}>
      <div className="form-grid">
        <label className="field">Machine<select value={id} onChange={(e) => setId(e.target.value)}>{pool.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}</select></label>
        <label className="field">Repository passphrase<input type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="off" /></label>
      </div>
      {repo.gateway && (
        <label className="row small" style={{ gap: 6, marginTop: 8 }}>
          <input type="checkbox" checked={via} onChange={(e) => setVia(e.target.checked)} />
          Through the gateway ({repo.gateway.name}): for machines outside the network that cannot reach {repo.path} themselves
        </label>
      )}
      {needsShare && <><h3>Share password</h3><SigninFields value={signin} onChange={(s) => setSignin({ ...s, mode: "password" })} /></>}
      <p className="small muted">Encrypted here for that machine only. If the passphrase is wrong, its first backup reports it.
        {via && " Through the gateway the machine can add backups and restore, but never delete: old backups are removed only by the gateway's retention."}</p>
    </Modal>
  );
}

function ShareSignin({ repo, agents, onClose }: { repo: Repo; agents: BackupAgent[]; onClose: () => void }) {
  const { run, busy } = useAction();
  const machines = agents.filter((a) => repo.agents.some((x) => x.id === a.id));
  const [s, setS] = useState<Signin>({ ...noSignin(), mode: repo.shareAuth as Signin["mode"], username: repo.shareUser ?? "" });
  const save = () => run(async () => {
    const access = s.mode === "password" ? await Promise.all(machines.map(async (m) => ({ agentId: m.id, sealedShare: await sealSignin(m, s) }))) : [];
    await api(`backup/repositories/${repo.id}/share`, { body: { share_auth: s.mode, share_user: s.mode === "password" ? signinUser(s) : null, access } });
  }, "Share sign-in updated").then(onClose);
  return (
    <Modal wide title={repo.s3 ? `Access keys for ${repo.name}` : `Network sign-in for ${repo.name}`} onClose={onClose}
      footer={<button className="primary" disabled={busy || !signinOk(s)} onClick={save}>Save for {machines.length} machine{machines.length === 1 ? "" : "s"}</button>}>
      <div className="mono small" style={{ marginBottom: 8 }}>{repo.path}</div>
      {repo.s3 ? (
        <div className="form-grid">
          <label className="field">Access key ID<input value={s.username} onChange={(e) => setS({ ...s, mode: "password", domain: "", username: e.target.value })} autoComplete="off" /></label>
          <label className="field">Secret access key<input type="password" value={s.password} onChange={(e) => setS({ ...s, mode: "password", password: e.target.value })} autoComplete="new-password" /></label>
        </div>
      ) : <SigninFields value={s} onChange={setS} />}
      <TestConnection agent={machines.find((m) => m.online) ?? machines[0]} path={repo.path} signin={s} s3={repo.s3} />
      <p className="small muted">{repo.s3 ? "Create the new keys at the storage provider first, then enter them here; remove the old ones afterwards." : "Changing the password here does not change it on the NAS or server; change it there first, then here."}</p>
    </Modal>
  );
}

// ---------------------------------------------------------------- plans

function describeSchedule(s: any): string {
  if (s.type === "interval") return `every ${s.hours} h`;
  if (s.type === "daily") return `${s.days?.length ? s.days.map((d: number) => DAYS[d]).join(", ") : "daily"} at ${s.time}`;
  return "manual";
}

function Plans({ agents, repos }: { agents: BackupAgent[]; repos: Repo[] }) {
  const { tenantId, can } = useApp();
  const plans = useListData<Plan>("backup/plans", { tenantId: tenantId || undefined }, [tenantId]);
  const { run, busy } = useAction();
  const [edit, setEdit] = useState<Plan | "new" | null>(null);
  const repoName = (id: string) => repos.find((r) => r.id === id)?.name ?? "—";
  return (
    <div className="card">
      {can("configure") && <button className="primary" style={{ marginBottom: 10 }} onClick={() => setEdit("new")}>New plan</button>}
      <Table rows={plans.data} onRow={can("configure") ? setEdit : undefined} empty="No plans. A plan backs up one machine into one repository on a schedule."
        columns={[
          { key: "name", label: "Plan", render: (p) => <><b>{p.name}</b><div className="small muted">{p.label} of {p.agentName}</div></> },
          { key: "repo", label: "Repository", render: (p) => repoName(p.repositoryId) },
          { key: "schedule", label: "When", render: (p) => <>{describeSchedule(p.schedule)}{!p.enabled && <> <Pill value="paused" tone="muted" /></>}</> },
          { key: "next", label: "Next run", render: (p) => (p.enabled ? fmtTime(p.nextRunAt) : "—") },
          { key: "ret", label: "Keeps", render: (p) => p.retention ? Object.entries(p.retention).filter(([, v]) => v).map(([k, v]) => `${v} ${k.replace("keep_", "")}`).join(", ") : "everything" },
          { key: "run", label: "", render: (p) => can("respond") && <button className="small" disabled={busy} onClick={(e) => { e.stopPropagation(); run(() => api(`backup/plans/${p.id}/run`, { body: {} }), "Started"); }}>Run now</button> },
        ]} />
      {edit && <PlanEditor plan={edit === "new" ? null : edit} agents={agents} repos={repos} onClose={() => { setEdit(null); plans.reload(); }} />}
    </div>
  );
}

function PlanEditor({ plan, agents, repos, onClose }: { plan: Plan | null; agents: BackupAgent[]; repos: Repo[]; onClose: () => void }) {
  const { run, busy } = useAction();
  const [name, setName] = useState(plan?.name ?? "Nightly backup");
  const [agentId, setAgentId] = useState(plan?.agentId ?? agents[0]?.id ?? "");
  const agent = agents.find((a) => a.id === agentId);
  const usable = repos.filter((r) => r.status === "ready" && r.agents.some((a) => a.id === agentId));
  const [repoId, setRepoId] = useState(plan?.repositoryId ?? "");
  const [job, setJob] = useState<any>(plan?.job ?? null);
  const [schedule, setSchedule] = useState<any>(plan?.schedule ?? { type: "daily", time: "01:00", days: [], utc_offset_minutes: -new Date().getTimezoneOffset() });
  const [retention, setRetention] = useState<any>(plan?.retention ?? { keep_last: 7, keep_daily: 14, keep_weekly: 8, keep_monthly: 12, keep_yearly: 0 });
  const [enabled, setEnabled] = useState(plan?.enabled ?? true);
  const caps = agent?.capabilities ?? [];
  const jobKind = job ?? (caps.includes("backup_hyperv") ? { type: "backup_hyperv", vm_ids: [] } : caps.includes("backup_system") ? { type: "backup_system" } : { type: "backup_disks", paths: [] });
  const repo = repoId || usable[0]?.id || "";
  const save = () => run(() => plan
    ? api(`backup/plans/${plan.id}`, { method: "PATCH", body: { name, job: jobKind, schedule, retention, enabled } })
    : api("backup/plans", { body: { name, agentId, repositoryId: repo, job: jobKind, schedule, retention, enabled } }), "Plan saved").then((r) => r !== undefined && onClose());
  const remove = async () => { if (plan && await confirmDialog(`Delete the plan ${plan.name}? Its backups are kept.`)) run(() => api(`backup/plans/${plan.id}`, { method: "DELETE" }), "Plan deleted").then(onClose); };
  return (
    <Modal wide title={plan ? `Edit ${plan.name}` : "New backup plan"} onClose={onClose}
      footer={<>{plan && <button className="danger" onClick={remove}>Delete</button>}<button className="primary" disabled={busy || !agentId || !repo} onClick={save}>Save</button></>}>
      <div className="form-grid">
        <label className="field">Name<input value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label className="field">Machine<select value={agentId} disabled={!!plan} onChange={(e) => { setAgentId(e.target.value); setJob(null); setRepoId(""); }}>{agents.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}</select></label>
        <label className="field">Repository<select value={repo} disabled={!!plan} onChange={(e) => setRepoId(e.target.value)}>{usable.length === 0 && <option value="">No ready repository this machine can use</option>}{usable.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select></label>
        <label className="field">What
          <select value={jobKind.type} onChange={(e) => setJob(e.target.value === "backup_disks" ? { type: "backup_disks", paths: [] } : e.target.value === "backup_hyperv" ? { type: "backup_hyperv", vm_ids: [] } : { type: e.target.value })}>
            {caps.includes("backup_system") && <option value="backup_system">Whole system (live, consistent)</option>}
            {caps.includes("backup_disks") && <option value="backup_disks">Chosen disks</option>}
            {caps.includes("backup_hyperv") && <option value="backup_hyperv">Hyper-V VMs</option>}
          </select>
        </label>
      </div>
      {jobKind.type === "backup_disks" && <div className="small" style={{ marginTop: 8 }}>{(agentInventoryDisks(agent)).map((d) => (
        <label key={d} className="row" style={{ gap: 6 }}><input type="checkbox" checked={jobKind.paths.includes(d)} onChange={(e) => setJob({ ...jobKind, paths: e.target.checked ? [...jobKind.paths, d] : jobKind.paths.filter((x: string) => x !== d) })} />{d}</label>
      ))}<input placeholder="or type a device path and press Enter" onKeyDown={(e) => { const v = (e.target as HTMLInputElement).value.trim(); if (e.key === "Enter" && v) setJob({ ...jobKind, paths: [...jobKind.paths, v] }); }} /></div>}
      {jobKind.type === "backup_hyperv" && <p className="small muted">All VMs on the host, including ones added later. Running VMs are captured with production checkpoints.</p>}
      <h3 style={{ marginTop: 12 }}>When</h3>
      <div className="form-grid">
        <label className="field">Schedule<select value={schedule.type} onChange={(e) => setSchedule(e.target.value === "interval" ? { type: "interval", hours: 4 } : e.target.value === "daily" ? { type: "daily", time: "01:00", days: [], utc_offset_minutes: -new Date().getTimezoneOffset() } : { type: "manual" })}>
          <option value="daily">At a time of day</option><option value="interval">Every few hours</option><option value="manual">Only when started</option></select></label>
        {schedule.type === "interval" && <label className="field">Every (hours)<input type="number" min={1} max={744} value={schedule.hours} onChange={(e) => setSchedule({ ...schedule, hours: Number(e.target.value) })} /></label>}
        {schedule.type === "daily" && <label className="field">Time (this browser's time zone)<input type="time" value={schedule.time} onChange={(e) => setSchedule({ ...schedule, time: e.target.value })} /></label>}
      </div>
      {schedule.type === "daily" && <div className="row small" style={{ gap: 8, marginTop: 6 }}>{DAYS.map((d, i) => (
        <label key={d} className="row" style={{ gap: 3 }}><input type="checkbox" checked={schedule.days.includes(i)} onChange={(e) => setSchedule({ ...schedule, days: e.target.checked ? [...schedule.days, i].sort() : schedule.days.filter((x: number) => x !== i) })} />{d}</label>
      ))}<span className="muted">(none ticked = every day)</span></div>}
      <h3 style={{ marginTop: 12 }}>Keep</h3>
      <div className="form-grid">
        {["keep_last", "keep_daily", "keep_weekly", "keep_monthly", "keep_yearly"].map((k) => (
          <label key={k} className="field">{k.replace("keep_", "").replace(/^./, (c) => c.toUpperCase())}<input type="number" min={0} value={retention?.[k] ?? 0} onChange={(e) => setRetention({ ...(retention ?? {}), [k]: Number(e.target.value) })} /></label>
        ))}
      </div>
      <p className="small muted">All zero keeps everything. Old images are only deleted after a successful backup, and never while the repository is on hold.</p>
      <label className="row small" style={{ gap: 6 }}><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled</label>
    </Modal>
  );
}

function agentInventoryDisks(agent?: BackupAgent): string[] {
  return agent?.disks ?? [];
}

// ---------------------------------------------------------------- images, restore, boot checks

function Images({ agents, repos }: { agents: BackupAgent[]; repos: Repo[] }) {
  const { tenantId } = useApp();
  const [repo, setRepo] = useState("");
  const images = useListData<Image>("backup/images", { tenantId: tenantId || undefined, repositoryId: repo || undefined }, [tenantId, repo]);
  const [restore, setRestore] = useState<Image | null>(null);
  const [boot, setBoot] = useState<Image | null>(null);
  const [files, setFiles] = useState<Image | null>(null);
  const { can } = useApp();
  return (
    <div className="card">
      <div className="row" style={{ marginBottom: 10 }}>
        <select value={repo} onChange={(e) => setRepo(e.target.value)}><option value="">All repositories</option>{repos.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select>
      </div>
      <Table rows={images.data} empty="No images yet."
        columns={[
          { key: "what", label: "Image", render: (i) => <><b>{i.vmName ?? i.hostname}</b> <span className="small muted">{i.kind}{i.label ? ` · ${i.label}` : ""}</span>{i.anomaly && <div className="small" style={{ color: "#fca5a5" }}>⚠ {i.anomaly}</div>}</> },
          { key: "created", label: "Taken", render: (i) => unixTime(i.created) },
          { key: "size", label: "Size", render: (i) => <span className="small">{bytes(i.capturedBytes)} · {bytes(i.storedNewBytes)} new</span> },
          { key: "consistency", label: "Consistency" },
          { key: "boot", label: "Boots?", render: (i) => i.lastBootCheck ? <Pill value={i.lastBootCheck.outcome} tone={i.lastBootCheck.outcome === "failed" ? "bad" : "good"} /> : <span className="small muted">not tested</span> },
          { key: "act", label: "", render: (i) => <div className="row" style={{ gap: 4 }}>
            {can("scripts") && <button className="small primary" onClick={() => setFiles(i)}>Browse files</button>}
            {can("scripts") && <button className="small" onClick={() => setRestore(i)}>Restore</button>}
            {can("scripts") && <button className="small" onClick={() => setBoot(i)}>Boot test</button>}
          </div> },
        ]} />
      {restore && <RestoreDialog image={restore} agents={agents} repos={repos} onClose={() => setRestore(null)} />}
      {boot && <BootDialog image={boot} agents={agents} repos={repos} onClose={() => setBoot(null)} />}
      {files && <FileBrowser image={files} onClose={() => setFiles(null)} />}
    </div>
  );
}

function RestoreDialog({ image, agents, repos, onClose }: { image: Image; agents: BackupAgent[]; repos: Repo[]; onClose: () => void }) {
  const { run, busy } = useAction();
  const { can } = useApp();
  // Any of the customer's machines can restore; one without access to the repository is given it here.
  const repo = repos.find((r) => r.id === image.repositoryId);
  const owner = agents.find((a) => a.id === image.agentId);
  const hasAccess = (id: string) => !!repo?.agents.some((x) => x.id === id);
  const pool = agents.filter((a) => !owner || a.tenantId === owner.tenantId)
    .sort((a, b) => Number(hasAccess(b.id)) - Number(hasAccess(a.id)));
  const [agentId, setAgentId] = useState(pool[0]?.id ?? "");
  const agent = pool.find((a) => a.id === agentId);
  const caps = agent?.capabilities ?? [];
  const needsAccess = !!agent && !hasAccess(agent.id);
  const [pass, setPass] = useState("");
  const [via, setVia] = useState(false);
  const [type, setType] = useState("vhdx");
  const [directory, setDirectory] = useState("");
  const [vmName, setVmName] = useState(`${image.vmName ?? image.hostname}-restored`);
  const [device, setDevice] = useState("");
  const [confirm, setConfirm] = useState("");
  const [disk, setDisk] = useState(0);
  const target = type === "vhdx" ? { type, directory } : type === "hyperv_vm" ? { type, name: vmName, directory, start: false } : { type, device, disk, confirm };
  const ok = type === "disk" ? device && confirm === device : directory.trim() && (type !== "hyperv_vm" || vmName.trim());
  const go = () => run(async () => {
    if (needsAccess && agent) {
      const sealed: Sealed = await seal(agent.publicKey, JSON.stringify({ passphrase: pass, recovery_key: null }));
      await api(`backup/repositories/${image.repositoryId}/access`, { body: { agentId: agent.id, sealed, viaGateway: via } });
    }
    return api("backup/restores", { body: { imageId: image.imageId, agentId, target } });
  }, "Restore queued: follow it in Activity").then((r) => r !== undefined && onClose());
  return (
    <Modal wide title={`Restore ${image.vmName ?? image.hostname} from ${unixTime(image.created)}`} onClose={onClose}
      footer={<button className={type === "disk" ? "danger" : "primary"} disabled={busy || !ok || !agentId || (needsAccess && !pass)} onClick={go}>{type === "disk" ? "Overwrite the disk" : needsAccess ? "Give access and restore" : "Restore"}</button>}>
      <div className="form-grid">
        <label className="field">Machine that restores<select value={agentId} onChange={(e) => setAgentId(e.target.value)}>{pool.map((a) => <option key={a.id} value={a.id}>{a.name}{a.capabilities.includes("restore_hyperv") ? " · Hyper-V" : ""}{a.role === "recovery" ? " · recovery session" : ""}{hasAccess(a.id) ? "" : " · no access yet"}</option>)}</select></label>
        <label className="field">Restore to<select value={type} onChange={(e) => setType(e.target.value)}>
          {caps.includes("restore_vhdx") && <option value="vhdx">Virtual disk files (VHDX)</option>}
          {caps.includes("restore_hyperv") && <option value="hyperv_vm">A new Hyper-V VM</option>}
          {caps.includes("restore_disk") && can("destructive") && <option value="disk">A physical disk (overwrites it)</option>}
        </select></label>
        {type !== "disk" && <label className="field">Folder on that machine<input value={directory} onChange={(e) => setDirectory(e.target.value)} placeholder="D:\\Restores" /></label>}
        {type === "hyperv_vm" && <label className="field">VM name<input value={vmName} onChange={(e) => setVmName(e.target.value)} /></label>}
        {type === "disk" && <>
          <label className="field">Image disk<select value={disk} onChange={(e) => setDisk(Number(e.target.value))}>{(image.disks.length ? image.disks : [{}]).map((d: any, i: number) => <option key={i} value={i}>Disk {i}{d.size ? ` (${bytes(d.size)})` : ""}</option>)}</select></label>
          {(agent?.diskInfo ?? []).some((d) => !d.system && !d.inUse) && <label className="field">Disk on {agent?.name}<select value={device} onChange={(e) => { setDevice(e.target.value); setConfirm(""); }}>
            <option value="">Choose…</option>
            {(agent?.diskInfo ?? []).filter((d) => !d.system && !d.inUse).map((d) => <option key={d.path} value={d.path}>{d.path} · {bytes(d.size)}{d.model ? ` · ${d.model}` : ""}{d.serial ? ` · ${d.serial}` : ""}</option>)}
          </select></label>}
          <label className="field">Target device<input value={device} onChange={(e) => { setDevice(e.target.value); setConfirm(""); }} placeholder="\\.\PhysicalDrive1 or /dev/sdb" /></label>
        </>}
      </div>
      {needsAccess && (
        <div className="card" style={{ marginTop: 10 }}>
          <b>{agent?.name} has no access to {repo?.name ?? "this repository"} yet.</b>
          <div className="form-grid" style={{ marginTop: 6 }}>
            <label className="field">Repository passphrase<input type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="off" /></label>
          </div>
          {repo?.gateway && <label className="row small" style={{ gap: 6 }}><input type="checkbox" checked={via} onChange={(e) => setVia(e.target.checked)} /> Through the gateway ({repo.gateway.name})</label>}
          <p className="small muted">Encrypted in this browser for {agent?.name} only.</p>
        </div>
      )}
      {type === "disk" && agent?.role === "recovery" && agent.firmware && <p className="small muted" style={{ marginTop: 8 }}>
        {agent.name} started in {agent.firmware === "uefi" ? `UEFI mode${agent.secureBoot ? " with Secure Boot" : ""}` : "legacy BIOS mode"}. The disk may be larger, or smaller if the backed-up partitions fit; a UEFI system gets the fallback boot loader and a firmware boot entry, and the job says if the firmware mode must be changed.
      </p>}
      {type === "disk" && <div className="card warn-card" style={{ marginTop: 10 }}>
        Everything on <b className="mono">{device || "the target device"}</b> is replaced. Type the device again to confirm. You will also be asked for your password.
        <input style={{ marginTop: 6, width: "100%" }} value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder={device} />
      </div>}
    </Modal>
  );
}

function BootDialog({ image, agents, repos, onClose }: { image: Image; agents: BackupAgent[]; repos: Repo[]; onClose: () => void }) {
  const { run, busy } = useAction();
  const repo = repos.find((r) => r.id === image.repositoryId);
  // Every Hyper-V or QEMU host of the customer; one without access to the repository can be given it here.
  const owner = agents.find((a) => a.id === image.agentId);
  const hosts = agents.filter((a) => a.capabilities.some((c) => c === "boot_kvm" || c === "boot_hyperv") && (!owner || a.tenantId === owner.tenantId));
  const hasAccess = (id: string) => !!repo?.agents.some((x) => x.id === id);
  const [agentId, setAgentId] = useState((hosts.find((h) => hasAccess(h.id)) ?? hosts[0])?.id ?? "");
  const host = hosts.find((a) => a.id === agentId);
  const hyperv = !!host?.capabilities.includes("boot_hyperv") && !host?.capabilities.includes("boot_kvm");
  const [keep, setKeep] = useState(false);
  const [folder, setFolder] = useState("");
  const [pass, setPass] = useState("");
  const [via, setVia] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const needsAccess = !!host && !hasAccess(host.id);
  const checks = useListData<any>(`backup/images/${image.imageId}/boot-checks`);
  const [shot, setShot] = useState<string | null>(null);
  const showShot = async (id: number) => {
    const r = await fetch(`/api/console/backup/boot-checks/${id}/screenshot.png`, { headers: { Authorization: `Bearer ${getToken()}` } });
    if (r.ok) setShot(URL.createObjectURL(await r.blob()));
  };
  const start = () => run(async () => {
    if (!host) return;
    if (needsAccess) {
      const sealed: Sealed = await seal(host.publicKey, JSON.stringify({ passphrase: pass, recovery_key: null }));
      await api(`backup/repositories/${image.repositoryId}/access`, { body: { agentId: host.id, sealed, viaGateway: via } });
    }
    await api(`backup/images/${image.imageId}/boot-check`, { body: { agentId: host.id, keepRunning: keep, directory: hyperv && folder.trim() ? folder.trim() : null } });
    setMsg(keep
      ? (hyperv ? `Queued. When it has booted, the VM stays in Hyper-V Manager on ${host.name} as "Fenrir check ${image.hostname} …", network disconnected. Stop it from Machines › ${host.name} when you are done.`
                : `Queued. The VM stays running on ${host.name} (isolated) for up to 8 hours; stop it from Machines › ${host.name}.`)
      : "Queued. The result appears below in a few minutes.");
  }).then(() => checks.reload());
  const kept = host?.runningVms ?? [];
  return (
    <Modal wide title={`Boot test of ${image.vmName ?? image.hostname}`} onClose={onClose}
      footer={<button className="primary" disabled={busy || !host || (needsAccess && !pass)} onClick={start}>{needsAccess ? "Give access and start" : "Start boot test"}</button>}>
      {hosts.length === 0 ? (
        <p>No machine of this customer can boot VMs yet. A Windows machine with Hyper-V, or a Linux machine with QEMU, can: install the backup agent on it (it detects Hyper-V by itself).</p>
      ) : (
        <>
          <div className="form-grid">
            <label className="field">Boot on
              <select value={agentId} onChange={(e) => { setAgentId(e.target.value); setMsg(null); }}>
                {hosts.map((a) => <option key={a.id} value={a.id}>{a.name} · {a.capabilities.includes("boot_hyperv") ? "Hyper-V" : "QEMU/KVM"}{hasAccess(a.id) ? "" : " · no access yet"}{a.online ? "" : " (offline)"}</option>)}
              </select>
            </label>
            {hyperv && <label className="field">Folder on {host?.name} for the VM's disks<input value={folder} onChange={(e) => setFolder(e.target.value)} placeholder="default: the agent's folder on C:" /></label>}
          </div>
          {needsAccess && (
            <div className="card" style={{ marginTop: 10 }}>
              <b>{host?.name} has no access to {repo?.name ?? "this repository"} yet.</b>
              <div className="form-grid" style={{ marginTop: 6 }}>
                <label className="field">Repository passphrase<input type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="off" /></label>
              </div>
              {repo?.gateway && <label className="row small" style={{ gap: 6 }}><input type="checkbox" checked={via} onChange={(e) => setVia(e.target.checked)} /> Through the gateway ({repo.gateway.name})</label>}
              <p className="small muted">Encrypted in this browser for {host?.name} only.{repo?.isShare && repo.shareAuth === "password" && !via ? " The repository is on a network share that needs a password: give access on the Repositories tab instead." : ""}</p>
            </div>
          )}
          <label className="row small" style={{ gap: 6, marginTop: 8 }}>
            <input type="checkbox" checked={keep} onChange={(e) => setKeep(e.target.checked)} />
            {hyperv ? "Keep the VM afterwards so I can log in and check it (it stays in Hyper-V Manager until I stop it)" : "Keep it running afterwards (up to 8 hours)"}
          </label>
        </>
      )}
      {msg && <p role="status" className="small">{msg}</p>}
      <p className="small muted">The backup is restored as a VM with its network disconnected; nothing is written to the backup or the original machine. A pass means Windows (or Linux) started and answered; a kept VM lets you log in and check applications and data yourself.{hyperv && " The VM's disks need about as much free space on the host as the data in the backup."}</p>
      {kept.length > 0 && (
        <div className="card" style={{ marginBottom: 10 }}>
          <b>Test VMs kept on {host?.name}</b>
          {kept.map((v) => (
            <div key={v.sessionId} className="row small" style={{ gap: 8 }}>
              Image {String(v.imageId).slice(0, 8)} since {unixTime(v.startedUnix)}{v.vncPort ? ` · console on the host at 127.0.0.1:${v.vncPort}` : ""}
              <button className="small" disabled={busy} onClick={() => run(() => api(`backup/agents/${host!.id}/vms/${v.sessionId}/stop`, { body: {} }), "Stopping and removing the VM")}>Stop and remove</button>
            </div>
          ))}
        </div>
      )}
      <Table rows={checks.data} empty="Not tested yet." columns={[
        { key: "at", label: "When", render: (b) => fmtTime(b.at) },
        { key: "agentName", label: "Host", render: (b) => <span className="small">{b.agentName}</span> },
        { key: "outcome", label: "Result", render: (b) => <Pill value={b.outcome} tone={b.outcome === "failed" ? "bad" : "good"} /> },
        { key: "message", label: "Detail", render: (b) => <span className="small">{b.message} ({b.seconds}s, {b.accel})</span> },
        { key: "shot", label: "", render: (b) => b.hasScreenshot && <button className="small" onClick={() => showShot(b.id)}>Screen</button> },
      ]} />
      {shot && <img src={shot} alt="VM screen at the end of the boot test" style={{ maxWidth: "100%", marginTop: 10, border: "1px solid var(--line)" }} />}
    </Modal>
  );
}

// ---------------------------------------------------------------- activity

function JobsTable({ rows }: { rows: Job[] | null }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  return (
    <Table rows={rows} empty="No jobs yet." columns={[
      { key: "label", label: "Job", render: (j) => <><b>{j.label}</b> <span className="small muted">{j.agentName}</span></> },
      { key: "state", label: "State", render: (j) => <><StatePill state={j.state} /> <span className="small muted">{progressText(j.progress)}</span></> },
      { key: "createdAt", label: "Requested", render: (j) => <span className="small">{ago(j.createdAt)} by {j.requestedBy}</span> },
      { key: "detail", label: "Detail", render: (j) => <span className="small">{j.error ?? j.warnings.join(" ")}</span> },
      { key: "cancel", label: "", render: (j) => !FINAL.includes(j.state) && can("respond") && <button className="small" disabled={busy} onClick={() => run(() => api(`backup/jobs/${j.id}/cancel`, { body: {} }), "Cancelling")}>Cancel</button> },
    ]} />
  );
}

function Activity() {
  const { tenantId } = useApp();
  const jobs = useListData<Job>("backup/jobs", { tenantId: tenantId || undefined, limit: 200 }, [tenantId]);
  useAutoRefresh(jobs.reload, 10000);
  return <div className="card"><JobsTable rows={jobs.data} /></div>;
}

// ---------------------------------------------------------------- device page

/** The Backup section of a device: its backup agent (if installed), images and recent jobs, or an install button. */
export function DeviceBackup({ device }: { device: { id: string; hostname: string; platform: string; osVersion?: string } }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const agents = useListData<BackupAgent>("backup/agents", { deviceId: device.id }, [device.id]);
  const agent = agents.data?.[0];
  const detail = useData<any>(agent ? `backup/agents/${agent.id}` : null, {}, [agent?.id]);
  const [role, setRole] = useState(/server/i.test(device.osVersion ?? "") || device.platform === "linux" ? "server" : "workstation");
  const [sent, setSent] = useState(false);
  const [files, setFiles] = useState<Image | null>(null);
  useAutoRefresh(agents.reload, 15000);
  if (agents.data == null) return <div className="empty">Loading…</div>;
  if (!agent) return (
    <div className="card">
      <h3>Not backed up</h3>
      <p className="small muted">Install the Fenrir backup agent to take image backups of this machine into a repository you own (a NAS, file server or disk). It runs as its own protected service, separate from the security agent.</p>
      {!["windows", "linux", "macos"].includes(device.platform) ? <p className="small">Not available for this platform.</p> : can("configure") && can("scripts") ? (
        <div className="row" style={{ gap: 8 }}>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="workstation">Desktop or laptop</option><option value="server">Server</option>
            {device.platform === "windows" && <option value="hyperv">Hyper-V host (back up its VMs)</option>}
          </select>
          <button className="primary" disabled={busy || sent} onClick={() => run(() => api(`backup/devices/${device.id}/install`, { body: { role } }), "Install sent: the machine appears here within a few minutes").then((r) => r && setSent(true))}>Enable backup</button>
        </div>
      ) : <p className="small">Ask an administrator to enable backup.</p>}
      {sent && <p className="small muted">Sent to the Fenrir agent. Follow it under Activity › Scripts & jobs.</p>}
    </div>
  );
  return (
    <>
      <div className="grid k4" style={{ marginBottom: 14 }}>
        <Stat label="Backup agent" value={agent.online ? "Online" : "Offline"} hint={`version ${agent.agentVersion}`} />
        <Stat label="Last backup" value={agent.lastBackup ? agent.lastBackup.state : "never"} hint={agent.lastBackup ? ago(agent.lastBackup.at) : undefined} accent={agent.lastBackup?.state === "failed" ? "bad" : undefined} />
        <Stat label="Images" value={detail.data?.images?.length ?? "—"} />
        <Stat label="Plans" value={detail.data?.plans?.length ?? "—"} hint={detail.data?.plans?.map((p: Plan) => describeSchedule(p.schedule)).join(", ")} to="/backups" />
      </div>
      <div className="card">
        <h3>Images</h3>
        <Table rows={detail.data?.images ?? null} empty="No images yet. Create a plan on the Backups page." columns={[
          { key: "created", label: "Taken", render: (i: Image) => unixTime(i.created) },
          { key: "kind", label: "Type", render: (i: Image) => `${i.kind}${i.vmName ? ` · ${i.vmName}` : ""}` },
          { key: "size", label: "Size", render: (i: Image) => bytes(i.capturedBytes) },
          { key: "boot", label: "Boots?", render: (i: Image) => i.lastBootCheck ? <Pill value={i.lastBootCheck.outcome} tone={i.lastBootCheck.outcome === "failed" ? "bad" : "good"} /> : "—" },
          { key: "files", label: "", render: (i: Image) => can("scripts") && <button className="small" onClick={() => setFiles(i)}>Browse files</button> },
        ]} />
        {files && <FileBrowser image={files} onClose={() => setFiles(null)} />}
      </div>
      <div className="card"><h3>Recent backup jobs</h3><JobsTable rows={detail.data?.jobs ?? null} /></div>
    </>
  );
}
