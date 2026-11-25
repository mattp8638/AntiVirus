// Apps & clusters: Microsoft 365, Google Workspace, Salesforce and Kubernetes backed up by one of the tenant's backup
// agents (backup/docs/design/saas.md, kubernetes.md). The customer's own app secret or cluster token is sealed in this
// browser to the machine that runs the backups; the server stores and forwards only the sealed form.
import { useMemo, useState } from "react";
import { api, fmtTime, unlockedUntil } from "../api";
import { useApp } from "../app-context";
import { seal, sealSupported } from "../backup-seal";
import { confirmDialog } from "../components/dialogs";
import { ErrorNote, Modal, Pill, Table, useAction, useListData } from "../components/ui";
import type { BackupAgent } from "./Backups";

type Kind = "m365" | "google" | "salesforce" | "quickbooks" | "kubernetes";
const KINDS: { id: Kind; label: string; secret: string; help: string }[] = [
  { id: "m365", label: "Microsoft 365", secret: "Client secret", help: "An app registration in the customer's Entra ID with application permissions User.Read.All, Mail.ReadWrite and Files.ReadWrite.All (admin consent)." },
  { id: "google", label: "Google Workspace", secret: "Service account key (JSON)", help: "A service account with domain-wide delegation for gmail.readonly, drive.readonly and admin.directory.user.readonly (and gmail.insert, gmail.labels, gmail.modify, drive to restore)." },
  { id: "salesforce", label: "Salesforce", secret: "Consumer secret", help: "A connected app with the client credentials flow and a run-as user that can view all data." },
  { id: "quickbooks", label: "QuickBooks Online", secret: "Client secret", help: "The customer's Intuit app (Accounting scope), connected to the company once: its client ID, client secret and refresh token. Intuit replaces the refresh token as it is used; the machine keeps the newest itself." },
  { id: "kubernetes", label: "Kubernetes", secret: "Service account token", help: "A service account that can read (and, to restore, create) the namespaces' objects; with volume data, also create pods, claims and volume snapshots." },
];
const SOURCE_TYPES = ["backup_saas", "backup_kubernetes"];
export const isAppPlan = (p: { job: any }) => SOURCE_TYPES.includes(p.job?.type);

interface Plan { id: string; name: string; agentId: string; agentName: string; repositoryId: string; job: any; schedule: any; enabled: boolean; nextRunAt: string | null; lastRunAt: string | null }
interface Repo { id: string; name: string; status: string; agents: { id: string }[] }
interface Img { imageId: string; repositoryId: string; machineId?: string; created: number; storedNewBytes: number; label: string | null }

const words = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
const service = (k: string) => KINDS.find((x) => x.id === k)?.label ?? k;

function describe(job: any): string {
  if (job.type === "backup_kubernetes") return `Kubernetes ${job.cluster.name}: ${job.cluster.namespaces.join(", ")}`;
  return `${service(job.tenant.service)}: ${job.tenant.tenant}`;
}

function machineOf(job: any): string {
  return job.type === "backup_kubernetes" ? `k8s:${job.cluster.name}` : `saas:${job.tenant.service}:${job.tenant.tenant}`;
}

export function AppsAndClusters({ agents, repos }: { agents: BackupAgent[]; repos: Repo[] }) {
  const { tenantId, can } = useApp();
  const plans = useListData<Plan>("backup/plans", { tenantId: tenantId || undefined }, [tenantId]);
  const { run, busy } = useAction();
  const [adding, setAdding] = useState(false);
  const [restoring, setRestoring] = useState<Plan | null>(null);
  const runners = agents.filter((a) => a.capabilities.includes("saas") || a.capabilities.includes("kubernetes"));
  const mine = (plans.data ?? []).filter(isAppPlan);
  const repoName = (id: string) => repos.find((r) => r.id === id)?.name ?? "—";
  return (
    <div className="card">
      <p className="small muted">Mailboxes, OneDrive and Google Drive files, CRM records and Kubernetes namespaces (with their volumes), backed up by one of this customer's machines into the same encrypted repositories as its images. You connect the customer's own app or service account; its secret is encrypted in this browser for that machine, and this server never sees it.</p>
      {can("configure") && <div className="row" style={{ gap: 8, marginBottom: 10 }}>
        <button className="primary" disabled={runners.length === 0} onClick={() => setAdding(true)}>Connect a service or cluster</button>
        {runners.length === 0 && <span className="small muted">Needs a machine with an up-to-date backup agent.</span>}
      </div>}
      <ErrorNote error={plans.error} />
      <Table rows={plans.data ? mine : null} empty="Nothing connected."
        columns={[
          { key: "name", label: "Source", render: (p) => <><b>{p.name}</b><div className="small muted">{describe(p.job)}</div></> },
          { key: "agent", label: "Runs on", render: (p) => p.agentName },
          { key: "repo", label: "Repository", render: (p) => repoName(p.repositoryId) },
          { key: "last", label: "Last run", render: (p) => <>{fmtTime(p.lastRunAt)}{!p.enabled && <> <Pill value="paused" tone="muted" /></>}</> },
          { key: "next", label: "Next run", render: (p) => (p.enabled ? fmtTime(p.nextRunAt) : "—") },
          { key: "act", label: "", render: (p) => <span className="row" style={{ gap: 6 }}>
            {can("respond") && <button className="small" disabled={busy} onClick={() => run(() => api(`backup/plans/${p.id}/run`, { body: {} }), "Started")}>Back up now</button>}
            {can("respond") && <button className="small" onClick={() => setRestoring(p)}>Restore</button>}
            {can("configure") && <button className="small danger" onClick={async () => { if (await confirmDialog(`Disconnect ${p.name}? Its backups are kept; the sealed secret is deleted.`)) run(() => api(`backup/plans/${p.id}`, { method: "DELETE" }), "Disconnected").then(() => plans.reload()); }}>Disconnect</button>}
          </span> },
        ]} />
      {adding && <Connect agents={runners} repos={repos} onClose={() => { setAdding(false); plans.reload(); }} />}
      {restoring && <Restore plan={restoring} onClose={() => setRestoring(null)} />}
    </div>
  );
}

function Connect({ agents, repos, onClose }: { agents: BackupAgent[]; repos: Repo[]; onClose: () => void }) {
  const { run, busy } = useAction();
  const [kind, setKind] = useState<Kind>("m365");
  const able = agents.filter((a) => a.capabilities.includes(kind === "kubernetes" ? "kubernetes" : "saas"));
  const [agentId, setAgentId] = useState("");
  const agent = able.find((a) => a.id === agentId) ?? able[0];
  const usable = repos.filter((r) => r.status === "ready" && agent && r.agents.some((a) => a.id === agent.id));
  const [repoId, setRepoId] = useState("");
  const repo = usable.find((r) => r.id === repoId)?.id ?? usable[0]?.id ?? "";
  const [f, setF] = useState({ tenant: "", client_id: "", domain_url: "", admin: "", users: "", objects: "", name: "", api_server: "", ca_pem: "", namespaces: "", volume_image: "", time: "01:00" });
  const [mail, setMail] = useState(true);
  const [files, setFiles] = useState(true);
  const [m365, setM365] = useState({ sites: false, teams: false, directory: false });
  const [secret, setSecret] = useState("");
  const [refresh, setRefresh] = useState("");
  const meta = KINDS.find((k) => k.id === kind)!;
  const field = (k: keyof typeof f, label: string, placeholder = "") =>
    <label className="field">{label}<input value={f[k]} placeholder={placeholder} onChange={(e) => setF({ ...f, [k]: e.target.value })} /></label>;
  const save = () => run(async () => {
    if (!agent) throw new Error("choose the machine that runs the backups");
    if (!sealSupported()) throw new Error("This browser cannot encrypt secrets (Web Crypto X25519 is needed).");
    const sealed = await seal(agent.publicKey, kind === "quickbooks" ? JSON.stringify({ client_secret: secret.trim(), refresh_token: refresh.trim() }) : secret.trim());
    const job = kind === "kubernetes"
      ? { type: "backup_kubernetes", sealed_token: sealed, cluster: { name: f.name.trim(), api_server: f.api_server.trim(), ca_pem: f.ca_pem.trim(), namespaces: words(f.namespaces), volume_image: f.volume_image.trim() } }
      : { type: "backup_saas", sealed_secret: sealed, tenant: { service: kind, tenant: f.tenant.trim(), client_id: f.client_id.trim(), domain_url: f.domain_url.trim(), admin: f.admin.trim(), users: words(f.users), objects: words(f.objects), mail, files, ...(kind === "m365" ? m365 : {}) } };
    const name = kind === "kubernetes" ? `Kubernetes ${f.name.trim()}` : `${meta.label} ${f.tenant.trim()}`;
    return api("backup/plans", { body: { name, agentId: agent.id, repositoryId: repo, job, enabled: true,
      schedule: { type: "daily", time: f.time, days: [], utc_offset_minutes: -new Date().getTimezoneOffset() },
      retention: { keep_last: 7, keep_daily: 30, keep_weekly: 12, keep_monthly: 12, keep_yearly: 0 } } });
  }, "Connected").then((r) => r !== undefined && onClose());
  return (
    <Modal wide title="Connect a service or cluster" onClose={onClose}
      footer={<button className="primary" disabled={busy || !agent || !repo || !secret.trim() || (kind === "quickbooks" && !refresh.trim())} onClick={save}>Connect</button>}>
      <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
        {KINDS.map((k) => <button key={k.id} className={kind === k.id ? "primary small" : "small"} onClick={() => { setKind(k.id); setAgentId(""); setRepoId(""); }}>{k.label}</button>)}
      </div>
      <p className="small muted">{meta.help}</p>
      <div className="form-grid">
        <label className="field">Runs on<select value={agent?.id ?? ""} onChange={(e) => { setAgentId(e.target.value); setRepoId(""); }}>
          {able.length === 0 && <option value="">No machine can run this</option>}
          {able.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
        </select></label>
        <label className="field">Repository<select value={repo} onChange={(e) => setRepoId(e.target.value)}>
          {usable.length === 0 && <option value="">No ready repository this machine can use</option>}
          {usable.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
        </select></label>
        {kind === "kubernetes" ? <>
          {field("name", "Cluster name", "prod")}
          {field("api_server", "API server", "https://k8s.example.lan:6443")}
          {field("namespaces", "Namespaces (spaces or commas)", "shop payments")}
          {field("volume_image", "Volume data: fenrir-backup image the cluster can pull (empty: objects only)", "registry.example.lan/fenrir-backup:latest")}
        </> : <>
          {field("tenant", kind === "m365" ? "Tenant (directory ID or domain)" : kind === "google" ? "Domain" : kind === "quickbooks" ? "Company ID (realm ID)" : "Org name", kind === "m365" ? "contoso.onmicrosoft.com" : kind === "google" ? "example.com" : kind === "quickbooks" ? "9130350000000000" : "acme")}
          {kind === "google" ? field("admin", "Administrator to list users as", "admin@example.com") : field("client_id", kind === "m365" ? "Application (client) ID" : kind === "quickbooks" ? "Client ID" : "Consumer key")}
          {kind === "salesforce" && field("domain_url", "My Domain URL", "https://acme.my.salesforce.com")}
          {kind === "quickbooks" && field("domain_url", "API address (empty: QuickBooks Online; sandbox: https://sandbox-quickbooks.api.intuit.com)")}
          {kind === "salesforce" ? field("objects", "Objects (empty: standard and custom)") : kind === "quickbooks" ? field("objects", "Entities (empty: lists and every transaction type)", "Customer Invoice Bill") : field("users", "Users (empty: everyone)")}
        </>}
        <label className="field">Back up every day at<input type="time" value={f.time} onChange={(e) => setF({ ...f, time: e.target.value })} /></label>
      </div>
      {kind === "kubernetes" && <label className="field">CA certificate (PEM)<textarea rows={3} value={f.ca_pem} onChange={(e) => setF({ ...f, ca_pem: e.target.value })} /></label>}
      {(kind === "m365" || kind === "google") && <div className="row small" style={{ gap: 14 }}>
        <label className="row" style={{ gap: 4 }}><input type="checkbox" checked={mail} onChange={(e) => setMail(e.target.checked)} /> Mail</label>
        <label className="row" style={{ gap: 4 }}><input type="checkbox" checked={files} onChange={(e) => setFiles(e.target.checked)} /> {kind === "m365" ? "OneDrive" : "Drive"} files</label>
        {kind === "m365" && <>
          <label className="row" style={{ gap: 4 }} title="Needs Sites.ReadWrite.All"><input type="checkbox" checked={m365.sites} onChange={(e) => setM365({ ...m365, sites: e.target.checked })} /> SharePoint sites</label>
          <label className="row" style={{ gap: 4 }} title="Needs ChannelMessage.Read.All (Microsoft approves this permission per app)"><input type="checkbox" checked={m365.teams} onChange={(e) => setM365({ ...m365, teams: e.target.checked })} /> Teams messages</label>
          <label className="row" style={{ gap: 4 }} title="Needs Directory.Read.All and Policy.Read.All"><input type="checkbox" checked={m365.directory} onChange={(e) => setM365({ ...m365, directory: e.target.checked })} /> Entra ID</label>
        </>}
      </div>}
      <label className="field">{meta.secret} — encrypted in this browser for {agent?.name ?? "the machine"}
        <textarea rows={kind === "google" ? 5 : 2} value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="off" spellCheck={false} />
      </label>
      {kind === "quickbooks" && <label className="field">Refresh token — encrypted like the secret
        <textarea rows={2} value={refresh} onChange={(e) => setRefresh(e.target.value)} autoComplete="off" spellCheck={false} />
      </label>}
    </Modal>
  );
}

function Restore({ plan, onClose }: { plan: Plan; onClose: () => void }) {
  const { run, busy } = useAction();
  const job = plan.job;
  const k8s = job.type === "backup_kubernetes";
  const open = !!unlockedUntil(plan.repositoryId);
  const images = useListData<Img>(open ? "backup/images" : null, { repositoryId: plan.repositoryId }, [plan.repositoryId, open]);
  const list = useMemo(() => (images.data ?? []).filter((i) => i.machineId === machineOf(job)).sort((a, b) => b.created - a.created), [images.data, job]);
  const [image, setImage] = useState("");
  const [f, setF] = useState({ account: "", to_account: "", kind: "", path: "", namespaces: "", rename_to: "", confirm: "" });
  const [overwrite, setOverwrite] = useState(false);
  const imageId = image || list[0]?.imageId || "";
  const owner = k8s ? job.cluster.name : job.tenant.tenant;
  const field = (k: keyof typeof f, label: string, placeholder = "") =>
    <label className="field">{label}<input value={f[k]} placeholder={placeholder} onChange={(e) => setF({ ...f, [k]: e.target.value })} autoComplete="off" /></label>;
  const go = () => run(() => api(`backup/agents/${plan.agentId}/jobs`, { body: {
    repositoryId: plan.repositoryId, confirm: f.confirm,
    kind: k8s
      ? { type: "restore_kubernetes", image_id: imageId, cluster: job.cluster, sealed_token: job.sealed_token, namespaces: words(f.namespaces), rename_to: f.rename_to.trim() || null, replace: overwrite }
      : { type: "restore_saas", image_id: imageId, tenant: job.tenant, sealed_secret: job.sealed_secret, account: f.account.trim(), to_account: f.to_account.trim() || null, kind: f.kind || null, path: f.path.trim() || null, overwrite },
  } }), `Restore started on ${plan.agentName}`).then((r) => r !== undefined && onClose());
  const ready = imageId && (k8s || f.account.trim()) && (!overwrite || f.confirm.trim().toLowerCase() === owner.toLowerCase());
  return (
    <Modal wide title={`Restore ${describe(job)}`} onClose={onClose}
      footer={<button className={overwrite ? "danger" : "primary"} disabled={busy || !ready} onClick={go}>Restore</button>}>
      {!open ? <div className="card warn-card small">Unlock the repository first: open <b>Images &amp; restore</b>, choose {owner} and enter its passphrase.</div> : <>
        <ErrorNote error={images.error} />
        <label className="field">Backup<select value={imageId} onChange={(e) => setImage(e.target.value)}>
          {list.length === 0 && <option value="">No backups yet</option>}
          {list.map((i) => <option key={i.imageId} value={i.imageId}>{new Date(i.created * 1000).toLocaleString()}{i.label ? ` · ${i.label}` : ""}</option>)}
        </select></label>
      </>}
      <div className="form-grid">
        {k8s ? <>
          {field("namespaces", "Namespaces (empty: all in the backup)")}
          {field("rename_to", "Restore under another name (one namespace)", "shop-restored")}
        </> : <>
          {field("account", job.tenant.service === "salesforce" ? "Org" : "Account", job.tenant.service === "salesforce" ? job.tenant.tenant : "ann@example.com")}
          {field("to_account", "Into account (empty: the same)")}
          <label className="field">What<select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
            <option value="">Everything</option><option value="mail">Mail</option><option value="file">Files</option><option value="record">Records</option>
            {job.tenant.service === "m365" && <><option value="site-file">SharePoint files (account: the site's address)</option><option value="directory">Entra ID objects (account: directory:tenant)</option></>}
          </select></label>
          {field("path", "Path starts with (empty: all)")}
        </>}
      </div>
      <p className="small muted">{k8s ? "Objects that exist are left as they are unless replaced; volume data goes into newly created claims." : "Mail and files go into a new “Restored <date>” folder; deleted records are created again."}</p>
      <label className="row small" style={{ gap: 6 }}><input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} /> {k8s ? "Replace objects that exist now" : "Update records that still exist"}</label>
      {overwrite && <label className="field">Type {owner} to confirm (you will be asked for your password)<input value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} autoComplete="off" /></label>}
    </Modal>
  );
}
