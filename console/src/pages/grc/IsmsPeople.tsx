import { useState } from "react";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { Markdown } from "../../components/Markdown";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** People and training (ISO 27001 5.3, 7.2, 7.3): named roles, RACI, competence and acknowledgement campaigns. */

const KIND_LABEL: Record<string, string> = { training: "Training", qualification: "Qualification", experience: "Experience", awareness: "Awareness" };
const STATUS: Record<string, [string, string]> = { current: ["current", "ok"], expiring: ["expiring soon", "warn"], expired: ["expired", "bad"], no_expiry: ["no expiry", "muted"] };
const ROLE_LABEL: Record<string, string> = { tenant_admin: "ISMS administrators", isms_manager: "ISMS managers", control_owner: "Control owners", approver: "Approvers", staff: "Staff", auditor: "Auditors", executive_viewer: "Executives" };
const LETTER_WORD: Record<string, string> = { R: "Responsible", A: "Accountable", C: "Consulted", I: "Informed" };
const ddmmyyyy = (iso?: string | null) => iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)}/${iso.slice(0, 4)}` : "";

function useMembers(tenantId: string) {
  const { data } = useData<any>("isms/members", { tenant_id: tenantId }, [tenantId]);
  return safeArray<any>(data?.members);
}

export function IsmsPeopleTab() {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  const perms = safeArray<string>(me?.permissions);
  const [view, setView] = useState("ack");
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its people and training.</p>;
  if (!perms.includes("documents.acknowledge")) return me ? <p className="muted">You have no ISMS role in this customer.</p> : null;
  const full = perms.includes("controls.view");
  return <div className="card">
    <label className="field" style={{ maxWidth: 280 }}>Show<select value={view} onChange={(e) => setView(e.target.value)}>
      <option value="ack">Acknowledgements</option>{full && <option value="roles">Roles and RACI</option>}<option value="competence">Competence</option></select></label>
    {view === "ack" && <Acknowledgements tenantId={tenantId} />}
    {view === "roles" && full && <RolesAndRaci tenantId={tenantId} />}
    {view === "competence" && <Competence tenantId={tenantId} />}
  </div>;
}

// Roles and RACI ------------------------------------------------------------------------------------------------------

function RolesAndRaci({ tenantId }: { tenantId: string }) {
  const { data, error, reload } = useData<any>("isms/people", { tenant_id: tenantId }, [tenantId]);
  const [editing, setEditing] = useState<any>(null);
  const [activity, setActivity] = useState("");
  const { run, busy } = useAction();
  const manage = !!data?.canManage;
  const roles = safeArray<any>(data?.roles);
  const raci = data?.raci ?? { activities: [], roles: [], cells: [], issues: [] };
  const letter = (aid: string, rid: string) => raci.cells.find((c: any) => c.activityId === aid && c.roleId === rid)?.letter ?? "";
  const setLetter = async (aid: string, rid: string, value: string) => {
    const letters: Record<string, string> = {};
    for (const c of raci.cells.filter((x: any) => x.activityId === aid)) letters[c.roleId] = c.letter;
    letters[rid] = value;
    if (await run(() => api(`isms/raci/activities/${aid}`, { method: "PUT", body: { letters } }))) reload();
  };
  return <>
    <ErrorNote error={error} />
    <div className="row" style={{ marginBottom: 8 }}><h3 style={{ margin: 0, flex: 1 }}>Roles</h3>{manage && <button className="primary" onClick={() => setEditing({})}>Add role</button>}</div>
    <p className="small muted">The roles that run the ISMS, who holds them, and what each is responsible for. What someone can do in Fenrir is set separately on the ISMS roles tab.</p>
    <Table rows={roles} empty="No roles yet." onRow={manage ? setEditing : undefined} columns={[
      { key: "name", label: "Role", render: (r) => <b>{displayValue(r.name)}</b> },
      { key: "holders", label: "Held by", render: (r) => r.holders.map((h: any) => h.name).join(", ") || "Not assigned" },
      { key: "responsibilities", label: "Responsibilities", render: (r) => displayValue(r.responsibilities) }]} />
    <h3>RACI matrix</h3>
    <p className="small muted">Each activity needs exactly one accountable role and at least one responsible role.</p>
    {raci.activities.length > 0 && raci.roles.length > 0 && <div style={{ overflowX: "auto" }}><table className="small" aria-label="RACI matrix">
      <thead><tr><th scope="col">Activity</th>{raci.roles.map((r: any) => <th key={r.id} scope="col">{r.name}</th>)}{manage && <th scope="col">Remove</th>}</tr></thead>
      <tbody>{raci.activities.map((a: any) => {
        const issues = raci.issues.filter((i: any) => i.activityId === a.id);
        return <tr key={a.id}><th scope="row" style={{ textAlign: "left" }}>{a.title}{issues.length > 0 && <div className="muted">{issues.map((i: any) => i.text).join(" ")}</div>}</th>
          {raci.roles.map((r: any) => <td key={r.id}>{manage
            ? <select aria-label={`${a.title}, ${r.name}`} value={letter(a.id, r.id)} disabled={busy} onChange={(e) => setLetter(a.id, r.id, e.target.value)}>
                <option value="">None</option>{Object.entries(LETTER_WORD).map(([k, w]) => <option key={k} value={k}>{k} ({w})</option>)}</select>
            : (letter(a.id, r.id) ? `${letter(a.id, r.id)} (${LETTER_WORD[letter(a.id, r.id)]})` : "")}</td>)}
          {manage && <td><button disabled={busy} aria-label={`Remove ${a.title}`} onClick={async () => { if (await run(() => api(`isms/raci/activities/${a.id}`, { method: "DELETE" }))) reload(); }}>Remove</button></td>}
        </tr>;
      })}</tbody></table></div>}
    {raci.roles.length === 0 && <p className="small muted">Add roles first.</p>}
    {manage && <div className="row" style={{ gap: 8, alignItems: "end" }}>
      <label className="field" style={{ flex: 1 }}>New activity<input value={activity} onChange={(e) => setActivity(e.target.value)} placeholder="For example run the risk assessment" /></label>
      <button disabled={busy || activity.trim().length < 2} onClick={async () => { if (await run(() => api("isms/raci/activities", { body: { tenantId, title: activity } }))) { setActivity(""); reload(); } }}>Add activity</button>
    </div>}
    {editing && <EditRole tenantId={tenantId} role={editing} onClose={() => { setEditing(null); reload(); }} />}
  </>;
}

function EditRole({ tenantId, role, onClose }: { tenantId: string; role: any; onClose: () => void }) {
  const members = useMembers(tenantId);
  const [f, setF] = useState({ name: role.name ?? "", responsibilities: role.responsibilities ?? "", authorities: role.authorities ?? "", holderIds: safeArray<any>(role.holders).map((h) => h.id) });
  const { run, busy } = useAction();
  const save = async () => { if (await run(() => role.id ? api(`isms/org-roles/${role.id}`, { method: "PATCH", body: f }) : api("isms/org-roles", { body: { tenantId, ...f } }), "Role saved")) onClose(); };
  const remove = async () => { if (confirm(`Remove the role ${role.name}?`) && await run(() => api(`isms/org-roles/${role.id}`, { method: "DELETE" }), "Role removed")) onClose(); };
  return <Modal title={role.id ? `Edit ${role.name}` : "Add a role"} onClose={onClose} footer={<>{role.id && <button disabled={busy} onClick={remove}>Remove</button>}<button className="primary" disabled={busy || f.name.trim().length < 2} onClick={save}>Save</button></>}>
    <label className="field">Name<input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
    <label className="field">Responsibilities<textarea rows={3} value={f.responsibilities} onChange={(e) => setF({ ...f, responsibilities: e.target.value })} /></label>
    <label className="field">Authorities<textarea rows={2} value={f.authorities} onChange={(e) => setF({ ...f, authorities: e.target.value })} /></label>
    <fieldset><legend className="small">Held by</legend>{members.map((m) => <label key={m.id} className="small" style={{ display: "block" }}>
      <input type="checkbox" checked={f.holderIds.includes(m.id)} onChange={() => setF({ ...f, holderIds: f.holderIds.includes(m.id) ? f.holderIds.filter((x) => x !== m.id) : [...f.holderIds, m.id] })} /> {m.name || m.email}</label>)}</fieldset>
  </Modal>;
}

// Competence ----------------------------------------------------------------------------------------------------------

function Competence({ tenantId }: { tenantId: string }) {
  const { data, error, reload } = useData<any>("isms/people", { tenant_id: tenantId }, [tenantId]);
  const [adding, setAdding] = useState(false);
  const { run, busy } = useAction();
  const manage = !!data?.canManage;
  return <>
    <ErrorNote error={error} />
    <div className="row" style={{ marginBottom: 8 }}><span style={{ flex: 1 }} />{manage && <button className="primary" onClick={() => setAdding(true)}>Add record</button>}</div>
    <p className="small muted">Training, qualifications, experience and awareness for the people in the ISMS. Records expiring within 30 days are flagged.</p>
    <Table rows={safeArray<any>(data?.competence)} empty="No records yet." columns={[
      { key: "userName", label: "Person" }, { key: "title", label: "Record", render: (r) => <><b>{displayValue(r.title)}</b><div className="small muted">{KIND_LABEL[r.kind]}</div></> },
      { key: "achievedOn", label: "Achieved", render: (r) => ddmmyyyy(r.achievedOn) },
      { key: "expiresOn", label: "Expires", render: (r) => <>{ddmmyyyy(r.expiresOn)} <Pill value={STATUS[r.status][0]} tone={STATUS[r.status][1]} /></> },
      { key: "evidenceTitle", label: "Evidence", render: (r) => displayValue(r.evidenceTitle ?? "") },
      ...(manage ? [{ key: "id", label: "", render: (r: any) => <button disabled={busy} aria-label={`Remove ${r.title} for ${r.userName}`} onClick={async () => { if (await run(() => api(`isms/competence/${r.id}`, { method: "DELETE" }))) reload(); }}>Remove</button> }] : [])]} />
    {adding && <AddCompetence tenantId={tenantId} onClose={() => { setAdding(false); reload(); }} />}
  </>;
}

function AddCompetence({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const members = useMembers(tenantId);
  const { data: ev } = useData<any>("isms/evidence", { tenant_id: tenantId }, [tenantId]);
  const [f, setF] = useState({ userId: "", kind: "training", title: "", achievedOn: "", expiresOn: "", evidenceId: "", notes: "" });
  const { run, busy } = useAction();
  const save = async () => { if (await run(() => api("isms/competence", { body: { tenantId, ...f, expiresOn: f.expiresOn || null, evidenceId: f.evidenceId || null } }), "Record added")) onClose(); };
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value });
  return <Modal title="Add a competence record" onClose={onClose} footer={<button className="primary" disabled={busy || !f.userId || f.title.trim().length < 2 || !f.achievedOn} onClick={save}>Add</button>}>
    <label className="field">Person<select value={f.userId} onChange={set("userId")}><option value="">Choose</option>{members.map((m) => <option key={m.id} value={m.id}>{m.name || m.email}</option>)}</select></label>
    <label className="field">Type<select value={f.kind} onChange={set("kind")}>{Object.entries(KIND_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
    <label className="field">Title<input value={f.title} onChange={set("title")} /></label>
    <label className="field">Achieved on<input type="date" value={f.achievedOn} onChange={set("achievedOn")} /></label>
    <label className="field">Expires on (optional)<input type="date" value={f.expiresOn} onChange={set("expiresOn")} /></label>
    {safeArray<any>(ev?.evidence).length > 0 && <label className="field">Evidence (optional)<select value={f.evidenceId} onChange={set("evidenceId")}><option value="">None</option>{safeArray<any>(ev?.evidence).map((e) => <option key={e.id} value={e.id}>{e.title}</option>)}</select></label>}
    <label className="field">Notes<textarea rows={2} value={f.notes} onChange={set("notes")} /></label>
  </Modal>;
}

// Acknowledgements ----------------------------------------------------------------------------------------------------

function Acknowledgements({ tenantId }: { tenantId: string }) {
  const { data: mine, reload: reloadMine } = useData<any>("isms/acknowledgements/mine", {}, [tenantId]);
  const { data, error, reload } = useData<any>("isms/acknowledgements/campaigns", { tenant_id: tenantId }, [tenantId]);
  const [reading, setReading] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  const pending = safeArray<any>(mine?.pending).filter((p) => p.tenantId === tenantId);
  const manage = !!data?.canManage;
  return <>
    <ErrorNote error={error} />
    <h3>For you to read</h3>
    {pending.length === 0 ? <p className="small muted">Nothing waiting for you.</p> : <Table rows={pending} onRow={(p) => setReading(p.id)} columns={[
      { key: "documentTitle", label: "Document", render: (p) => <b>{p.documentNumber} {displayValue(p.documentTitle)} (version {p.version})</b> },
      { key: "dueOn", label: "Due", render: (p) => <>{ddmmyyyy(p.dueOn)}{p.overdue && <> <Pill value="overdue" tone="bad" /></>}</> }]} />}
    {(manage || safeArray<any>(data?.campaigns).length > 0) && <>
      <div className="row" style={{ marginTop: 12 }}><h3 style={{ margin: 0, flex: 1 }}>Campaigns</h3>{manage && <button className="primary" disabled={!safeArray<any>(data?.candidates).length} onClick={() => setStarting(true)}>Ask people to acknowledge</button>}</div>
      <p className="small muted">A campaign asks everyone holding the chosen ISMS roles to read one published document. Client portal accounts acknowledge in the client portal. Reminders go out daily from 3 days before the due date.</p>
      <Table rows={safeArray<any>(data?.campaigns)} empty="No campaigns yet." onRow={manage ? (c) => setDetail(c.id) : undefined} columns={[
        { key: "documentTitle", label: "Document", render: (c) => <><b>{c.documentNumber} {displayValue(c.documentTitle)}</b><div className="small muted">Version {c.version}{c.superseded ? ", no longer the published version" : ""}</div></> },
        { key: "audienceRoles", label: "Asked", render: (c) => c.audienceRoles.length ? c.audienceRoles.map((r: string) => ROLE_LABEL[r] ?? r).join(", ") : "Everyone with a role" },
        { key: "progress", label: "Done", render: (c) => `${c.progress.done} of ${c.progress.total} (${c.progress.percent}%)` },
        { key: "dueOn", label: "Due", render: (c) => <>{ddmmyyyy(c.dueOn)}{c.overdue && <> <Pill value="overdue" tone="bad" /></>}</> },
        { key: "status", label: "Status", render: (c) => c.status === "open" ? "Open" : "Closed" }]} />
      {manage && safeArray<any>(data?.byUser).length > 0 && <>
        <h3>By person</h3>
        <Table rows={safeArray<any>(data?.byUser)} columns={[{ key: "name", label: "Person" }, { key: "done", label: "Acknowledged", render: (u) => `${u.done} of ${u.asked}` }]} />
      </>}
    </>}
    {reading && <ReadAndAcknowledge id={reading} onClose={() => { setReading(null); reloadMine(); reload(); }} />}
    {starting && <StartCampaign tenantId={tenantId} candidates={safeArray<any>(data?.candidates)} roles={safeArray<string>(data?.roles)} onClose={() => { setStarting(false); reload(); }} />}
    {detail && <CampaignDetail id={detail} onClose={() => { setDetail(null); reload(); }} />}
  </>;
}

function ReadAndAcknowledge({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, error } = useData<any>(`isms/acknowledgements/${id}/read`, {}, [id]);
  const [ok, setOk] = useState(false);
  const { run, busy } = useAction();
  if (!data) return <Modal title="Document" onClose={onClose}><ErrorNote error={error} /></Modal>;
  const done = async () => { if (await run(() => api(`isms/acknowledgements/${id}/acknowledge`, { body: { sha256: data.sha256, confirm: true } }), "Thank you: your acknowledgement is recorded")) onClose(); };
  return <Modal title={`${data.documentNumber} ${data.documentTitle}`} wide onClose={onClose} footer={!data.acknowledgedAt && <button className="primary" disabled={!ok || busy} onClick={done}>Acknowledge</button>}>
    <p className="small">Version {data.version}, please read by {ddmmyyyy(data.dueOn)}.</p>
    <div className="card" style={{ maxHeight: 420, overflowY: "auto" }}>{safeArray<any>(data.blocks).map((b) => <section key={b.ref} aria-label={b.ref}><Markdown text={b.markdown} /></section>)}</div>
    {data.acknowledgedAt ? <p className="small">You acknowledged this on {fmtTime(data.acknowledgedAt)}.</p>
      : <label className="small"><input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} /> I have read and understood this document</label>}
  </Modal>;
}

function StartCampaign({ tenantId, candidates, roles, onClose }: { tenantId: string; candidates: any[]; roles: string[]; onClose: () => void }) {
  const [f, setF] = useState({ documentVersionId: candidates[0]?.versionId ?? "", dueOn: "", audienceRoles: [] as string[] });
  const { run, busy } = useAction();
  const save = async () => { if (await run(() => api("isms/acknowledgements/campaigns", { body: { tenantId, ...f } }), "Campaign started; people have been emailed")) onClose(); };
  return <Modal title="Ask people to acknowledge a document" onClose={onClose} footer={<button className="primary" disabled={busy || !f.documentVersionId || !f.dueOn} onClick={save}>Start</button>}>
    <label className="field">Document<select value={f.documentVersionId} onChange={(e) => setF({ ...f, documentVersionId: e.target.value })}>{candidates.map((c) => <option key={c.versionId} value={c.versionId}>{c.number} {c.title} (version {c.version})</option>)}</select></label>
    <label className="field">Due by<input type="date" value={f.dueOn} onChange={(e) => setF({ ...f, dueOn: e.target.value })} /></label>
    <fieldset><legend className="small">Ask (none ticked means everyone with an ISMS role)</legend>{roles.map((r) => <label key={r} className="small" style={{ display: "block" }}>
      <input type="checkbox" checked={f.audienceRoles.includes(r)} onChange={() => setF({ ...f, audienceRoles: f.audienceRoles.includes(r) ? f.audienceRoles.filter((x) => x !== r) : [...f.audienceRoles, r] })} /> {ROLE_LABEL[r] ?? r}</label>)}</fieldset>
  </Modal>;
}

function CampaignDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, error, reload } = useData<any>(`isms/acknowledgements/campaigns/${id}`, {}, [id]);
  const { run, busy } = useAction();
  if (!data) return <Modal title="Campaign" onClose={onClose}><ErrorNote error={error} /></Modal>;
  return <Modal title={`${data.documentNumber} ${data.documentTitle}, version ${data.version}`} wide onClose={onClose}
    footer={data.status === "open" && <button disabled={busy} onClick={async () => { if (await run(() => api(`isms/acknowledgements/campaigns/${id}/close`, { body: {} }), "Campaign closed")) reload(); }}>Close campaign</button>}>
    <p className="small">{data.progress.done} of {data.progress.total} have acknowledged. Due {ddmmyyyy(data.dueOn)}.</p>
    <Table rows={data.people} columns={[{ key: "name", label: "Person" }, { key: "role", label: "ISMS role", render: (p) => ROLE_LABEL[p.role] ?? p.role },
      { key: "acknowledgedAt", label: "Acknowledged", render: (p) => p.acknowledgedAt ? `${fmtTime(p.acknowledgedAt)}${p.via === "portal" ? " (client portal)" : ""}` : <Pill value="waiting" tone="warn" /> }]} />
  </Modal>;
}
