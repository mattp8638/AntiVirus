// Device groups: create, nest, rename, give a policy, see and move members, delete. Used on the Device groups page,
// in Settings, and as a picker (with "New group…") wherever a device or enrolment code can be put in a group.
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useApp } from "../app-context";
import { confirmDialog, promptDialog } from "./dialogs";
import { displayValue } from "./DisplayValue";
import { ErrorNote, Modal, Table, TenantSelect, useAction, useListData } from "./ui";

export interface Group { id: string; tenantId: string; name: string; parentId: string | null; policyId: string | null; deviceCount?: number; childCount?: number }

/** Groups in tree order, each with its depth, so children sit under their parent. */
export function groupTree(groups: Group[]): { group: Group; depth: number; path: string }[] {
  const byParent = new Map<string | null, Group[]>();
  const ids = new Set(groups.map((g) => g.id));
  for (const g of groups) {
    const parent = g.parentId && ids.has(g.parentId) ? g.parentId : null;
    byParent.set(parent, [...(byParent.get(parent) ?? []), g]);
  }
  const out: { group: Group; depth: number; path: string }[] = [];
  const seen = new Set<string>();
  const walk = (parent: string | null, depth: number, prefix: string) => {
    for (const g of (byParent.get(parent) ?? []).sort((a, b) => a.name.localeCompare(b.name))) {
      if (seen.has(g.id)) continue;
      seen.add(g.id);
      const path = prefix ? `${prefix} › ${g.name}` : g.name;
      out.push({ group: g, depth, path });
      walk(g.id, depth + 1, path);
    }
  };
  walk(null, 0, "");
  return out;
}

/** A group and every group below it (a group cannot be moved under any of these). */
export function descendants(groups: Group[], id: string): Set<string> {
  const found = new Set([id]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const g of groups) if (g.parentId && found.has(g.parentId) && !found.has(g.id)) { found.add(g.id); grew = true; }
  }
  return found;
}

/** A group drop-down with "New group…" at the end, for one customer. */
export function GroupSelect({ tenantId, value, onChange, emptyLabel = "No group", disabled }: {
  tenantId: string; value: string; onChange: (id: string) => void; emptyLabel?: string; disabled?: boolean;
}) {
  const { can } = useApp();
  const { data, reload } = useListData<Group>(tenantId ? "groups" : null, { tenant_id: tenantId }, [tenantId]);
  const { run } = useAction();
  const tree = groupTree(data ?? []);
  const create = async () => {
    const name = await promptDialog("Name the new group", "", { title: "New group" });
    if (!name?.trim()) return;
    const made = await run(() => api<Group>("groups", { body: { tenantId, name: name.trim() } }), "Group created");
    if (made) { await reload(); onChange(made.id); }
  };
  return (
    <select value={value} disabled={disabled || !tenantId} onChange={(e) => (e.target.value === "__new" ? create() : onChange(e.target.value))}>
      <option value="">{emptyLabel}</option>
      {tree.map(({ group, path }) => <option key={group.id} value={group.id}>{displayValue(path)}</option>)}
      {can("configure") && tenantId && <option value="__new">＋ New group…</option>}
    </select>
  );
}

export function GroupsManager() {
  const { tenantId, can, tenantName } = useApp();
  const { data, error, reload } = useListData<Group>("groups", { tenant_id: tenantId }, [tenantId]);
  const { data: policies } = useListData<any>("policies", { tenant_id: tenantId }, [tenantId]);
  const [form, setForm] = useState<any>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const { run, busy } = useAction();
  const groups = data ?? [];
  const tree = useMemo(() => groupTree(groups), [groups]);
  const policyName = (id: string | null) => (id ? policies?.find((p) => p.id === id)?.name ?? "Policy" : "Inherit");
  const editable = (g: Group | null) => groups.filter((x) => x.tenantId === (g?.tenantId ?? form?.tenantId) && !(g && descendants(groups, g.id).has(x.id)));

  const save = async () => {
    setProblem(null);
    const body = { name: form.name, parentId: form.parentId || null, policyId: form.policyId || null };
    const done = await run(() => form.id ? api(`groups/${form.id}`, { method: "PATCH", body }) : api("groups", { body: { ...body, tenantId: form.tenantId } }),
                           form.id ? "Group saved" : "Group created");
    if (done) { setForm(null); reload(); }
  };
  const remove = async (g: Group) => {
    const parent = groups.find((x) => x.id === g.parentId);
    const where = parent ? `"${parent.name}"` : "no group";
    if (!(await confirmDialog(`Delete the group "${g.name}"? Its ${g.deviceCount ?? 0} device(s), sub-groups and enrolment codes move to ${where}. Nothing on the devices changes except the policy they inherit.`,
                              { title: "Delete group", confirmLabel: "Delete group", danger: true }))) return;
    setProblem(null);
    try {
      await api(`groups/${g.id}`, { method: "DELETE" });
      reload();
    } catch (err) { setProblem((err as Error).message); }
  };
  const rename = async (g: Group) => {
    const name = await promptDialog("New name", g.name, { title: "Rename group" });
    if (name?.trim() && name.trim() !== g.name && await run(() => api(`groups/${g.id}`, { method: "PATCH", body: { name: name.trim() } }), "Renamed")) reload();
  };

  return (
    <div className="card">
      <div className="row" style={{ marginBottom: 10 }}>
        <span className="small muted" style={{ flex: 1 }}>Groups organise devices inside a customer (sites, departments, servers, kiosks). A group can have
          its own protection policy, which its devices and sub-groups inherit. Scripts, patch policies, monitors and schedules can target groups.</span>
        {can("configure") && <button className="primary" onClick={() => setForm({ name: "", tenantId: tenantId || "", parentId: "", policyId: "" })}>New group</button>}
      </div>
      <ErrorNote error={error || problem} />
      <Table rows={tree.map(({ group, depth }) => ({ ...group, depth }))} empty="No groups yet."
             columns={[
               { key: "name", label: "Group", render: (g: any) => <span style={{ paddingLeft: g.depth * 20 }}>{g.depth > 0 && <span className="muted">└ </span>}<b>{displayValue(g.name)}</b>
                 {(g.childCount ?? 0) > 0 && <span className="small muted"> · {g.childCount} sub-group{g.childCount === 1 ? "" : "s"}</span>}</span> },
               ...(!tenantId ? [{ key: "tenantId", label: "Customer", render: (g: any) => tenantName(g.tenantId) }] : []),
               { key: "policyId", label: "Policy", render: (g: any) => displayValue(policyName(g.policyId)) },
               { key: "deviceCount", label: "Devices", render: (g: any) => <Link to={`/devices?group=${g.id}`}>{g.deviceCount ?? 0} device{g.deviceCount === 1 ? "" : "s"}</Link> },
               { key: "actions", label: "", render: (g: any) => can("configure") && <span style={{ whiteSpace: "nowrap" }}>
                   <button className="small" onClick={() => rename(g)}>Rename</button>{" "}
                   <button className="small" onClick={() => setForm({ id: g.id, tenantId: g.tenantId, name: g.name, parentId: g.parentId ?? "", policyId: g.policyId ?? "" })}>Edit</button>{" "}
                   <button className="small danger" onClick={() => remove(g)}>Delete</button></span> },
             ]} />
      {form && (
        <Modal title={form.id ? `Edit ${form.name || "group"}` : "New group"} onClose={() => setForm(null)}
               footer={<button className="primary" disabled={busy || !form.tenantId || !form.name.trim()} onClick={save}>{form.id ? "Save" : "Create"}</button>}>
          <div className="form-grid">
            {!form.id && <label className="field">Customer<TenantSelect value={form.tenantId} onChange={(id) => setForm({ ...form, tenantId: id, parentId: "", policyId: "" })} allowAll={false} /></label>}
            <label className="field">Name<input value={form.name} autoFocus maxLength={200} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. Leeds office" /></label>
            <label className="field">Inside group
              <select value={form.parentId} onChange={(e) => setForm({ ...form, parentId: e.target.value })}>
                <option value="">None (top level)</option>
                {groupTree(editable(form.id ? groups.find((g) => g.id === form.id) ?? null : null)).map(({ group, path }) =>
                  <option key={group.id} value={group.id}>{displayValue(path)}</option>)}
              </select></label>
            <label className="field">Protection policy
              <select value={form.policyId} onChange={(e) => setForm({ ...form, policyId: e.target.value })}>
                <option value="">Inherit (from the parent group or customer)</option>
                {policies?.filter((p) => !p.tenantId || p.tenantId === form.tenantId).map((p) => <option key={p.id} value={p.id}>{displayValue(p.name)}</option>)}
              </select></label>
          </div>
          <p className="small muted">To put devices in this group, select them on the Devices page and choose <b>Move to group</b>, or pick the group on a device's Settings tab or when you make an enrolment code.</p>
        </Modal>
      )}
    </div>
  );
}
