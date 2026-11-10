// Device groups: create, nest, rename, give a policy, see and move members, delete. Used on the Device groups page,
// in Settings, and as a picker (with "New group…") wherever a device or enrolment code can be put in a group.
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useApp } from "../app-context";
import { confirmDialog, promptDialog } from "./dialogs";
import { displayValue } from "./DisplayValue";
import { ErrorNote, Modal, Table, TenantSelect, useAction, useListData } from "./ui";

export interface RuleCondition { field: string; op: string; value: string }
export interface GroupRules { enabled?: boolean; match?: "all" | "any"; priority?: number; conditions?: RuleCondition[] }
export interface Group { id: string; tenantId: string; name: string; parentId: string | null; policyId: string | null; deviceCount?: number; childCount?: number; matchRules?: GroupRules }

// Automatic membership (cloud group_rules.py): what each field can be tested with, and how a rule reads in words.
export const RULE_FIELDS: Record<string, { label: string; ops: string[]; hint: string; options?: string[] }> = {
  platform: { label: "Platform", ops: ["is", "is not"], hint: "", options: ["windows", "linux", "macos", "android", "ios"] },
  role: { label: "Role", ops: ["is", "is not"], hint: "", options: ["workstation", "server", "domain-controller", "phone", "tablet", "computer"] },
  hostname: { label: "Device name", ops: ["matches", "does not match"], hint: "e.g. LDN-* (* is any text, ? is one character)" },
  os: { label: "Operating system", ops: ["contains", "does not contain"], hint: "e.g. Windows 11, Server 2022, Ubuntu" },
  tag: { label: "Tag", ops: ["has", "does not have"], hint: "e.g. kiosk" },
  ip: { label: "IP address", ops: ["in", "not in"], hint: "a range, e.g. 10.20.0.0/16" },
};

export function describeRules(rules: GroupRules | undefined | null): string {
  const conditions = rules?.conditions ?? [];
  if (!rules?.enabled || !conditions.length) return "";
  return conditions.map((c) => `${RULE_FIELDS[c.field]?.label ?? c.field} ${c.op} ${c.value}`).join(rules.match === "any" ? " or " : " and ");
}

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
  const { tenantId, can, tenantName, toast } = useApp();
  const { data, error, reload } = useListData<Group>("groups", { tenant_id: tenantId }, [tenantId]);
  const { data: policies } = useListData<any>("policies", { tenant_id: tenantId }, [tenantId]);
  const [form, setForm] = useState<any>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [preview, setPreview] = useState<any>(null);
  const { run, busy } = useAction();
  const blank = { name: "", tenantId: tenantId || "", parentId: "", policyId: "", match: "all", priority: 100, conditions: [] as RuleCondition[] };
  const open = (g: Group) => { setPreview(null); setForm({ id: g.id, tenantId: g.tenantId, name: g.name, parentId: g.parentId ?? "", policyId: g.policyId ?? "",
    match: g.matchRules?.match ?? "all", priority: g.matchRules?.priority ?? 100, conditions: [...(g.matchRules?.conditions ?? [])] }); };
  const setCondition = (i: number, patch: Partial<RuleCondition>) =>
    setForm({ ...form, conditions: form.conditions.map((c: RuleCondition, j: number) => (i === j ? { ...c, ...patch } : c)) });
  const showPreview = async () => {
    const conditions = (form.conditions as RuleCondition[]).filter((c) => c.value.trim());
    setPreview(await run(() => api<any>("groups/rules/preview", { body: { tenantId: form.tenantId, groupId: form.id ?? null,
      matchRules: { enabled: true, match: form.match, priority: Number(form.priority) || 100, conditions } } })) ?? null);
  };
  const groups = data ?? [];
  const tree = useMemo(() => groupTree(groups), [groups]);
  const policyName = (id: string | null) => (id ? policies?.find((p) => p.id === id)?.name ?? "Policy" : "Inherit");
  const editable = (g: Group | null) => groups.filter((x) => x.tenantId === (g?.tenantId ?? form?.tenantId) && !(g && descendants(groups, g.id).has(x.id)));

  const save = async () => {
    setProblem(null);
    const conditions = (form.conditions as RuleCondition[]).filter((c) => c.value.trim());
    const matchRules = conditions.length ? { enabled: true, match: form.match, priority: Number(form.priority) || 100, conditions } : null;
    const body = { name: form.name, parentId: form.parentId || null, policyId: form.policyId || null, matchRules };
    const done = await run(() => form.id ? api<any>(`groups/${form.id}`, { method: "PATCH", body }) : api<any>("groups", { body: { ...body, tenantId: form.tenantId } }));
    if (done) {
      toast(`${form.id ? "Group saved" : "Group created"}${done.rulesMoved ? `: its rules moved ${done.rulesMoved} device${done.rulesMoved === 1 ? "" : "s"}` : ""}`);
      setForm(null); setPreview(null); reload();
    }
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
        {can("configure") && <button className="primary" onClick={() => { setPreview(null); setForm(blank); }}>New group</button>}
      </div>
      <ErrorNote error={error || problem} />
      <Table rows={tree.map(({ group, depth }) => ({ ...group, depth }))} empty="No groups yet."
             columns={[
               { key: "name", label: "Group", render: (g: any) => <span style={{ paddingLeft: g.depth * 20 }}>{g.depth > 0 && <span className="muted">└ </span>}<b>{displayValue(g.name)}</b>
                 {(g.childCount ?? 0) > 0 && <span className="small muted"> · {g.childCount} sub-group{g.childCount === 1 ? "" : "s"}</span>}</span> },
               ...(!tenantId ? [{ key: "tenantId", label: "Customer", render: (g: any) => tenantName(g.tenantId) }] : []),
               { key: "policyId", label: "Policy", render: (g: any) => displayValue(policyName(g.policyId)) },
               { key: "matchRules", label: "Automatic membership", render: (g: any) => describeRules(g.matchRules)
                   ? <span className="small" title={`Priority ${g.matchRules.priority ?? 100}: the lowest number wins when several groups match`}>{displayValue(describeRules(g.matchRules))}</span>
                   : <span className="small muted">by hand</span> },
               { key: "deviceCount", label: "Devices", render: (g: any) => <Link to={`/devices?group=${g.id}`}>{g.deviceCount ?? 0} device{g.deviceCount === 1 ? "" : "s"}</Link> },
               { key: "actions", label: "", render: (g: any) => can("configure") && <span style={{ whiteSpace: "nowrap" }}>
                   <button className="small" onClick={() => rename(g)}>Rename</button>{" "}
                   <button className="small" onClick={() => open(g)}>Edit</button>{" "}
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
          <h3 style={{ marginTop: 14 }}>Automatic membership</h3>
          <p className="small muted" style={{ marginTop: 0 }}>Devices that match join this group by themselves: when they enrol, when their details change, and every hour.
            A device someone placed by hand stays where it was put until it is set back to Automatic.</p>
          {form.conditions.map((c: RuleCondition, i: number) => {
            const field = RULE_FIELDS[c.field];
            return (
              <div key={i} className="row" style={{ gap: 6, marginBottom: 6, flexWrap: "wrap" }}>
                <select value={c.field} aria-label="Field" onChange={(e) => setCondition(i, { field: e.target.value, op: RULE_FIELDS[e.target.value].ops[0], value: "" })}>
                  {Object.entries(RULE_FIELDS).map(([key, f]) => <option key={key} value={key}>{f.label}</option>)}</select>
                <select value={c.op} aria-label="Test" onChange={(e) => setCondition(i, { op: e.target.value })}>{field.ops.map((o) => <option key={o}>{o}</option>)}</select>
                {field.options
                  ? <select value={c.value} aria-label="Value" onChange={(e) => setCondition(i, { value: e.target.value })}><option value="">Choose…</option>{field.options.map((o) => <option key={o}>{o}</option>)}</select>
                  : <input value={c.value} aria-label="Value" placeholder={field.hint} style={{ flex: 1, minWidth: 160 }} onChange={(e) => setCondition(i, { value: e.target.value })} />}
                <button className="small ghost" aria-label="Remove condition" onClick={() => { setPreview(null); setForm({ ...form, conditions: form.conditions.filter((_: unknown, j: number) => j !== i) }); }}>✕</button>
              </div>);
          })}
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <button className="small" onClick={() => setForm({ ...form, conditions: [...form.conditions, { field: "hostname", op: "matches", value: "" }] })}>Add a condition</button>
            {form.conditions.length > 1 && <label className="small">Match <select value={form.match} onChange={(e) => setForm({ ...form, match: e.target.value })}>
              <option value="all">all of them</option><option value="any">any of them</option></select></label>}
            {form.conditions.length > 0 && <label className="small" title="When a device matches several groups, the lowest number wins">Priority
              <input type="number" min={0} max={10000} value={form.priority} style={{ width: 80, marginLeft: 6 }} onChange={(e) => setForm({ ...form, priority: e.target.value })} /></label>}
            {form.conditions.some((c: RuleCondition) => c.value.trim()) && form.tenantId && <button className="small" disabled={busy} onClick={showPreview}>See which devices match</button>}
          </div>
          {preview && <p className="small" role="status"><b>{preview.count}</b> device{preview.count === 1 ? "" : "s"} match{preview.count === 1 ? "es" : ""}
            {preview.devices.length > 0 && <>: {preview.devices.slice(0, 12).map((d: any) => d.hostname).join(", ")}{preview.count > 12 ? "…" : ""}</>}
            {preview.placedByHand > 0 && <>. {preview.placedByHand} of them {preview.placedByHand === 1 ? "was" : "were"} placed by hand and will stay where {preview.placedByHand === 1 ? "it is" : "they are"}.</>}</p>}
          {form.conditions.length === 0 && <p className="small muted">No conditions: devices join only when someone puts them here (Devices › Move to group, a device's Settings tab, or an enrolment code).</p>}
        </Modal>
      )}
    </div>
  );
}
