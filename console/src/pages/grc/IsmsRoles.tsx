import { useState } from "react";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { confirmDialog } from "../../components/dialogs";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** ISMS roles per person per customer. Everyone needs one to work in the ISMS for a customer, whatever their Fenrir role. */
export const ISMS_ROLE_LABEL: Record<string, string> = {
  tenant_admin: "ISMS administrator",
  isms_manager: "ISMS manager",
  control_owner: "Control and risk owner",
  approver: "Approver",
  staff: "Staff (reads and acknowledges policies)",
  auditor: "Auditor (read-only, time-limited)",
  executive_viewer: "Executive viewer",
};
const ROLES = Object.keys(ISMS_ROLE_LABEL);

type Membership = { id: string; userId: string; email: string; name: string; role: string; portal: boolean; expiresAt: string | null; grantedBy: string };
type Person = { id: string; email: string; name: string; portal: boolean };

export function IsmsRolesTab() {
  const { tenantId } = useApp();
  const { data: me, error: meError } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  const canManage = !!me?.canManageRoles;
  const { data, error, reload } = useData<{ memberships: Membership[] }>(canManage ? "isms/memberships" : null, { tenant_id: tenantId }, [tenantId, canManage]);
  const [editing, setEditing] = useState<Membership | "new" | null>(null);
  const { run } = useAction();
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its ISMS roles.</p>;
  const remove = async (m: Membership) => {
    if (!(await confirmDialog(`Remove ${m.email}'s ISMS role? They lose access to this customer's ISMS straight away.`, { confirmLabel: "Remove role", danger: true }))) return;
    await run(() => api(`isms/memberships/${m.id}`, { method: "DELETE" }), "Role removed");
    reload();
  };
  return (
    <div className="card">
      <ErrorNote error={meError || error} />
      <p className="small">
        Your ISMS role here: {me?.role ? <Pill value={ISMS_ROLE_LABEL[me.role] ?? me.role} tone="good" /> : <Pill value="none" />}
      </p>
      <p className="small muted">Everyone needs an ISMS role to work in this customer's ISMS, whatever their Fenrir role. Staff read and acknowledge policies in the client portal. Auditor access always ends on a set date.</p>
      {canManage && <>
        <div className="row" style={{ justifyContent: "flex-end", marginBottom: 8 }}>
          <button className="primary" onClick={() => setEditing("new")}>Give someone a role</button>
        </div>
        <Table rows={safeArray<Membership>(data?.memberships)} empty="Nobody has an ISMS role for this customer yet." onRow={(m) => setEditing(m)}
          columns={[
            { key: "email", label: "Person", render: (m) => <><b>{displayValue(m.name || m.email)}</b><div className="small muted">{displayValue(m.email)}{m.portal ? " (portal)" : ""}</div></> },
            { key: "role", label: "ISMS role", render: (m) => ISMS_ROLE_LABEL[m.role] ?? m.role },
            { key: "expiresAt", label: "Ends", render: (m) => <span className="small">{m.expiresAt ? fmtTime(m.expiresAt) : "No end date"}</span> },
            { key: "grantedBy", label: "Set by", render: (m) => <span className="small">{displayValue(m.grantedBy)}</span> },
            { key: "id", label: "", render: (m) => <button className="small" onClick={(e) => { e.stopPropagation(); remove(m); }} aria-label={`Remove ${m.email}'s role`}>Remove</button> },
          ]} />
      </>}
      {editing && <RoleEditor tenantId={tenantId} membership={editing === "new" ? null : editing} onClose={() => { setEditing(null); reload(); }} />}
    </div>
  );
}

function RoleEditor({ tenantId, membership, onClose }: { tenantId: string; membership: Membership | null; onClose: () => void }) {
  const { data } = useData<{ people: Person[] }>(membership ? null : "isms/candidates", { tenant_id: tenantId }, [tenantId]);
  const people = safeArray<Person>(data?.people);
  const [userId, setUserId] = useState(membership?.userId ?? "");
  const [role, setRole] = useState(membership?.role ?? "staff");
  const [ends, setEnds] = useState(membership?.expiresAt?.slice(0, 10) ?? "");
  const { run, busy } = useAction();
  const portal = membership ? membership.portal : !!people.find((p) => p.id === userId)?.portal;
  const allowed = portal ? ["staff"] : ROLES;
  const needsEnd = role === "auditor";
  const save = async () => {
    const expiresAt = ends ? `${ends}T23:59:59Z` : null;
    const saved = await run(() => api("isms/memberships", { method: "PUT", body: { tenantId, userId, role, expiresAt } }), "ISMS role saved");
    if (saved) onClose();
  };
  return (
    <Modal title={membership ? `ISMS role for ${membership.email}` : "Give someone an ISMS role"} onClose={onClose}
      footer={<button className="primary" disabled={busy || !userId || !allowed.includes(role) || (needsEnd && !ends)} onClick={save}>Save</button>}>
      {!membership && <label className="field">Person
        <select value={userId} onChange={(e) => { setUserId(e.target.value); if (people.find((p) => p.id === e.target.value)?.portal) setRole("staff"); }}>
          <option value="">Choose a person</option>
          {people.map((p) => <option key={p.id} value={p.id}>{p.name ? `${p.name} (${p.email})` : p.email}{p.portal ? ", portal" : ""}</option>)}
        </select>
      </label>}
      <label className="field">ISMS role
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          {allowed.map((r) => <option key={r} value={r}>{ISMS_ROLE_LABEL[r]}</option>)}
        </select>
      </label>
      <label className="field">{needsEnd ? "Access ends on (required, at most a year away)" : "Access ends on (optional)"}
        <input type="date" value={ends} onChange={(e) => setEnds(e.target.value)} />
      </label>
      {portal && <p className="small muted">Client portal accounts can only be staff.</p>}
    </Modal>
  );
}
