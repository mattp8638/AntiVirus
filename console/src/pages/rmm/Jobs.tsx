import { displayValue } from "../../components/DisplayValue";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ago, api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { describeTargets, emptyTargets, JobDetail, JobStatus, TargetPicker, Targets } from "../../components/rmm";
import { Modal, PageHead, Pill, Table, Tabs, useAction, useListData } from "../../components/ui";

export default function Jobs() {
  const { tenantId, tenantName } = useApp();
  const [searchParams, setSearchParams] = useSearchParams();
  const [tab, setTab] = useState("Activity");
  const { data, reload } = useListData<any>("rmm/jobs", { tenant_id: tenantId });
  const [jobId, setJobId] = useState<string | null>(searchParams.get("job"));
  useEffect(() => { const linked = searchParams.get("job"); if (linked) { setTab("Activity"); setJobId(linked); } }, [searchParams]);
  useEffect(() => { const t = window.setInterval(reload, 8000); return () => window.clearInterval(t); }, [reload]);
  return (
    <>
      <PageHead title="Automation" subtitle="Every script, patch and deployment job, plus schedules that run them for you." />
      <Tabs tabs={["Activity", "Scheduled tasks"]} active={tab} onChange={setTab} />
      {tab === "Activity" ? (
        <div className="card">
          <Table rows={data} onRow={(j) => setJobId(j.id)} empty="No jobs yet. Run a script or deploy software to start one."
                 columns={[{ key: "name", label: "Job", render: (j) => <><b>{displayValue(j.name)}</b><div className="small muted">{displayValue(j.commandType)}</div></> },
                           { key: "targets", label: "Targets", render: (j) => <span className="small">{describeTargets(j.targets, tenantName) !== "—" ? describeTargets(j.targets, tenantName) : `${j.summary.total} device(s)`}</span> },
                           { key: "status", label: "Status", render: (j) => <JobStatus job={j} /> },
                           { key: "createdBy", label: "By", render: (j) => <span className="small">{displayValue(j.createdBy)}</span> },
                           { key: "createdAt", label: "Started", render: (j) => ago(j.createdAt) }]} />
        </div>
      ) : <ScheduledTasks />}
      {jobId && <JobDetail jobId={jobId} onClose={() => { setJobId(null); if (searchParams.has("job")) { setSearchParams({}); } reload(); }} />}
    </>
  );
}

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

function describeSchedule(s: any) {
  if (!s) return "—";
  switch (s.type) {
    case "interval": return `Every ${s.everyMinutes} min`;
    case "daily": return `Daily at ${s.at}`;
    case "weekly": return `${(s.days || []).map((d: number) => DAYS[d]).join(", ")} at ${s.at}`;
    case "monthly": return `Day ${s.dayOfMonth} of each month at ${s.at}`;
    case "once": return `Once on ${s.date} at ${s.at}`;
  }
  return s.type;
}

function ScheduledTasks() {
  const { can, tenantName } = useApp();
  const { data, reload } = useListData<any>("rmm/tasks");
  const [editing, setEditing] = useState<any>(null);
  const { run } = useAction();
  return (
    <>
      <div className="row" style={{ marginBottom: 12 }}>
        <span className="muted small">Schedules run in the cloud. Offline devices pick their actions up when they reconnect.</span>
        <span style={{ flex: 1 }} />
        {can("configure") && <button className="primary" onClick={() => setEditing({ name: "", schedule: { type: "daily", at: "02:00", tz: Intl.DateTimeFormat().resolvedOptions().timeZone }, targets: emptyTargets(), actions: [], enabled: true })}>New schedule</button>}
      </div>
      <div className="card">
        <Table rows={data} onRow={setEditing} empty="No scheduled tasks."
               columns={[{ key: "name", label: "Task", render: (t) => <b>{displayValue(t.name)}</b> },
                         { key: "schedule", label: "When", render: (t) => describeSchedule(t.schedule) },
                         { key: "targets", label: "Targets", render: (t) => <span className="small">{describeTargets(t.targets, tenantName)}</span> },
                         { key: "actions", label: "Actions", render: (t) => t.actions.length },
                         { key: "nextRunAt", label: "Next run", render: (t) => t.enabled ? fmtTime(t.nextRunAt) : <Pill value="paused" tone="muted" /> },
                         { key: "lastRunAt", label: "Last run", render: (t) => ago(t.lastRunAt) },
                         { key: "go", label: "", render: (t) => can("configure") && <button className="small" onClick={async (e) => { e.stopPropagation(); await run(() => api(`rmm/tasks/${t.id}/run`, { method: "POST" }), "Started"); reload(); }}>Run now</button> }]} />
      </div>
      {editing && <TaskEditor task={editing} onClose={() => { setEditing(null); reload(); }} />}
    </>
  );
}

function TaskEditor({ task, onClose }: { task: any; onClose: () => void }) {
  const [form, setForm] = useState<any>({ ...task, targets: { ...emptyTargets(), ...task.targets } });
  const { data: scripts } = useListData<any>("rmm/scripts");
  const { data: packages } = useListData<any>("rmm/software");
  const { run, busy } = useAction();
  const schedule = form.schedule || {};
  const setSchedule = (patch: any) => setForm({ ...form, schedule: { ...schedule, ...patch } });
  const save = async () => {
    const body = { name: form.name, schedule: form.schedule, targets: form.targets, actions: form.actions, enabled: form.enabled };
    if (await run(() => (form.id ? api(`rmm/tasks/${form.id}`, { method: "PATCH", body }) : api("rmm/tasks", { body })), "Schedule saved")) onClose();
  };
  const setAction = (i: number, patch: any) => setForm({ ...form, actions: form.actions.map((a: any, j: number) => (i === j ? { ...a, ...patch } : a)) });
  return (
    <Modal title={form.id ? form.name : "New scheduled task"} onClose={onClose}
           footer={<>{form.id && <button className="danger" disabled={busy} onClick={async () => { if (confirm("Delete this schedule and stop its outstanding jobs?")) { if (await run(() => api(`rmm/tasks/${form.id}`, { method: "DELETE" }), "Schedule deleted; outstanding work cancelled or stopping")) onClose(); } }}>Delete</button>}
                   <button className="primary" disabled={busy || !form.name || !form.actions.length} onClick={save}>Save</button></>}>
      <div className="form-grid">
        <label className="field">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
        <label className="field">Repeat<select value={schedule.type} onChange={(e) => setSchedule({ type: e.target.value })}>
          {["daily", "weekly", "monthly", "interval", "once"].map((t) => <option key={t}>{t}</option>)}</select></label>
        {schedule.type === "interval" ? <label className="field">Every (minutes)<input type="number" min={5} value={schedule.everyMinutes || 60} onChange={(e) => setSchedule({ everyMinutes: Number(e.target.value) })} /></label>
          : <label className="field">At<input type="time" value={schedule.at || "02:00"} onChange={(e) => setSchedule({ at: e.target.value })} /></label>}
        {schedule.type === "monthly" && <label className="field">Day of month<input type="number" min={1} max={28} value={schedule.dayOfMonth || 1} onChange={(e) => setSchedule({ dayOfMonth: Number(e.target.value) })} /></label>}
        {schedule.type === "once" && <label className="field">Date<input type="date" value={schedule.date || ""} onChange={(e) => setSchedule({ date: e.target.value })} /></label>}
        <label className="field">Time zone<input value={schedule.tz || "UTC"} onChange={(e) => setSchedule({ tz: e.target.value })} /></label>
        <label className="field">Enabled<select value={form.enabled ? "yes" : "no"} onChange={(e) => setForm({ ...form, enabled: e.target.value === "yes" })}><option value="yes">Yes</option><option value="no">Paused</option></select></label>
      </div>
      {schedule.type === "weekly" && <div className="row" style={{ marginTop: 8 }}>
        {DAYS.map((d, i) => <label key={d} className="small"><input type="checkbox" checked={(schedule.days || []).includes(i)}
          onChange={() => setSchedule({ days: (schedule.days || []).includes(i) ? schedule.days.filter((x: number) => x !== i) : [...(schedule.days || []), i] })} /> {d}</label>)}
      </div>}
      <h3 style={{ marginTop: 14 }}>Actions</h3>
      {form.actions.map((a: any, i: number) => (
        <div key={i} className="row" style={{ marginBottom: 6 }}>
          <select value={a.type} onChange={(e) => setAction(i, { type: e.target.value })}><option value="script">Run script</option><option value="command">Run action</option><option value="software">Install software</option></select>
          {a.type === "script" && <select value={a.scriptId || ""} onChange={(e) => setAction(i, { scriptId: e.target.value })} style={{ flex: 1 }}>
            <option value="">Choose a script</option>{scripts?.map((s) => <option key={s.id} value={s.id}>{displayValue(s.name)} ({displayValue(s.language)})</option>)}</select>}
          {a.type === "command" && <select value={a.command || ""} onChange={(e) => setAction(i, { command: e.target.value })} style={{ flex: 1 }}>
            <option value="">Choose an action</option>
            {["patch.scan", "patch.install", "scan.quick", "scan.full", "inventory.refresh", "device.reboot", "policy.refresh"].map((c) => <option key={c}>{c}</option>)}</select>}
          {a.type === "software" && <select value={a.packageId || ""} onChange={(e) => setAction(i, { packageId: e.target.value })} style={{ flex: 1 }}>
            <option value="">Choose a package</option>{packages?.map((p) => <option key={p.id} value={p.id}>{displayValue(p.name)} ({displayValue(p.platform)})</option>)}</select>}
          <button className="small ghost" onClick={() => setForm({ ...form, actions: form.actions.filter((_: any, j: number) => j !== i) })}>✕</button>
        </div>
      ))}
      <button className="small" onClick={() => setForm({ ...form, actions: [...form.actions, { type: "script" }] })}>Add action</button>
      <h3 style={{ marginTop: 14 }}>Targets</h3>
      <TargetPicker value={form.targets} onChange={(targets: Targets) => setForm({ ...form, targets })} />
    </Modal>
  );
}
