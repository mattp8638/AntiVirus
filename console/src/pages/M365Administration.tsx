import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { safeArray } from "../data-shapes";
import { ErrorNote, Modal, Pill, Table, Tabs, useAction, useListData } from "../components/ui";

export function M365Administration({connection}:{connection:any}) {
  const {can}=useApp();
  const base="m365/connections/"+connection.id;
  const [tab,setTab]=useState("Users"),[query,setQuery]=useState(""),[selected,setSelected]=useState<any>(null);
  const [operation,setOperation]=useState("user.update"),[value,setValue]=useState(""),[job,setJob]=useState<any>(null);
  const [confirmed,setConfirmed]=useState(false),[diagnostics,setDiagnostics]=useState<any>(null);
  const [requestId,setRequestId]=useState(()=>crypto.randomUUID());
  const {run,busy}=useAction();
  const {data:users,error:userError,reload:reloadUsers}=useListData<any>(base+"/inventory/users");
  const {data:groups,error:groupError}=useListData<any>(tab==="Groups"||operation.startsWith("group.")?base+"/inventory/groups":null);
  const {data:licenses,error:licenseError}=useListData<any>(tab==="Licences"||operation.startsWith("license.")?base+"/inventory/licenses":null);
  const {data:history,error:historyError,reload:reloadHistory}=useListData<any>(can("m365_admin")?base+"/actions":null);
  useEffect(()=>{setSelected(null);setJob(null);setDiagnostics(null);setConfirmed(false);},[connection.id]);
  const choose=(row:any)=>{setSelected(row);setOperation("user.update");setValue(row.displayName||"");setJob(null);setConfirmed(false);setRequestId(crypto.randomUUID());};
  const prepare=async()=>{
    const parameters=operation==="user.revoke_sessions"?{}:operation==="user.update"?{displayName:value}:operation==="user.signin"?{accountEnabled:value==="true"}:
      operation.startsWith("license.")?{skuId:value}:{groupId:value};
    const result=await run(()=>api(base+"/actions",{body:{requestId,operation,targetId:selected.id,parameters}}),"Action prepared");
    if(result){setJob(result);reloadHistory();}
  };
  const execute=async()=>{
    const result=await run(()=>api(base+"/actions/"+job.id+"/execute",{body:{confirmed:true}}),"Action status updated");
    if(result){setJob(result);setConfirmed(false);reloadUsers();reloadHistory();}
  };
  return <section>
    <h2>Tenant administration · {connection.name}</h2>
    <p>Live directory views. Administrative changes require a reviewed action and fresh authentication.</p>
    <Tabs tabs={["Users","Groups","Licences","Actions","Access checks"]} active={tab} onChange={setTab}/>
    <ErrorNote error={userError||groupError||licenseError||historyError}/>
    {["Users","Groups","Licences"].includes(tab)&&<label className="field">Search<input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Name, sign-in or product"/></label>}
    {tab==="Users"&&<Table rows={users?.filter(r=>(r.displayName+" "+r.userPrincipalName).toLowerCase().includes(query.toLowerCase()))} onRow={can("m365_admin")?choose:undefined}
      columns={[{key:"displayName",label:"Name"},{key:"userPrincipalName",label:"Sign-in"},{key:"accountEnabled",label:"Sign-in enabled"},{key:"department",label:"Department"}]}/>}
    {tab==="Groups"&&<><p>Manage membership from a selected user. Dynamic, role-assignable, synced and Exchange-managed groups require separate workflows.</p>
      <Table rows={groups?.filter(r=>r.displayName?.toLowerCase().includes(query.toLowerCase()))} columns={[{key:"displayName",label:"Group"},{key:"groupTypes",label:"Type",render:r=>safeArray<string>(r.groupTypes).join(", ")||"Security"},{key:"isAssignableToRole",label:"Role assignable"},{key:"onPremisesSyncEnabled",label:"Synced"}]}/></>}
    {tab==="Licences"&&<Table rows={licenses?.filter(r=>r.skuPartNumber?.toLowerCase().includes(query.toLowerCase()))} columns={[{key:"skuPartNumber",label:"Product"},{key:"consumedUnits",label:"Assigned"},{key:"available",label:"Available",render:r=>Math.max(0,(r.prepaidUnits?.enabled||0)-(r.consumedUnits||0))}]}/>}
    {tab==="Actions"&&<><p>Refresh to check progress. Running or unknown outcomes must be reconciled against Microsoft before preparing another action; they are never replayed automatically.</p><button onClick={reloadHistory}>Refresh history</button>
      <Table rows={history} onRow={r=>{setJob(r);setSelected(null);setConfirmed(false);}} columns={[{key:"operation",label:"Operation"},{key:"target",label:"User",render:r=>r.preview?.user?.userPrincipalName||r.targetId},{key:"status",label:"Status",render:r=><Pill value={r.status}/>},{key:"executedBy",label:"Executed by"},{key:"createdAt",label:"Prepared",render:r=>fmtTime(r.createdAt)}]}/></>}
    {tab==="Access checks"&&<><p>These checks test read access. Write consent and target restrictions are validated by Microsoft when an operation runs.</p>
      <button disabled={busy} onClick={async()=>{const result=await run(()=>api(base+"/diagnostics",{method:"POST"}),"Checks completed");if(result)setDiagnostics(result);}}>Run access checks</button>
      {diagnostics&&<><Table rows={safeArray<any>(diagnostics.checks)} columns={[{key:"resource",label:"Resource"},{key:"status",label:"Read access"}]}/>
      <Table rows={Object.entries((diagnostics.operations && typeof diagnostics.operations === "object" && !Array.isArray(diagnostics.operations) ? diagnostics.operations : {}) as Record<string,string[]>).map(([operation,permissions])=>({operation,permissions}))} columns={[{key:"operation",label:"Operation"},{key:"permissions",label:"Application permissions",render:r=>safeArray<string>(r.permissions).join(", ")}]}/></>}</>}
    {selected&&!job&&<Modal title={selected.userPrincipalName} onClose={()=>setSelected(null)}>
      <label className="field">Action<select value={operation} onChange={e=>{setOperation(e.target.value);setValue("");setRequestId(crypto.randomUUID());}}>
        <option value="user.update">Change display name</option><option value="user.signin">Enable or block sign-in</option>
        <option value="user.revoke_sessions">Revoke sign-in sessions</option>
        <option value="license.add">Assign licence</option><option value="license.remove">Remove licence</option>
        <option value="group.add_member">Add to group</option><option value="group.remove_member">Remove from group</option>
      </select></label>
      {operation!=="user.revoke_sessions"&&<label className="field">{operation==="user.update"?"Display name":"New setting"}
        {operation==="user.update"?<input value={value} onChange={e=>{setValue(e.target.value);setRequestId(crypto.randomUUID());}}/>:
        <select value={value} onChange={e=>{setValue(e.target.value);setRequestId(crypto.randomUUID());}}><option value="">Choose…</option>
          {operation==="user.signin"?<><option value="true">Allow sign-in</option><option value="false">Block sign-in</option></>:
          operation.startsWith("license.")?licenses?.map(r=><option key={r.skuId} value={r.skuId}>{r.skuPartNumber}</option>):
          groups?.map(r=><option key={r.id} value={r.id}>{r.displayName}</option>)}
        </select>}
      </label>}
      {operation==="user.revoke_sessions"&&<p>Invalidate this user’s refresh tokens and browser sessions. This can take a few minutes and does not block future sign-ins. External users must be managed in their home tenant.</p>}
      <button className="primary" disabled={busy||(operation!=="user.revoke_sessions"&&!value)} onClick={prepare}>Review change</button>
    </Modal>}
    {job&&<Modal title="Review Microsoft action" onClose={()=>{setJob(null);setSelected(null);}}>
      <p><b>Customer connection:</b> {connection.name}</p><p><b>Directory:</b> {connection.directoryId}</p>
      <p><b>User:</b> {job.preview?.user?.userPrincipalName}</p><p><b>Action:</b> {job.operation} · <b>Status:</b> {job.status}</p>
      {job.preview?.group&&<p><b>Group:</b> {job.preview.group.displayName}</p>}
      {job.preview?.license&&<p><b>Licence:</b> {job.preview.license.name}</p>}
      <p><b>Change:</b> {job.operation==="user.revoke_sessions"?"Revoke this user’s sign-in sessions; future sign-ins remain allowed":job.operation==="user.update"?`Display name: ${job.preview?.user?.displayName} → ${job.parameters.displayName}`:job.operation==="user.signin"?`${job.preview?.user?.accountEnabled?"Sign-in allowed":"Sign-in blocked"} → ${job.parameters.accountEnabled?"Allow sign-in":"Block sign-in"}`:job.operation==="license.add"?"Assign the selected licence":job.operation==="license.remove"?"Remove the selected licence":job.operation==="group.add_member"?"Add this user to the selected group":"Remove this user from the selected group"}</p>
      <p>Required application permissions: {job.preview?.requiredPermissions?.join(", ")}</p>
      {job.result?.message&&<p>{job.result.message}</p>}
      {job.status==="prepared"&&can("m365_admin")&&<><p>This changes the selected tenant. Removing licences or blocking sign-in can interrupt service. The preview expires after ten minutes.</p>
        <label><input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/> I have reviewed this customer, user and change.</label>
        <p><button className="primary" disabled={busy||!confirmed} onClick={execute}>Confirm and execute</button></p></>}
      {job.status.startsWith("succeeded")&&<p>Microsoft accepted this action. The Users view has been refreshed.</p>}
      {["running","unknown"].includes(job.status)&&<p>Check current Microsoft state before submitting another action. This record cannot be executed again.</p>}
    </Modal>}
  </section>;
}
