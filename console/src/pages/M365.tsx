import { M365Administration } from "./M365Administration";
import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { RecordEditor } from "../components/RecordEditor";
import { safeArray } from "../data-shapes";
import { ErrorNote, Modal, PageHead, Pill, Table, useAction, useListData } from "../components/ui";
function Insights({data}:{data:any}) {
  const mfa=data.mfa, score=data.secureScore;
  return <div className="card" style={{marginBottom:12}}>
    <div className="grid k4">
      <div><div className="small muted">Users</div><b>{data.enabledUsers}</b><div className="small muted">enabled of {data.users}</div></div>
      <div><div className="small muted">Unused licences</div><b style={{color:data.licencesUnused?"#fcd34d":undefined}}>{data.licencesUnused}</b><div className="small muted">{data.licencesAssigned} of {data.licencesPurchased} assigned</div></div>
      <div><div className="small muted">MFA registered</div><b style={{color:mfa&&mfa.percent<100?"#fca5a5":undefined}}>{mfa?`${mfa.percent ?? "—"}%`:"—"}</b><div className="small muted">{mfa?`${mfa.notRegistered} without MFA`:"needs AuditLog.Read.All"}</div></div>
      <div><div className="small muted">Secure Score</div><b>{score?`${score.percent}%`:"—"}</b><div className="small muted">{score?`${score.current} of ${score.max}`:"not available"}</div></div>
    </div>
    {mfa?.adminsWithoutMfa?.length>0&&<p style={{color:"#fca5a5",marginTop:10}}><b>Admins without MFA:</b> {mfa.adminsWithoutMfa.join(", ")}</p>}
    {data.disabledButLicensed?.length>0&&<p className="small" style={{marginTop:6}}><b>Disabled accounts still holding licences ({data.disabledButLicensed.length}):</b> {data.disabledButLicensed.join(", ")}</p>}
  </div>;
}

export default function M365() {
  const { tenantId, can } = useApp();
  const { data, error, reload } = useListData<any>(can("configure") ? "m365/connections" : null, {tenant_id:tenantId});
  const [create, setCreate] = useState(false);
  const [selected, setSelected] = useState<any>(null);
  const [secret, setSecret] = useState(false);
  const { run, busy } = useAction();
  useEffect(()=>{setCreate(false);setSelected(null);setSecret(false);},[tenantId]);
  if (!can("configure")) return <PageHead title="Microsoft 365" subtitle="Configuration access is required." />;
  return <>
    <PageHead title="Microsoft 365" subtitle="Customer directory administration, licences and security snapshots."
      actions={<button className="primary" onClick={() => setCreate(true)}>Connect directory</button>} />
    <ErrorNote error={error} />
    <div className="card"><p>Register an application in the customer's directory and grant application permissions: User.Read.All, LicenseAssignment.Read.All and SecurityEvents.Read.All, with admin consent. Snapshot sync is read-only. Select a connection below for live administration and access checks. New-user creation additionally requires User.ReadWrite.All and Domain.Read.All with admin consent; other actions list their required permissions before execution.</p></div>
    <div className="card"><p>Register an application in the customer's directory and grant application permissions: User.Read.All, LicenseAssignment.Read.All and SecurityEvents.Read.All, with admin consent. Add AuditLog.Read.All to see MFA registration (needs Entra ID P1/P2). Sync is read-only and runs on demand.</p></div>
    <Table rows={data} onRow={setSelected} columns={[{key:"name",label:"Connection"},{key:"directoryId",label:"Directory"},{key:"status",label:"Status",render:r=><Pill value={r.status}/>},{key:"syncedAt",label:"Last successful sync",render:r=>fmtTime(r.syncedAt)}]} />
    {create && <RecordEditor title="Connect Microsoft 365" fields={[{key:"name",label:"Name",required:true},{key:"directoryId",label:"Directory (tenant) UUID",required:true},{key:"clientId",label:"Application (client) UUID",required:true},{key:"clientSecret",label:"Client secret",type:"password",required:true}]}
      onSave={body=>api("m365/connections",{body})} onClose={()=>{setCreate(false);reload();}} />}
    {selected && <Modal title={selected.name} onClose={()=>setSelected(null)} footer={<><button onClick={()=>setSecret(true)}>Replace application secret</button><button className="primary" disabled={busy} onClick={async()=>{const row=await run(()=>api("m365/connections/"+selected.id+"/sync",{method:"POST"}),"Directory synchronised");if(row)setSelected(row);reload();}}>Sync now</button></>}>
      <ErrorNote error={selected.lastError || null}/>
      {selected.snapshot?.insights&&<Insights data={selected.snapshot.insights}/>}
      <M365Administration key={selected.id} connection={selected}/>
      <h3>Cached users from last snapshot</h3><Table rows={safeArray<any>(selected.snapshot?.users)} columns={[{key:"displayName",label:"Name"},{key:"userPrincipalName",label:"Sign-in"},{key:"accountEnabled",label:"Enabled"}]}/>
      <h3>Licences</h3><Table rows={safeArray<any>(selected.snapshot?.licenses)} columns={[{key:"skuPartNumber",label:"Product"},{key:"consumedUnits",label:"Assigned"},{key:"available",label:"Available",render:r=>Math.max(0,(r.prepaidUnits?.enabled||0)-(r.consumedUnits||0))}]}/>
      <h3>Secure Score</h3><Table rows={safeArray<any>(selected.snapshot?.secureScores)} columns={[{key:"currentScore",label:"Current score"},{key:"maxScore",label:"Maximum"},{key:"createdDateTime",label:"Measured"}]}/>
    </Modal>}
    {secret && selected && <RecordEditor title="Replace application secret" tenant={false} fields={[{key:"clientSecret",label:"New client secret",type:"password",required:true}]}
      onSave={({clientSecret})=>api("m365/connections/"+selected.id+"/secret",{method:"PUT",body:{clientSecret}})} onClose={()=>setSecret(false)}/>}
  </>;
}
