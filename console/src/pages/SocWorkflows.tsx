import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { RecordEditor } from "../components/RecordEditor";
import { ErrorNote, PageHead, Table, useAction, useData } from "../components/ui";

export default function SocWorkflows() {
  const {tenantId,can}=useApp();
  const {data,error,reload}=useData<any[]>("soc/suppressions",{tenant_id:tenantId});
  const [create,setCreate]=useState(false);
  const {run,busy}=useAction();
  useEffect(()=>{setCreate(false);},[tenantId]);
  return <>
    <PageHead title="SOC maintenance windows" subtitle="Temporarily suppress a detection rule for one customer. Events remain available for hunting and suppression expires automatically."
      actions={can("configure")&&<button className="primary" onClick={()=>setCreate(true)}>Add suppression</button>}/>
    <ErrorNote error={error}/>
    <Table rows={data} columns={[{key:"ruleId",label:"Rule"},{key:"reason",label:"Reason"},{key:"expiresAt",label:"Expires",render:r=>fmtTime(r.expiresAt)},{key:"createdBy",label:"Created by"},{key:"revoke",label:"",render:r=>can("configure")&&<button disabled={busy} onClick={async()=>{if(await run(()=>api("soc/suppressions/"+r.id,{method:"DELETE"}),"Suppression revoked"))reload();}}>Revoke</button>}]}/>
    {create&&<RecordEditor title="Suppress a rule temporarily" fields={[{key:"ruleId",label:"Detection rule",type:"select",source:"rules",required:true},{key:"reason",label:"Reason and change reference",required:true},{key:"expiresAt",label:"Expiry (ISO date/time, within 30 days)",required:true}]}
      onSave={body=>api("soc/suppressions",{body})} onClose={()=>{setCreate(false);reload();}}/>}
  </>;
}

export function IncidentEvidence({incidentId}:{incidentId:string}) {
  const {can}=useApp();
  const {data,error,reload}=useData<any[]>("soc/incidents/"+incidentId+"/evidence");
  const [create,setCreate]=useState(false);
  return <section className="card"><h2>Evidence</h2><p>Text evidence is immutable after submission and recorded with its SHA-256 fingerprint.</p>
    <ErrorNote error={error}/>{can("respond")&&<button onClick={()=>setCreate(true)}>Attach text evidence</button>}
    <Table rows={data} columns={[{key:"name",label:"Evidence",render:r=><details><summary>{r.name}</summary><pre style={{whiteSpace:"pre-wrap"}}>{r.content}</pre></details>},{key:"sha256",label:"SHA-256",render:r=><span className="mono" style={{overflowWrap:"anywhere"}}>{r.sha256}</span>},{key:"author",label:"Added by"},{key:"createdAt",label:"Added",render:r=>fmtTime(r.createdAt)}]}/>
    {create&&<RecordEditor title="Attach evidence" tenant={false} fields={[{key:"name",label:"Name",required:true},{key:"content",label:"Evidence text (up to 100,000 characters)",type:"textarea",required:true}]}
      onSave={({name,content})=>api("soc/incidents/"+incidentId+"/evidence",{body:{name,content}})} onClose={()=>{setCreate(false);reload();}}/>}
  </section>;
}
