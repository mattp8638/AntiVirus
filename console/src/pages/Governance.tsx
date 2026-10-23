import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { RecordEditor } from "../components/RecordEditor";
import { ErrorNote, Modal, PageHead, Pill, Table, useAction, useData } from "../components/ui";
export default function Governance() {
  const {tenantId,can}=useApp();
  const {data,error,reload}=useData<any[]>("grc/records",{tenant_id:tenantId});
  const {data:frameworks}=useData<{frameworks:string[]}>("grc/frameworks");
  const [create,setCreate]=useState(false),[selected,setSelected]=useState<any>(null),[status,setStatus]=useState("in_review"),[due,setDue]=useState("");
  const {run,busy}=useAction();
  useEffect(()=>{setCreate(false);setSelected(null);},[tenantId]);
  return <>
    <PageHead title="GRC & ISMS" subtitle="Risk register, policy and evidence tracking, audit preparation and time-limited exceptions."
      actions={can("grc")&&<button className="primary" onClick={()=>setCreate(true)}>New record</button>}/>
    <ErrorNote error={error}/>
    <Table rows={data} onRow={r=>{setSelected(r);setStatus(r.status);setDue(r.reviewDue||"");}} columns={[{key:"title",label:"Record"},{key:"kind",label:"Type"},{key:"framework",label:"Framework"},{key:"owner",label:"Owner"},{key:"riskScore",label:"Risk (1–25)",render:r=>r.kind==="risk"?r.riskScore:"—"},{key:"status",label:"Review",render:r=><Pill value={r.reviewOverdue?"overdue":r.status} tone={r.reviewOverdue?"bad":undefined}/>} ]}/>
    {create&&<RecordEditor title="New governance record" fields={[{key:"kind",label:"Record type",type:"select",options:["risk","policy","evidence","audit","exception"],required:true,value:"risk"},{key:"title",label:"Title",required:true},{key:"description",label:"Description / treatment / evidence notes",type:"textarea"},{key:"framework",label:"Framework reference",type:"select",options:frameworks?.frameworks||[]},{key:"control",label:"Control reference"},{key:"owner",label:"Owner"},{key:"likelihood",label:"Likelihood (1–5)",type:"number",value:1},{key:"impact",label:"Impact (1–5)",type:"number",value:1},{key:"reviewDue",label:"Review due (ISO date/time, optional)"},{key:"documentId",label:"Knowledge-base document (optional)",type:"select",source:"documents"},{key:"evidenceUrl",label:"HTTPS evidence link (optional)"}]}
      onSave={body=>api("grc/records",{body:{...body,reviewDue:body.reviewDue||null,documentId:body.documentId||null}})} onClose={()=>{setCreate(false);reload();}}/>}
    {selected&&<Modal title={selected.title} onClose={()=>setSelected(null)} footer={can("grc")&&<button className="primary" disabled={busy} onClick={async()=>{const row=await run(()=>api("grc/records/"+selected.id+"/review",{method:"PATCH",body:{status,reviewDue:due||null}}),"Review saved");if(row)setSelected(row);reload();}}>Save review</button>}>
      <p style={{whiteSpace:"pre-wrap"}}>{selected.description}</p><p>Framework: {selected.framework||"Unmapped"} · Control: {selected.control||"Unmapped"}</p><p>Review due: {fmtTime(selected.reviewDue)} · Approved by: {selected.approvedBy||"Pending"}</p>
      {selected.evidenceUrl&&<a href={selected.evidenceUrl} target="_blank" rel="noreferrer">Open evidence</a>}
      {can("grc")&&<><label className="field">Status<select value={status} onChange={e=>setStatus(e.target.value)}>{["draft","in_review","approved","accepted","closed"].map(x=><option key={x}>{x}</option>)}</select></label><label className="field">Next review (ISO date/time)<input value={due} onChange={e=>setDue(e.target.value)}/></label></>}
    </Modal>}
  </>;
}
