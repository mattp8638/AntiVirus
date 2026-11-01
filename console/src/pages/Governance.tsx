import { displayValue } from "../components/DisplayValue";
import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { RecordEditor } from "../components/RecordEditor";
import { safeArray } from "../data-shapes";
import { ErrorNote, Modal, PageHead, Pill, Table, Tabs, useAction, useData, useListData } from "../components/ui";
import { useSearchParams } from "react-router-dom";
import { EvidenceTab, ProgrammesTab } from "./grc/Programmes";
import { PoliciesTab } from "./grc/Policies";
import { COMPLIANCE_SECTION, SectionTabs } from "../components/sections";

const CONTROL_TONE:Record<string,string>={met:"good",evidenced:"good",exception:"warn",gap:"bad"};

function Controls({tenantId,onAddEvidence}:{tenantId:string;onAddEvidence:(framework:string,control:string)=>void}) {
  const {can}=useApp();
  const {data,error}=useData<any>(tenantId?"grc/controls":null,{tenant_id:tenantId},[tenantId]);
  const [open,setOpen]=useState<string>("cyber-essentials");
  if(!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its statement of applicability.</p>;
  const frameworks=safeArray<any>(data?.frameworks);
  const current=frameworks.find(f=>f.framework===open)??frameworks[0];
  return <>
    <ErrorNote error={error}/>
    <p className="small muted">Technical controls are checked automatically from protection policy and fleet state (settings no agent enforces yet never count). Other controls are met by approved policy, evidence or audit records, or covered by an accepted exception.</p>
    <div className="row" style={{gap:6,flexWrap:"wrap",margin:"8px 0"}}>
      {frameworks.map(f=><button key={f.framework} className={`small ${f.framework===current?.framework?"primary":""}`} onClick={()=>setOpen(f.framework)}>{displayValue(f.label)} · {displayValue(f.coverage)}%</button>)}
    </div>
    {current&&<div className="card">
      <div className="small muted" style={{marginBottom:8}}>{displayValue(current.name)}: {displayValue(current.counts.met)} met automatically · {displayValue(current.counts.evidenced)} evidenced · {displayValue(current.counts.exception)} exceptions · {displayValue(current.counts.gap)} gaps</div>
      <Table rows={current.controls} columns={[
        {key:"id",label:"Control",render:c=><><b>{displayValue(c.id)}</b> {displayValue(c.title)}</>},
        {key:"status",label:"Status",render:c=><Pill value={c.status} tone={CONTROL_TONE[c.status]}/>},
        {key:"evidence",label:"Automatic check",render:c=><span className="small">{safeArray<string>(c.evidence).join(" · ")}</span>},
        {key:"records",label:"Register records",render:c=><>{safeArray<any>(c.records).map(r=><div key={r.id} className="small">{displayValue(r.title)} <Pill value={r.status}/></div>)}
          {can("grc")&&c.status==="gap"&&<button className="small" onClick={()=>onAddEvidence(current.label,`${c.id} ${c.title}`)}>Add evidence</button>}</>}]}/>
    </div>}
  </>;
}
export default function Governance() {
  const {tenantId,can}=useApp();
  const {data,error,reload}=useListData<any>("grc/records",{tenant_id:tenantId});
  const {data:frameworks}=useData<{frameworks:string[]}>("grc/frameworks");
  const [create,setCreate]=useState<false|{framework?:string;control?:string}>(false),[selected,setSelected]=useState<any>(null),[status,setStatus]=useState("in_review"),[due,setDue]=useState("");
  const [params,setParams]=useSearchParams();
  const tab=params.get("tab")||"Programmes";
  const setTab=(next:string)=>setParams(next==="Programmes"?{}:{tab:next},{replace:true});
  const {run,busy}=useAction();
  useEffect(()=>{setCreate(false);setSelected(null);},[tenantId]);
  return <>
    <SectionTabs items={COMPLIANCE_SECTION} />
    <PageHead title="GRC & compliance" subtitle="UK and UK-targeted governance programmes with requirements, answers, policies, evidence and a risk register."
      actions={can("grc")&&tab==="Risk register"&&<button className="primary" onClick={()=>setCreate({})}>New record</button>}/>
    <ErrorNote error={error}/>
    <Tabs tabs={["Programmes","Policies","Evidence","Risk register","Controls"]} active={tab} onChange={setTab}/>
    {tab==="Programmes"&&<ProgrammesTab/>}
    {tab==="Policies"&&<PoliciesTab/>}
    {tab==="Evidence"&&<EvidenceTab/>}
    {tab==="Controls"&&<Controls tenantId={tenantId} onAddEvidence={(framework,control)=>setCreate({framework,control})}/>}
    {tab==="Risk register"&&<Table rows={data} onRow={r=>{setSelected(r);setStatus(r.status);setDue(r.reviewDue||"");}} columns={[{key:"title",label:"Record"},{key:"kind",label:"Type"},{key:"framework",label:"Framework"},{key:"owner",label:"Owner"},{key:"riskScore",label:"Risk (1–25)",render:r=>r.kind==="risk"?r.riskScore:"—"},{key:"status",label:"Review",render:r=><Pill value={r.reviewOverdue?"overdue":r.status} tone={r.reviewOverdue?"bad":undefined}/>} ]}/>}
    {create&&<RecordEditor title="New governance record" fields={[{key:"kind",label:"Record type",type:"select",options:["risk","policy","evidence","audit","exception"],required:true,value:create.control?"evidence":"risk"},{key:"title",label:"Title",required:true},{key:"description",label:"Description / treatment / evidence notes",type:"textarea"},{key:"framework",label:"Framework reference",type:"select",options:safeArray<string>(frameworks?.frameworks),value:create.framework},{key:"control",label:"Control reference (start with the control ID, e.g. CE-3)",value:create.control},{key:"owner",label:"Owner"},{key:"likelihood",label:"Likelihood (1–5)",type:"number",value:1},{key:"impact",label:"Impact (1–5)",type:"number",value:1},{key:"reviewDue",label:"Review due (ISO date/time, optional)"},{key:"documentId",label:"Knowledge-base document (optional)",type:"select",source:"documents"},{key:"evidenceUrl",label:"HTTPS evidence link (optional)"}]}
      onSave={body=>api("grc/records",{body:{...body,reviewDue:body.reviewDue||null,documentId:body.documentId||null}})} onClose={()=>{setCreate(false);reload();}}/>}
    {selected&&<Modal title={selected.title} onClose={()=>setSelected(null)} footer={can("grc")&&<button className="primary" disabled={busy} onClick={async()=>{const row=await run(()=>api("grc/records/"+selected.id+"/review",{method:"PATCH",body:{status,reviewDue:due||null}}),"Review saved");if(row)setSelected(row);reload();}}>Save review</button>}>
      <p style={{whiteSpace:"pre-wrap"}}>{displayValue(selected.description)}</p><p>Framework: {displayValue(selected.framework||"Unmapped")} · Control: {displayValue(selected.control||"Unmapped")}</p><p>Review due: {fmtTime(selected.reviewDue)} · Approved by: {displayValue(selected.approvedBy||"Pending")}</p>
      {selected.evidenceUrl&&<a href={selected.evidenceUrl} target="_blank" rel="noreferrer">Open evidence</a>}
      {can("grc")&&<><label className="field">Status<select value={status} onChange={e=>setStatus(e.target.value)}>{["draft","in_review","approved","accepted","closed"].map(x=><option key={x}>{x}</option>)}</select></label><label className="field">Next review (ISO date/time)<input value={due} onChange={e=>setDue(e.target.value)}/></label></>}
    </Modal>}
  </>;
}
