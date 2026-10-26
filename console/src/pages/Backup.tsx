import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { RecordEditor } from "../components/RecordEditor";
import { ErrorNote, Modal, PageHead, Pill, Table, useListData } from "../components/ui";
export default function Backup() {
  const {tenantId,can}=useApp();
  const {data,error,reload}=useListData<any>("backup/plans",{tenant_id:tenantId});
  const {data:exercises,reload:reloadExercises}=useListData<any>("backup/exercises",{tenant_id:tenantId});
  const [mode,setMode]=useState(""),[selected,setSelected]=useState<any>(null),[exercise,setExercise]=useState<any>(null),[ingest,setIngest]=useState<any>(null);
  const {data:runs,reload:reloadRuns}=useListData<any>(selected?"backup/plans/"+selected.id+"/runs":null);
  useEffect(()=>{setMode("");setSelected(null);setExercise(null);},[tenantId]);
  const close=()=>{setMode("");reload();reloadRuns();reloadExercises();};
  return <>
    <PageHead title="Backup & disaster recovery" subtitle="Track provider results, recovery-point freshness and documented recovery exercises. Failed or overdue backups raise alerts. Backup and restore execution stays with your provider."
      actions={can("configure")&&<button className="primary" onClick={()=>setMode("plan")}>Add protection plan</button>}/>
    <ErrorNote error={error}/>
    <Table rows={data} onRow={setSelected} columns={[{key:"name",label:"Protected service"},{key:"provider",label:"Provider"},{key:"health",label:"Health",render:r=><Pill value={r.health} tone={r.health==="protected"?"good":r.health==="unknown"?"muted":"bad"}/>},{key:"lastSuccessAt",label:"Last success",render:r=>fmtTime(r.lastSuccessAt)},{key:"rpoHours",label:"RPO (hours)"},{key:"rtoMinutes",label:"RTO (minutes)"}]}/>
    <h2>Recovery exercises</h2><Table rows={exercises} onRow={r=>{setExercise(r);setMode("review");}} columns={[{key:"target",label:"Isolated recovery target"},{key:"status",label:"Status",render:r=><Pill value={r.status}/>},{key:"requestedBy",label:"Requested by"},{key:"durationMinutes",label:"Actual minutes"},{key:"completedAt",label:"Completed",render:r=>fmtTime(r.completedAt)}]}/>
    {selected&&<Modal title={selected.name} onClose={()=>{setSelected(null);setIngest(null);}} footer={can("configure")&&<><button onClick={async()=>{
        if(selected.ingestConfigured&&!window.confirm("Issue a new token? The backup tool's current token stops working."))return;
        try{setIngest(await api("backup/plans/"+selected.id+"/ingest-token",{method:"POST"}));reload();}catch(e){alert((e as Error).message);}
      }}>{selected.ingestConfigured?"Rotate tool token":"Connect backup tool"}</button><button onClick={()=>setMode("run")}>Record provider result</button><button onClick={()=>setMode("exercise")}>Request recovery exercise</button></>}>
      {ingest&&<div className="card" style={{marginBottom:12}}>
        <b>Push job results from your backup tool</b>
        <p className="small muted">Copy this token now; it is not shown again. Add a post-job script (or the provider's webhook) that sends each result:</p>
        <pre className="mono small" style={{whiteSpace:"pre-wrap",userSelect:"all"}}>{`curl -X POST ${window.location.origin}${ingest.url} \\
  -H "${ingest.header}: ${ingest.token}" -H "Content-Type: application/json" \\
  -d '{"externalId":"<job id>","status":"success","completedAt":"<ISO time>","evidence":"<summary>"}'`}</pre>
      </div>}
      {!ingest&&<p className="small muted">{selected.ingestConfigured?"A backup tool is connected and pushes results automatically.":"Results are recorded by hand until you connect the backup tool."}</p>}
      <Table rows={runs} columns={[{key:"externalId",label:"Provider job ID"},{key:"status",label:"Result"},{key:"completedAt",label:"Completed",render:r=>fmtTime(r.completedAt)},{key:"evidence",label:"Evidence"}]}/>
    </Modal>}
    {mode==="plan"&&<RecordEditor title="Protection plan" fields={[{key:"name",label:"Service name",required:true},{key:"provider",label:"Backup provider",required:true},{key:"rpoHours",label:"RPO hours",type:"number",value:24},{key:"rtoMinutes",label:"RTO minutes",type:"number",value:240},{key:"configurationId",label:"Configuration (optional)",type:"select",source:"configurations"},{key:"runbookId",label:"Recovery runbook (optional)",type:"select",source:"documents"}]}
      onSave={body=>api("backup/plans",{body:{...body,configurationId:body.configurationId||null,runbookId:body.runbookId||null}})} onClose={close}/>}
    {mode==="run"&&selected&&<RecordEditor title="Record provider result" tenant={false} fields={[{key:"externalId",label:"Unique provider job ID",required:true},{key:"status",label:"Result",type:"select",options:["success","failed"],value:"success",required:true},{key:"completedAt",label:"Actual completion time (ISO date/time)",value:new Date().toISOString(),required:true},{key:"bytesProtected",label:"Bytes protected",type:"number",value:0},{key:"evidence",label:"Provider evidence or report reference",type:"textarea"}]}
      onSave={({tenantId:_,...body})=>api("backup/plans/"+selected.id+"/runs",{body})} onClose={close}/>}
    {mode==="exercise"&&selected&&<RecordEditor title="Request recovery exercise" tenant={false} fields={[{key:"target",label:"Isolated test target and scope",required:true}]}
      onSave={({target})=>api("backup/plans/"+selected.id+"/exercises",{body:{target}})} onClose={close}/>}
    {mode==="review"&&exercise&&<Modal title="Recovery exercise" onClose={close}><p>{exercise.target}</p><p>Status: {exercise.status}</p><pre style={{whiteSpace:"pre-wrap"}}>{exercise.evidence}</pre>
      {can("configure")&&["requested","approved"].includes(exercise.status)&&<button onClick={()=>setMode("transition")}>Record next step</button>}</Modal>}
    {mode==="transition"&&exercise&&<RecordEditor title="Update recovery exercise" tenant={false} fields={[{key:"status",label:"Next step",type:"select",options:exercise.status==="requested"?["approved","cancelled"]:["completed","failed","cancelled"],required:true},{key:"evidence",label:"Validation evidence (required when finished)",type:"textarea"},{key:"durationMinutes",label:"Actual duration in minutes",type:"number",value:0}]}
      onSave={({tenantId:_,...body})=>api("backup/exercises/"+exercise.id,{method:"PATCH",body})} onClose={close}/>}
  </>;
}
