import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { RecordEditor } from "../components/RecordEditor";
import { safeArray } from "../data-shapes";
import { ErrorNote, Modal, PageHead, Pill, Table, useAction, useListData } from "../components/ui";
export default function Network() {
  const { tenantId, can }=useApp();
  const {data,error,reload}=useListData<any>("network/monitors",{tenant_id:tenantId});
  const [create,setCreate]=useState(false),[selected,setSelected]=useState<any>(null);
  const {run,busy}=useAction();
  useEffect(()=>{setCreate(false);setSelected(null);},[tenantId]);
  const action=async(path:string,body?:unknown)=>{const row=await run(()=>api("network/monitors/"+selected.id+path,{method:body?"PATCH":"POST",body}),"Monitor updated");if(row)setSelected(row);reload();};
  return <>
    <PageHead title="Network monitoring" subtitle="Scheduled TCP service checks from the Fenrir server. Three consecutive failures raise an alert; recovery resolves it."
      actions={can("configure")&&<button className="primary" onClick={()=>setCreate(true)}>Add service monitor</button>}/>
    <ErrorNote error={error}/>
    <Table rows={data} onRow={setSelected} columns={[{key:"name",label:"Service"},{key:"address",label:"IP address"},{key:"port",label:"Port"},{key:"state",label:"State",render:r=><Pill value={r.enabled?r.state:"paused"} tone={r.state==="up"?"good":r.state==="down"?"bad":"muted"}/>},{key:"checkedAt",label:"Last check",render:r=>fmtTime(r.checkedAt)}]}/>
    {create&&<RecordEditor title="Add TCP monitor" fields={[{key:"name",label:"Service name",required:true},{key:"address",label:"Reachable service IP address",required:true},{key:"port",label:"TCP port",type:"number",value:443,required:true},{key:"intervalSeconds",label:"Interval in seconds (60–86400)",type:"number",value:300,required:true},{key:"configurationId",label:"Linked configuration (optional)",type:"select",source:"configurations"}]}
      onSave={body=>api("network/monitors",{body:{...body,configurationId:body.configurationId||null}})} onClose={()=>{setCreate(false);reload();}}/>}
    {selected&&<Modal title={selected.name} onClose={()=>setSelected(null)} footer={can("configure")&&<><button disabled={busy} onClick={()=>action("",{enabled:!selected.enabled})}>{selected.enabled?"Pause":"Resume"}</button><button disabled={busy} onClick={()=>action("/check")}>Check now</button></>}>
      <Table rows={[...safeArray<any>(selected.samples)].reverse()} columns={[{key:"at",label:"Time",render:r=>fmtTime(r.at)},{key:"up",label:"Available"},{key:"latencyMs",label:"Connection time (ms)"}]}/>
    </Modal>}
  </>;
}
