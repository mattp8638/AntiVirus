import { displayValue } from "../components/DisplayValue";
import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { RecordEditor } from "../components/RecordEditor";
import { safeArray } from "../data-shapes";
import { ErrorNote, Modal, PageHead, Pill, Table, useAction, useListData } from "../components/ui";
import { NETWORK_SECTION, SectionTabs } from "../components/sections";
const STATE_LABEL:Record<string,string>={up:"up",down:"down",unknown:"waiting",probe_offline:"probe device not reporting",no_probe:"probe device missing"};
export default function Network() {
  const { tenantId, can }=useApp();
  const {data,error,reload}=useListData<any>("network/monitors",{tenant_id:tenantId});
  const [create,setCreate]=useState(false),[selected,setSelected]=useState<any>(null);
  const {run,busy}=useAction();
  useEffect(()=>{setCreate(false);setSelected(null);},[tenantId]);
  const {data:devices}=useListData<any>(selected?"devices":null,{tenant_id:selected?.tenantId});
  const hostname=(id:string|null)=>id?(safeArray<any>(devices).find(d=>d.id===id)?.hostname??"an enrolled device"):"the Fenrir server";
  const action=async(path:string,body?:unknown)=>{const row=await run(()=>api("network/monitors/"+selected.id+path,{method:body?"PATCH":"POST",body}),"Monitor updated");if(row)setSelected(row);reload();};
  return <>
    <SectionTabs items={NETWORK_SECTION} />
    <PageHead title="Network monitoring" subtitle="Scheduled TCP service checks, from the Fenrir server for internet-facing services or from an enrolled device for printers, switches and servers on a customer's LAN. Three consecutive failures raise an alert; recovery resolves it."
      actions={can("configure")&&<button className="primary" onClick={()=>setCreate(true)}>Add service monitor</button>}/>
    <ErrorNote error={error}/>
    <Table rows={data} onRow={setSelected} columns={[{key:"name",label:"Service"},{key:"address",label:"IP address"},{key:"port",label:"Port"},{key:"state",label:"State",render:r=><Pill value={r.enabled?STATE_LABEL[r.state]??r.state:"paused"} tone={r.state==="up"?"good":r.state==="down"?"bad":r.state==="probe_offline"||r.state==="no_probe"?"warn":"muted"}/>},{key:"probeDeviceId",label:"Checked from",render:r=>r.probeDeviceId?<span>{displayValue(safeArray<any>(r.samples).slice(-1)[0]?.from??"enrolled device")}</span>:<span className="muted">Fenrir server</span>},{key:"checkedAt",label:"Last check",render:r=>fmtTime(r.checkedAt)}]}/>
    {create&&<RecordEditor title="Add TCP monitor" fields={[{key:"name",label:"Service name",required:true},{key:"address",label:"Reachable service IP address",required:true},{key:"port",label:"TCP port",type:"number",value:443,required:true},{key:"intervalSeconds",label:"Interval in seconds (60–86400)",type:"number",value:300,required:true},{key:"configurationId",label:"Linked configuration (optional)",type:"select",source:"configurations"},{key:"probeDeviceId",label:"Probe from device (needed for private LAN addresses; blank = from the Fenrir server)",type:"select",source:"devices"}]}
      onSave={body=>api("network/monitors",{body:{...body,configurationId:body.configurationId||null,probeDeviceId:body.probeDeviceId||null}})} onClose={()=>{setCreate(false);reload();}}/>}
    {selected&&<Modal title={selected.name} onClose={()=>setSelected(null)} footer={can("configure")&&<><button disabled={busy} onClick={()=>action("",{enabled:!selected.enabled})}>{selected.enabled?"Pause":"Resume"}</button><button disabled={busy} onClick={()=>action("/check")}>Check now</button></>}>
      <p className="small muted">{displayValue(selected.address)}:{displayValue(selected.port)} · checked from {displayValue(hostname(selected.probeDeviceId))}{displayValue(selected.probeDeviceId&&" (results arrive when the device next checks in)")}</p>
      {can("configure")&&<label className="field" style={{marginBottom:10}}>Probe from
        <select value={selected.probeDeviceId||""} disabled={busy} onChange={e=>action("",{probeDeviceId:e.target.value||null})}>
          <option value="">The Fenrir server (internet-facing services)</option>
          {safeArray<any>(devices).map(d=><option key={d.id} value={d.id}>{displayValue(d.hostname)}</option>)}
        </select></label>}
      <Table rows={[...safeArray<any>(selected.samples)].reverse()} columns={[{key:"at",label:"Time",render:r=>fmtTime(r.at)},{key:"up",label:"Available"},{key:"latencyMs",label:"Connection time (ms)"}]}/>
    </Modal>}
  </>;
}
