import { useState } from 'react'
import './styles.css'

const API = 'http://localhost:8000'

const navItems = [
  { id: 'overview', label: 'Command Overview' },
  { id: 'pipeline', label: 'Threat Pipeline' },
  { id: 'endpoint', label: 'Endpoint Risk' },
  { id: 'investigator', label: 'Investigator' },
  { id: 'exposure', label: 'ExposureScout' },
  { id: 'cve', label: 'CVE Watchdog' },
  { id: 'phish', label: 'PhishGuard' },
  { id: 'emailintel', label: 'Email Intelligence' },
  { id: 'settings', label: 'Settings' },
]

const toArray = value => Array.isArray(value) ? value : []
const first = (obj, keys, fallback = 'Not available') => keys.map(k => obj?.[k]).find(v => v !== undefined && v !== null && v !== '') ?? fallback
const label = key => String(key || '').replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/\b\w/g, c => c.toUpperCase())
const valueText = value => value === null || value === undefined || value === '' ? 'Not provided' : Array.isArray(value) ? `${value.length} items` : typeof value === 'object' ? JSON.stringify(value) : String(value)
const toneFor = value => {
  const text = String(value || '').toLowerCase()
  if (['critical', 'high', 'block', 'blocked', 'malicious', 'failed', 'error', 'danger'].some(x => text.includes(x))) return 'red'
  if (['medium', 'monitor', 'warning', 'pending', 'suspicious', 'review'].some(x => text.includes(x))) return 'orange'
  if (['low', 'safe', 'success', 'trusted', 'verified', 'healthy', 'pass', 'created', 'connected', 'sent', 'active'].some(x => text.includes(x))) return 'green'
  return 'blue'
}

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, options)
  if (!response.ok) throw new Error(await response.text())
  return response.json()
}

function Badge({ children, tone = 'neutral' }) {
  return <span className={`badge ${tone}`}>{children}</span>
}

function Button({ children, onClick, disabled }) {
  return <button className="primary-btn" onClick={onClick} disabled={disabled}>{children}</button>
}

function StatCard({ title, value, subtitle, tone = 'blue' }) {
  return <section className={`stat-card ${tone}`}><p>{title}</p><h2>{value}</h2><span>{subtitle}</span></section>
}

function Panel({ title, subtitle, children }) {
  return <section className="panel"><div className="panel-header"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div></div>{children}</section>
}

function Verdict({ tone = 'blue', eyebrow = 'Result', title, message }) {
  return <section className={`verdict-card ${tone}`}><div><Badge tone={tone}>{eyebrow}</Badge><h2>{title}</h2><p>{message}</p></div></section>
}

function EmptyState({ children = 'Nothing to show yet.' }) {
  return <div className="empty-state">{children}</div>
}

function KeyValueCards({ data, keys }) {
  const entries = (keys || Object.keys(data || {})).filter(k => data?.[k] !== undefined)
  if (!entries.length) return <EmptyState>No readable details were returned.</EmptyState>
  return <div className="kv-grid">{entries.map(k => <article className="kv-card" key={k}><span>{label(k)}</span><strong>{valueText(data[k])}</strong></article>)}</div>
}

function ActionCards({ items, titleKeys = ['title', 'control', 'value', 'cve', 'issue', 'domain', 'email', 'name', 'hostname', 'id'], detailKeys = ['recommended_action', 'remediation', 'reason', 'message', 'description'], empty = 'No actions required.' }) {
  if (!items?.length) return <EmptyState>{empty}</EmptyState>
  return <div className="action-card-grid">{items.map((item, index) => {
    const obj = typeof item === 'object' ? item : { value: item }
    const title = first(obj, titleKeys, `Item ${index + 1}`)
    const detail = first(obj, detailKeys, 'Review this item and confirm the next appropriate action.')
    const tone = toneFor(first(obj, ['severity', 'decision', 'status', 'risk_band'], detail))
    return <article className={`action-card ${tone}`} key={index}>
      <div className="action-card-top"><Badge tone={tone}>{first(obj, ['severity', 'decision', 'status', 'type'], 'Review')}</Badge><span>#{index + 1}</span></div>
      <h3>{title}</h3>
      <p>{detail}</p>
    </article>
  })}</div>
}

function RecordCards({ items, titleKeys = ['name', 'hostname', 'domain', 'email', 'id'], empty = 'No records found.' }) {
  if (!items?.length) return <EmptyState>{empty}</EmptyState>
  return <div className="record-grid evidence-record-grid">{items.map((item, index) => {
    const obj = typeof item === 'object' ? item : { value: item }
    const title = first(obj, titleKeys, `Record ${index + 1}`)
    const status = first(obj, ['status', 'severity', 'state', 'decision'], 'Record')
    const tone = toneFor(status)
    const summary = first(obj, ['operating_system', 'provider', 'type', 'message', 'description', 'last_seen'], 'Full record details are shown below.')
    const entries = Object.entries(obj).filter(([, value]) => value !== undefined && value !== null && value !== '')
    return <article className={`record-card evidence ${tone}`} key={index}>
      <div className="record-card-top"><Badge tone={tone}>{status}</Badge><span>Evidence record #{index + 1}</span></div>
      <h3>{title}</h3>
      <p className="record-summary">{summary}</p>
      <div className="record-evidence-grid">
        {entries.map(([key, value]) => <article className="record-evidence-field" key={key}>
          <span>{label(key)}</span>
          <strong>{valueText(value)}</strong>
        </article>)}
      </div>
    </article>
  })}</div>
}

function Outcome({ data, context = 'general' }) {
  if (!data) return null
  const status = first(data, ['status', 'message', 'result', 'decision', 'verdict'], 'Action completed')
  const tone = toneFor(status)
  const messages = {
    agent: 'The endpoint has been registered and can now be used in posture and investigation workflows.',
    settings: 'The configuration action completed. Review the cards below for the values returned by the backend.',
    email: 'The sender intelligence check has been converted into a readable verdict and evidence summary.',
    phish: 'The authorised phishing simulation action completed and is ready for review.',
    general: 'Sentinel converted the backend response into a readable security outcome.',
  }
  return <div className="outcome-stack"><Verdict tone={tone} eyebrow={label(context)} title={status} message={messages[context] || messages.general} /><KeyValueCards data={data} keys={Object.keys(data).slice(0, 10)} /></div>
}

function Overview() {
  return <div className="page-stack">
    <div className="hero"><div><Badge tone="green">Operational</Badge><h1>Sentinel Security Command Centre</h1><p>A Blue Team workspace that presents outcomes, risks, evidence and next actions clearly. Normal users should never have to interpret raw API output.</p></div></div>
    <div className="stats-grid"><StatCard title="Threat Pipeline" value="Live" subtitle="Validation, scoring and block actions" /><StatCard title="Investigator" value="Ready" subtitle="Evidence, timeline and reports" tone="purple" /><StatCard title="Interface" value="Human" subtitle="Cards, verdicts and next actions" tone="green" /><StatCard title="Roadmap" value="Locked" subtitle="50-module Blue Team suite" tone="orange" /></div>
    <div className="experience-grid"><article className="experience-card"><Badge tone="blue">Detect</Badge><h3>Clear threat decisions</h3><p>Indicators become verdicts, scores and reviewable defensive actions.</p></article><article className="experience-card"><Badge tone="purple">Investigate</Badge><h3>Evidence-first workflow</h3><p>Findings, timelines and bundles are surfaced as analyst-ready outputs.</p></article><article className="experience-card"><Badge tone="green">Fix</Badge><h3>Actionable guidance</h3><p>Users see what happened, how bad it is, and what to do next.</p></article></div>
  </div>
}

function ThreatPipeline() {
  const [input, setInput] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const runPipeline = async () => { setLoading(true); setError(''); setResult(null); try { setResult(await api('/api/pipeline/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ input }) })) } catch (err) { setError(err.message) } finally { setLoading(false) } }
  const validation = toArray(result?.validation?.results)
  const decisions = toArray(result?.decisions?.decisions)
  const blockEntries = result?.blocklist?.plain_text ? result.blocklist.plain_text.split('\n').filter(Boolean) : []
  return <div className="page-stack"><div className="page-title"><Badge tone="blue">Live Workflow</Badge><h1>Threat Processing Pipeline</h1><p>Paste indicators and receive clear validation, threat decisions and defensive action cards.</p></div><Panel title="IOC Input" subtitle="Paste domains, URLs, IPs, hashes or CVEs."><textarea className="input-area" rows="8" value={input} onChange={e => setInput(e.target.value)} placeholder="hxxp://evil[.]com&#10;1.1.1.1&#10;CVE-2024-1234" /><Button onClick={runPipeline} disabled={loading || !input.trim()}>{loading ? 'Processing…' : 'Run Full Pipeline'}</Button>{error && <div className="error-box">{error}</div>}</Panel>{result && <><Verdict tone={blockEntries.length ? 'red' : 'green'} eyebrow="Pipeline complete" title={blockEntries.length ? 'Defensive actions generated' : 'No block actions required'} message="The pipeline result has been converted into validation, decision and action cards." /><div className="stats-grid three"><StatCard title="Validated IOCs" value={validation.length} subtitle="Extracted from input" /><StatCard title="Threat Decisions" value={decisions.length} subtitle="Scored by ThreatGate" tone="purple" /><StatCard title="Block Actions" value={blockEntries.length} subtitle="Review before deployment" tone={blockEntries.length ? 'red' : 'green'} /></div><Panel title="Validated Indicators"><RecordCards items={validation} titleKeys={['value']} /></Panel><Panel title="Threat Decisions"><ActionCards items={decisions} titleKeys={['value']} detailKeys={['reason']} /></Panel><Panel title="Generated Defensive Actions"><ActionCards items={blockEntries.map(entry => ({ value: entry, decision: 'BLOCK', reason: 'Review this defensive block action before deployment.' }))} titleKeys={['value']} detailKeys={['reason']} empty="No block actions were generated." /></Panel></>}</div>
}

function EndpointRisk() {
  const [agents, setAgents] = useState(null)
  const [registered, setRegistered] = useState(null)
  const [host, setHost] = useState('')
  const [result, setResult] = useState(null)
  const loadAgents = async () => setAgents(await api('/api/endpoint/agents'))
  const register = async () => setRegistered(await api('/api/endpoint/agent/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ hostname: host || 'TEST-ENDPOINT', operating_system: 'Windows 11 Pro' }) }))
  const sample = async () => setResult(await api('/api/endpoint/sample'))
  const assessment = result?.assessment
  return <div className="page-stack"><div className="page-title"><Badge tone="green">Live Agents</Badge><h1>Endpoint Risk</h1><p>Register endpoints, review posture and see prioritised remediation cards.</p></div><Panel title="Agent Registration"><input className="text-input" value={host} onChange={e => setHost(e.target.value)} placeholder="Hostname" /><Button onClick={register}>Register Agent</Button><Button onClick={loadAgents}>Refresh Agents</Button></Panel>{registered && <Panel title="Registered Agent"><Outcome data={registered} context="agent" /></Panel>}<Panel title="Sample Assessment"><Button onClick={sample}>Run Sample Endpoint Assessment</Button></Panel>{assessment && <><Verdict tone={toneFor(assessment.risk_band)} eyebrow="Endpoint posture" title={`${assessment.risk_band} risk`} message="Endpoint posture has been summarised into score, band and remediation actions." /><div className="stats-grid three"><StatCard title="Host" value={assessment.hostname} subtitle={assessment.operating_system} /><StatCard title="Risk Score" value={`${assessment.risk_score}/100`} subtitle="Endpoint posture" tone="orange" /><StatCard title="Risk Band" value={assessment.risk_band} subtitle="Calculated severity" tone={toneFor(assessment.risk_band)} /></div><Panel title="Prioritised Findings"><ActionCards items={toArray(assessment.findings)} titleKeys={['control']} detailKeys={['remediation']} /></Panel></>}{agents && <Panel title="Registered Agents"><RecordCards items={agents.agents || agents.results || agents.items || []} titleKeys={['hostname', 'agent_id']} empty="No endpoints are registered yet." /></Panel>}</div>
}

function Investigator() {
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState(null)
  const [details, setDetails] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const loadDetails = async id => setDetails(await api(`/api/investigator/${id}`))
  const loadHistory = async () => setHistory(await api('/api/investigator/history'))
  const run = async () => { setLoading(true); setError(''); setResult(null); try { const data = await api('/api/investigator/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ include_processes: true, include_network: true, include_services: true, include_startup: true, include_eventlog_summary: true, max_eventlog_events: 50 }) }); setResult(data); await loadDetails(data.investigation_id); await loadHistory() } catch (err) { setError(err.message) } finally { setLoading(false) } }
  return <div className="page-stack"><div className="page-title"><Badge tone="purple">Release 1</Badge><h1>Endpoint Investigator</h1><p>Run safe collection and receive a verdict, findings, timeline, report and evidence bundle.</p></div><Panel title="Run Investigation" subtitle="Non-destructive collection only."><Button onClick={run} disabled={loading}>{loading ? 'Investigating…' : 'Run Local Investigation'}</Button><Button onClick={loadHistory}>Load History</Button>{error && <div className="error-box">{error}</div>}</Panel>{result && <><Verdict tone={toneFor(result.highest_severity)} eyebrow="Investigation complete" title={result.exit_decision} message={result.production_grade_effect} /><div className="stats-grid three"><StatCard title="Investigation" value={result.investigation_id} subtitle={result.hostname} /><StatCard title="Findings" value={result.finding_count} subtitle={`${result.evidence_count} evidence artefacts`} tone="orange" /><StatCard title="Highest Severity" value={result.highest_severity} subtitle="Normalised finding score" tone={toneFor(result.highest_severity)} /></div><Panel title="Investigation Outputs"><div className="action-card-grid"><article className="action-card blue"><div className="action-card-top"><Badge tone="blue">Report</Badge><span>HTML</span></div><h3>Open analyst report</h3><p>Readable report with findings and timeline.</p><a className="download-link" href={`${API}/api/investigator/${result.investigation_id}/report`} target="_blank" rel="noreferrer">Open report</a></article><article className="action-card purple"><div className="action-card-top"><Badge tone="purple">Evidence</Badge><span>ZIP</span></div><h3>Download evidence bundle</h3><p>Hashed artefacts ready for case attachment.</p><a className="download-link" href={`${API}/api/investigator/${result.investigation_id}/bundle`}>Download bundle</a></article></div></Panel></>}{details && <><Panel title="Findings"><ActionCards items={toArray(details.findings)} titleKeys={['title']} detailKeys={['recommended_action', 'description']} empty="No suspicious findings were identified." /></Panel><Panel title="Timeline"><table className="data-table"><thead><tr><th>Time</th><th>Source</th><th>Event</th><th>Severity</th></tr></thead><tbody>{toArray(details.timeline).length ? details.timeline.map((t, i) => <tr key={i}><td>{t.time}</td><td>{t.source}</td><td>{t.event}</td><td><Badge tone={toneFor(t.severity)}>{t.severity}</Badge></td></tr>) : <tr><td colSpan="4">No timeline events generated.</td></tr>}</tbody></table></Panel></>}{history && <Panel title="Investigation History"><RecordCards items={history.investigations || []} titleKeys={['investigation_id', 'hostname']} empty="No investigation history available yet." /></Panel>}</div>
}

function ExposureScout() {
  const [target, setTarget] = useState('')
  const [result, setResult] = useState(null)
  const scan = async () => setResult(await api('/api/exposure/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target }) }))
  return <div className="page-stack"><div className="page-title"><Badge tone="blue">Scanner</Badge><h1>ExposureScout</h1><p>Scan an approved domain or IP and receive exposure risk cards.</p></div><Panel title="Target"><input className="text-input" value={target} onChange={e => setTarget(e.target.value)} placeholder="example.com or 192.168.1.10" /><Button onClick={scan} disabled={!target}>Run Exposure Scan</Button></Panel>{result && <><Verdict tone={toneFor(result.risk_band)} eyebrow="Exposure result" title={`${result.risk_band} exposure`} message={`Sentinel scanned ${result.target} and prioritised exposed services.`} /><div className="stats-grid three"><StatCard title="Target" value={result.target} subtitle="Scanned asset" /><StatCard title="Risk Score" value={result.risk_score} subtitle="Exposure score" tone="orange" /><StatCard title="Risk Band" value={result.risk_band} subtitle="Calculated exposure" tone={toneFor(result.risk_band)} /></div><Panel title="Exposure Findings"><ActionCards items={toArray(result.findings)} titleKeys={['issue']} detailKeys={['recommendation', 'remediation']} /></Panel></>}</div>
}

function CVEWatchdog() {
  const [product, setProduct] = useState('')
  const [version, setVersion] = useState('')
  const [result, setResult] = useState(null)
  const scan = async () => setResult(await api('/api/cve/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ product, version }) }))
  const vulns = toArray(result?.vulnerabilities)
  return <div className="page-stack"><div className="page-title"><Badge tone="purple">Vulnerability Intel</Badge><h1>CVE Watchdog</h1><p>Map products and versions to vulnerability cards.</p></div><Panel title="Asset Software"><input className="text-input" value={product} onChange={e => setProduct(e.target.value)} placeholder="Product" /><input className="text-input" value={version} onChange={e => setVersion(e.target.value)} placeholder="Version" /><Button onClick={scan} disabled={!product || !version}>Scan CVEs</Button></Panel>{result && <><Verdict tone={vulns.length ? 'orange' : 'green'} eyebrow="CVE result" title={vulns.length ? 'Vulnerabilities found' : 'No vulnerabilities returned'} message="Review each vulnerability card and prioritise known exploited or high-impact items." /><Panel title="Vulnerabilities"><ActionCards items={vulns} titleKeys={['cve']} detailKeys={['summary', 'description', 'recommendation']} empty="No vulnerabilities were returned." /></Panel></>}</div>
}

function PhishGuard() {
  const [domain, setDomain] = useState('')
  const [name, setName] = useState('')
  const [recipients, setRecipients] = useState('')
  const [template, setTemplate] = useState('Password Reset Awareness')
  const [result, setResult] = useState(null)
  const [domains, setDomains] = useState(null)
  const [templates, setTemplates] = useState(null)
  const connectDomain = async () => setResult(await api('/api/phish/domain/connect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain, provider: 'manual' }) }))
  const loadTemplates = async () => setTemplates(await api('/api/phish/templates'))
  const loadDomains = async () => setDomains(await api('/api/phish/domain/list'))
  const create = async () => { const list = recipients.split(/[\n,;]/).map(x => x.trim()).filter(Boolean); setResult(await api('/api/phish/campaign', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain, name, template_name: template, recipients: list }) })) }
  return <div className="page-stack"><div className="page-title"><Badge tone="green">Safe Simulation</Badge><h1>PhishGuard</h1><p>Authorised awareness testing shown as campaign, template and domain cards.</p></div><Panel title="Domain Control"><input className="text-input" value={domain} onChange={e => setDomain(e.target.value)} placeholder="connected-domain.co.uk" /><Button onClick={connectDomain}>Connect Domain</Button><Button onClick={loadDomains}>List Domains</Button></Panel><Panel title="Campaign Builder"><input className="text-input" value={name} onChange={e => setName(e.target.value)} placeholder="Campaign name" /><input className="text-input" value={template} onChange={e => setTemplate(e.target.value)} placeholder="Template name" /><textarea className="input-area" rows="5" value={recipients} onChange={e => setRecipients(e.target.value)} placeholder="joe.bloggs@connected-domain.co.uk&#10;jane.doe@connected-domain.co.uk" /><Button onClick={create} disabled={!domain || !name || !recipients}>Create Campaign</Button><Button onClick={loadTemplates}>Load Templates</Button></Panel>{result && <Panel title="PhishGuard Outcome"><Outcome data={result} context="phish" /></Panel>}{templates && <Panel title="Templates"><RecordCards items={templates.templates || templates.results || templates.items || []} titleKeys={['name', 'template_name', 'subject']} empty="No templates available yet." /></Panel>}{domains && <Panel title="Connected Domains"><RecordCards items={domains.domains || domains.results || domains.items || []} titleKeys={['domain', 'name']} empty="No connected domains found yet." /></Panel>}</div>
}

function EmailIntel() {
  const [email, setEmail] = useState('')
  const [result, setResult] = useState(null)
  const check = async () => setResult(await api('/api/email-intel/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }) }))
  return <div className="page-stack"><div className="page-title"><Badge tone="blue">Reputation</Badge><h1>Email Intelligence</h1><p>Validate sender trust with a readable verdict and evidence cards.</p></div><Panel title="Email Check"><input className="text-input" value={email} onChange={e => setEmail(e.target.value)} placeholder="sender@example.com" /><Button onClick={check} disabled={!email}>Check Email</Button></Panel>{result && <Panel title="Email Verdict"><Outcome data={result} context="email" /></Panel>}</div>
}

function Settings() {
  const [mail, setMail] = useState({ provider: 'smtp', host: '', port: 587, username: '', password: '', sender_address: '', connected_domain: '' })
  const [provider, setProvider] = useState({ name: '', provider_type: 'virustotal', api_key: '', enabled: true })
  const [validation, setValidation] = useState({ allow_domains: [], trusted_senders: [], blocked_senders: [], blocked_domains: [] })
  const [result, setResult] = useState(null)
  const csv = v => v.split(/[\n,;]/).map(x => x.trim()).filter(Boolean)
  const saveMail = async () => setResult(await api('/api/settings/mail', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...mail, port: Number(mail.port) }) }))
  const testMail = async () => setResult(await api('/api/settings/mail/test', { method: 'POST' }))
  const saveProvider = async () => setResult(await api('/api/settings/ioc-provider', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(provider) }))
  const saveValidation = async () => setResult(await api('/api/settings/email-validation', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(validation) }))
  return <div className="page-stack"><div className="page-title"><Badge tone="purple">Configuration</Badge><h1>Settings</h1><p>Configuration actions are shown as confirmation cards with clear status and returned values.</p></div><Panel title="Email Connection / SMTP"><input className="text-input" placeholder="SMTP Host" value={mail.host} onChange={e => setMail({ ...mail, host: e.target.value })} /><input className="text-input" placeholder="Port" value={mail.port} onChange={e => setMail({ ...mail, port: e.target.value })} /><input className="text-input" placeholder="Username" value={mail.username} onChange={e => setMail({ ...mail, username: e.target.value })} /><input className="text-input" type="password" placeholder="Password" value={mail.password} onChange={e => setMail({ ...mail, password: e.target.value })} /><input className="text-input" placeholder="Sender address" value={mail.sender_address} onChange={e => setMail({ ...mail, sender_address: e.target.value })} /><input className="text-input" placeholder="Connected domain" value={mail.connected_domain} onChange={e => setMail({ ...mail, connected_domain: e.target.value })} /><Button onClick={saveMail}>Save Email Connection</Button><Button onClick={testMail}>Send Test Email</Button></Panel><Panel title="API / Integrations"><input className="text-input" placeholder="Provider name" value={provider.name} onChange={e => setProvider({ ...provider, name: e.target.value })} /><input className="text-input" placeholder="Provider type e.g. virustotal, abusech, otx, misp" value={provider.provider_type} onChange={e => setProvider({ ...provider, provider_type: e.target.value })} /><input className="text-input" type="password" placeholder="API key" value={provider.api_key} onChange={e => setProvider({ ...provider, api_key: e.target.value })} /><Button onClick={saveProvider}>Save Integration</Button></Panel><Panel title="Email Validation Rules"><textarea className="input-area" rows="3" placeholder="Allowed domains" onChange={e => setValidation({ ...validation, allow_domains: csv(e.target.value) })} /><textarea className="input-area" rows="3" placeholder="Trusted senders" onChange={e => setValidation({ ...validation, trusted_senders: csv(e.target.value) })} /><textarea className="input-area" rows="3" placeholder="Blocked senders" onChange={e => setValidation({ ...validation, blocked_senders: csv(e.target.value) })} /><textarea className="input-area" rows="3" placeholder="Blocked domains" onChange={e => setValidation({ ...validation, blocked_domains: csv(e.target.value) })} /><Button onClick={saveValidation}>Save Validation Rules</Button></Panel>{result && <Panel title="Settings Outcome"><Outcome data={result} context="settings" /></Panel>}</div>
}

export default function App() {
  const [active, setActive] = useState('overview')
  const pages = { overview: <Overview />, pipeline: <ThreatPipeline />, endpoint: <EndpointRisk />, investigator: <Investigator />, exposure: <ExposureScout />, cve: <CVEWatchdog />, phish: <PhishGuard />, emailintel: <EmailIntel />, settings: <Settings /> }
  return <div className="app-shell"><aside className="sidebar"><div className="brand"><div className="brand-mark">S</div><div><h2>Sentinel</h2><p>Cyber Defence Platform</p></div></div><nav>{navItems.map(item => <button key={item.id} className={active === item.id ? 'active' : ''} onClick={() => setActive(item.id)}>{item.label}</button>)}</nav></aside><main className="content">{pages[active]}</main></div>
}
