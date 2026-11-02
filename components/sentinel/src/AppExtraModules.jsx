import { useState } from 'react'

const API = 'http://localhost:8000'
const arr = value => Array.isArray(value) ? value : []
const isObj = value => value && typeof value === 'object' && !Array.isArray(value)
const pick = (obj, keys, fallback = 'Not available') => keys.map(key => obj?.[key]).find(value => value !== undefined && value !== null && value !== '') ?? fallback
const nice = key => String(key || '').replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/\b\w/g, c => c.toUpperCase())
const toneFor = value => {
  const raw = String(value || '').toLowerCase()
  if (['critical', 'high', 'block', 'blocked', 'failed', 'danger', 'malicious', 'error'].some(v => raw.includes(v))) return 'red'
  if (['medium', 'warning', 'monitor', 'pending', 'review', 'suspicious'].some(v => raw.includes(v))) return 'orange'
  if (['low', 'safe', 'active', 'success', 'sent', 'created', 'healthy', 'pass', 'trusted'].some(v => raw.includes(v))) return 'green'
  return 'blue'
}

async function api(path, options = {}) {
  const res = await fetch(`${API}${path}`, options)
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

function Badge({ children, tone = 'blue' }) { return <span className={`badge ${tone}`}>{children}</span> }
function Button({ children, ...props }) { return <button className="primary-btn" {...props}>{children}</button> }
function Panel({ title, subtitle, children }) { return <section className="panel"><div className="panel-header"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div></div>{children}</section> }
function StatCard({ title, value, subtitle, tone = 'blue' }) { return <section className={`stat-card ${tone}`}><p>{title}</p><h2>{value}</h2><span>{subtitle}</span></section> }
function Verdict({ title, message, tone = 'blue', eyebrow = 'Result' }) { return <section className={`verdict-card ${tone}`}><Badge tone={tone}>{eyebrow}</Badge><h2>{title}</h2><p>{message}</p></section> }
function Empty({ children = 'Nothing to show yet.' }) { return <div className="empty-state">{children}</div> }

function FieldGrid({ data }) {
  const entries = Object.entries(data || {}).filter(([, value]) => value !== undefined && value !== null && value !== '' && !Array.isArray(value) && !isObj(value))
  if (!entries.length) return <Empty>No summary fields returned.</Empty>
  return <div className="kv-grid">{entries.slice(0, 12).map(([key, value]) => <article className="kv-card" key={key}><span>{nice(key)}</span><strong>{String(value)}</strong></article>)}</div>
}

function ActionCards({ items, empty = 'No actions required.' }) {
  if (!items?.length) return <Empty>{empty}</Empty>
  return <div className="action-card-grid">{items.map((item, index) => {
    const obj = isObj(item) ? item : { value: item, status: 'Review' }
    const title = pick(obj, ['title', 'control', 'value', 'issue', 'cve', 'domain', 'email', 'name', 'subject', 'event'], `Item ${index + 1}`)
    const detail = pick(obj, ['remediation', 'recommended_action', 'reason', 'message', 'description', 'summary'], 'Review this item and decide the next action.')
    const status = pick(obj, ['severity', 'decision', 'status', 'risk_band', 'type'], 'Review')
    const tone = toneFor(status)
    return <article className={`action-card ${tone}`} key={index}>
      <div className="action-card-top"><Badge tone={tone}>{status}</Badge><span>#{index + 1}</span></div>
      <h3>{title}</h3>
      <p>{detail}</p>
    </article>
  })}</div>
}

function RecordCards({ items, titleKeys = ['name', 'hostname', 'domain', 'email', 'id'], empty = 'No records found.' }) {
  if (!items?.length) return <Empty>{empty}</Empty>
  return <div className="record-grid evidence-record-grid">{items.map((item, index) => {
    const obj = isObj(item) ? item : { value: item }
    const title = pick(obj, titleKeys, `Record ${index + 1}`)
    const status = pick(obj, ['status', 'severity', 'state', 'decision'], 'Record')
    const nestedLists = Object.entries(obj).filter(([, value]) => Array.isArray(value))
    return <article className={`record-card evidence ${toneFor(status)}`} key={index}>
      <div className="record-card-top"><Badge tone={toneFor(status)}>{status}</Badge><span>Record #{index + 1}</span></div>
      <h3>{title}</h3>
      <p className="record-summary">{pick(obj, ['summary', 'message', 'description', 'last_seen', 'provider'], 'Full record details are shown below.')}</p>
      <FieldGrid data={obj} />
      {nestedLists.map(([key, value]) => <div className="nested-findings" key={key}><h4>{nice(key)}</h4><ActionCards items={value} empty={`No ${nice(key).toLowerCase()} returned.`} /></div>)}
    </article>
  })}</div>
}

function Outcome({ data, context = 'Outcome' }) {
  if (!data) return null
  const status = pick(data, ['status', 'message', 'result', 'decision', 'verdict'], 'Action completed')
  const lists = Object.entries(data).filter(([, value]) => Array.isArray(value))
  return <div className="outcome-stack"><Verdict tone={toneFor(status)} eyebrow={context} title={status} message="The response is displayed as readable cards and evidence fields." /><FieldGrid data={data} />{lists.map(([key, value]) => <Panel key={key} title={nice(key)}><RecordCards items={value} /></Panel>)}</div>
}

export function Investigator() {
  const [result, setResult] = useState(null)
  const [details, setDetails] = useState(null)
  const [history, setHistory] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const run = async () => {
    setLoading(true); setError('')
    try {
      const data = await api('/api/investigator/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ include_processes: true, include_network: true, include_services: true, include_startup: true, include_eventlog_summary: true, max_eventlog_events: 50 }) })
      setResult(data)
      setDetails(await api(`/api/investigator/${data.investigation_id}`))
      setHistory(await api('/api/investigator/history'))
    } catch (e) { setError(e.message) } finally { setLoading(false) }
  }

  return <div className="page-stack"><div className="page-title"><Badge tone="purple">Investigation</Badge><h1>Investigator</h1><p>Run safe local evidence collection and review findings, timeline, report and evidence bundle.</p></div>
    <Panel title="Run Investigation" subtitle="Non-destructive collection only. This does not delete files or alter the endpoint."><Button onClick={run} disabled={loading}>{loading ? 'Investigating…' : 'Run Local Investigation'}</Button>{error && <div className="error-box">{error}</div>}</Panel>
    {result && <><Verdict tone={toneFor(result.highest_severity)} eyebrow="Investigation complete" title={result.exit_decision || 'Investigation completed'} message={result.production_grade_effect || 'Evidence has been collected for analyst review.'} /><div className="stats-grid three"><StatCard title="Investigation" value={result.investigation_id} subtitle={result.hostname} /><StatCard title="Findings" value={result.finding_count || 0} subtitle={`${result.evidence_count || 0} evidence artefacts`} tone="orange" /><StatCard title="Highest Severity" value={result.highest_severity || 'unknown'} subtitle="Normalised finding score" tone={toneFor(result.highest_severity)} /></div><Panel title="Outputs"><div className="action-card-grid"><article className="action-card blue"><Badge tone="blue">Report</Badge><h3>Open analyst report</h3><p>Readable HTML report with findings and timeline.</p><a className="download-link" href={`${API}/api/investigator/${result.investigation_id}/report`} target="_blank" rel="noreferrer">Open report</a></article><article className="action-card purple"><Badge tone="purple">Evidence</Badge><h3>Download evidence bundle</h3><p>Hashed artefacts ready for case attachment.</p><a className="download-link" href={`${API}/api/investigator/${result.investigation_id}/bundle`}>Download bundle</a></article></div></Panel></>}
    {details && <><Panel title="Findings"><ActionCards items={arr(details.findings)} empty="No suspicious findings identified." /></Panel><Panel title="Timeline"><RecordCards items={arr(details.timeline)} titleKeys={['event', 'source']} empty="No timeline events generated." /></Panel></>}
    {history && <Panel title="Investigation History"><RecordCards items={arr(history.investigations)} titleKeys={['investigation_id', 'hostname']} empty="No investigation history available." /></Panel>}
  </div>
}

export function ExposureScout() {
  const [target, setTarget] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const scan = async () => { setError(''); try { setResult(await api('/api/exposure/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target }) })) } catch (e) { setError(e.message) } }
  return <div className="page-stack"><div className="page-title"><Badge tone="blue">Scanner</Badge><h1>ExposureScout</h1><p>Scan an approved domain or IP and review exposed service risk.</p></div><Panel title="Target"><input className="text-input" value={target} onChange={e => setTarget(e.target.value)} placeholder="example.com or 192.168.1.10" /><Button onClick={scan} disabled={!target}>Run Exposure Scan</Button>{error && <div className="error-box">{error}</div>}</Panel>{result && <><Verdict tone={toneFor(result.risk_band)} eyebrow="Exposure result" title={`${result.risk_band || 'Unknown'} exposure`} message={`Sentinel scanned ${result.target || target} and prioritised returned exposure findings.`} /><div className="stats-grid three"><StatCard title="Target" value={result.target || target} subtitle="Scanned asset" /><StatCard title="Risk Score" value={result.risk_score ?? '—'} subtitle="Exposure score" tone="orange" /><StatCard title="Risk Band" value={result.risk_band || 'unknown'} subtitle="Calculated exposure" tone={toneFor(result.risk_band)} /></div><Panel title="Exposure Findings"><ActionCards items={arr(result.findings)} empty="No exposure findings returned." /></Panel></>}</div>
}

export function CVEWatchdog() {
  const [product, setProduct] = useState('')
  const [version, setVersion] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const scan = async () => { setError(''); try { setResult(await api('/api/cve/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ product, version }) })) } catch (e) { setError(e.message) } }
  const vulns = arr(result?.vulnerabilities)
  return <div className="page-stack"><div className="page-title"><Badge tone="purple">Vulnerability Intel</Badge><h1>CVE Watchdog</h1><p>Map products and versions to vulnerability findings.</p></div><Panel title="Asset Software"><input className="text-input" value={product} onChange={e => setProduct(e.target.value)} placeholder="Product" /><input className="text-input" value={version} onChange={e => setVersion(e.target.value)} placeholder="Version" /><Button onClick={scan} disabled={!product || !version}>Scan CVEs</Button>{error && <div className="error-box">{error}</div>}</Panel>{result && <><Verdict tone={vulns.length ? 'orange' : 'green'} eyebrow="CVE result" title={vulns.length ? 'Vulnerabilities found' : 'No vulnerabilities returned'} message="Review each CVE card and prioritise known exploited or high-impact items." /><Panel title="Vulnerabilities"><ActionCards items={vulns} empty="No vulnerabilities were returned." /></Panel></>}</div>
}

export function PhishGuard() {
  const [domain, setDomain] = useState('')
  const [name, setName] = useState('')
  const [recipients, setRecipients] = useState('')
  const [template, setTemplate] = useState('Password Reset Awareness')
  const [result, setResult] = useState(null)
  const [domains, setDomains] = useState(null)
  const [templates, setTemplates] = useState(null)
  const [error, setError] = useState('')
  const create = async () => { setError(''); try { const list = recipients.split(/[\n,;]/).map(x => x.trim()).filter(Boolean); setResult(await api('/api/phish/campaign', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain, name, template_name: template, recipients: list }) })) } catch (e) { setError(e.message) } }
  return <div className="page-stack"><div className="page-title"><Badge tone="green">Safe Simulation</Badge><h1>PhishGuard</h1><p>Authorised domain-controlled awareness testing.</p></div><Panel title="Domain Control"><input className="text-input" value={domain} onChange={e => setDomain(e.target.value)} placeholder="connected-domain.co.uk" /><Button onClick={async () => setResult(await api('/api/phish/domain/connect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain, provider: 'manual' }) }))}>Connect Domain</Button><Button onClick={async () => setDomains(await api('/api/phish/domain/list'))}>List Domains</Button></Panel><Panel title="Campaign Builder"><input className="text-input" value={name} onChange={e => setName(e.target.value)} placeholder="Campaign name" /><input className="text-input" value={template} onChange={e => setTemplate(e.target.value)} placeholder="Template name" /><textarea className="input-area" rows="5" value={recipients} onChange={e => setRecipients(e.target.value)} placeholder="recipient@example.com" /><Button onClick={create} disabled={!domain || !name || !recipients}>Create Campaign</Button><Button onClick={async () => setTemplates(await api('/api/phish/templates'))}>Load Templates</Button>{error && <div className="error-box">{error}</div>}</Panel>{result && <Panel title="Outcome"><Outcome data={result} context="PhishGuard" /></Panel>}{templates && <Panel title="Templates"><RecordCards items={templates.templates || templates.results || templates.items || []} titleKeys={['name', 'template_name', 'subject']} /></Panel>}{domains && <Panel title="Connected Domains"><RecordCards items={domains.domains || domains.results || domains.items || []} titleKeys={['domain', 'name']} /></Panel>}</div>
}

export function EmailIntel() {
  const [email, setEmail] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const check = async () => { setError(''); try { setResult(await api('/api/email-intel/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }) })) } catch (e) { setError(e.message) } }
  return <div className="page-stack"><div className="page-title"><Badge tone="blue">Reputation</Badge><h1>Email Intelligence</h1><p>Validate whether a sender appears trusted, suspicious or malicious.</p></div><Panel title="Email Check"><input className="text-input" value={email} onChange={e => setEmail(e.target.value)} placeholder="sender@example.com" /><Button onClick={check} disabled={!email}>Check Email</Button>{error && <div className="error-box">{error}</div>}</Panel>{result && <Panel title="Email Verdict"><Outcome data={result} context="Email" /></Panel>}</div>
}

export function Settings() {
  const [mail, setMail] = useState({ provider: 'smtp', host: '', port: 587, username: '', password: '', sender_address: '', connected_domain: '' })
  const [provider, setProvider] = useState({ name: '', provider_type: 'virustotal', api_key: '', enabled: true })
  const [validation, setValidation] = useState({ allow_domains: [], trusted_senders: [], blocked_senders: [], blocked_domains: [] })
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const csv = v => v.split(/[\n,;]/).map(x => x.trim()).filter(Boolean)
  const call = async fn => { setError(''); try { setResult(await fn()) } catch (e) { setError(e.message) } }
  return <div className="page-stack"><div className="page-title"><Badge tone="purple">Configuration</Badge><h1>Settings</h1><p>Control SMTP, IOC integrations and email validation rules.</p></div><Panel title="Email Connection / SMTP"><input className="text-input" placeholder="SMTP Host" value={mail.host} onChange={e => setMail({ ...mail, host: e.target.value })} /><input className="text-input" placeholder="Port" value={mail.port} onChange={e => setMail({ ...mail, port: e.target.value })} /><input className="text-input" placeholder="Username" value={mail.username} onChange={e => setMail({ ...mail, username: e.target.value })} /><input className="text-input" type="password" placeholder="Password" value={mail.password} onChange={e => setMail({ ...mail, password: e.target.value })} /><input className="text-input" placeholder="Sender address" value={mail.sender_address} onChange={e => setMail({ ...mail, sender_address: e.target.value })} /><input className="text-input" placeholder="Connected domain" value={mail.connected_domain} onChange={e => setMail({ ...mail, connected_domain: e.target.value })} /><Button onClick={() => call(() => api('/api/settings/mail', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...mail, port: Number(mail.port) }) }))}>Save Email Connection</Button><Button onClick={() => call(() => api('/api/settings/mail/test', { method: 'POST' }))}>Send Test Email</Button></Panel><Panel title="API / Integrations"><input className="text-input" placeholder="Provider name" value={provider.name} onChange={e => setProvider({ ...provider, name: e.target.value })} /><input className="text-input" placeholder="Provider type e.g. virustotal, abusech, otx, misp" value={provider.provider_type} onChange={e => setProvider({ ...provider, provider_type: e.target.value })} /><input className="text-input" type="password" placeholder="API key" value={provider.api_key} onChange={e => setProvider({ ...provider, api_key: e.target.value })} /><Button onClick={() => call(() => api('/api/settings/ioc-provider', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(provider) }))}>Save Integration</Button></Panel><Panel title="Email Validation Rules"><textarea className="input-area" rows="3" placeholder="Allowed domains" onChange={e => setValidation({ ...validation, allow_domains: csv(e.target.value) })} /><textarea className="input-area" rows="3" placeholder="Trusted senders" onChange={e => setValidation({ ...validation, trusted_senders: csv(e.target.value) })} /><textarea className="input-area" rows="3" placeholder="Blocked senders" onChange={e => setValidation({ ...validation, blocked_senders: csv(e.target.value) })} /><textarea className="input-area" rows="3" placeholder="Blocked domains" onChange={e => setValidation({ ...validation, blocked_domains: csv(e.target.value) })} /><Button onClick={() => call(() => api('/api/settings/email-validation', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(validation) }))}>Save Validation Rules</Button></Panel>{error && <div className="error-box">{error}</div>}{result && <Panel title="Settings Outcome"><Outcome data={result} context="Settings" /></Panel>}</div>
}
