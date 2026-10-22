import { useState } from 'react'

const API = 'http://localhost:8000'
const arr = value => Array.isArray(value) ? value : []
const isObj = value => value && typeof value === 'object' && !Array.isArray(value)
const nice = value => String(value || '').replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/\b\w/g, c => c.toUpperCase())
const toneFor = value => {
  const raw = String(value || '').toLowerCase()
  if (['critical', 'high', 'fail'].some(v => raw.includes(v))) return 'red'
  if (['medium', 'warning', 'softfail', 'unknown', 'suspicious'].some(v => raw.includes(v))) return 'orange'
  if (['low', 'pass', 'complete', 'safe', 'informational'].some(v => raw.includes(v))) return 'green'
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

function KeyGrid({ data }) {
  const entries = Object.entries(data || {}).filter(([, value]) => value !== undefined && value !== null && value !== '')
  if (!entries.length) return <Empty>No fields available.</Empty>
  return <div className="kv-grid">{entries.map(([key, value]) => <article className="kv-card" key={key}><span>{nice(key)}</span><strong>{isObj(value) || Array.isArray(value) ? JSON.stringify(value) : String(value)}</strong></article>)}</div>
}

function compactValue(value) {
  if (value === undefined || value === null || value === '') return ''
  if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? '' : 's'}`
  if (isObj(value)) return Object.entries(value).slice(0, 4).map(([key, item]) => `${nice(key)}: ${compactValue(item) || 'provided'}`).join(' | ')
  const text = String(value).replace(/\s+/g, ' ').trim()
  return text.length > 260 ? `${text.slice(0, 257)}...` : text
}

function evidencePreview(finding) {
  if (finding.evidence_summary) return compactValue(finding.evidence_summary)
  return compactValue(finding.evidence)
}

function FindingDetail({ label, children }) {
  if (!children) return null
  return <div className="finding-detail"><span>{label}</span><p>{children}</p></div>
}

function FindingCards({ findings }) {
  if (!findings.length) return <Empty>No phishing findings were generated.</Empty>
  return <div className="action-card-grid">{findings.map((finding, index) => {
    const tone = toneFor(finding.severity)
    const checked = finding.what_was_checked || 'Sentinel parsed the email headers, body, links and attachments without executing active content.'
    const meaning = finding.possible_intent || finding.reason
    const nextStep = finding.analyst_next_step || finding.recommended_action
    const evidence = evidencePreview(finding)
    return <article className={`action-card finding-card ${tone}`} key={finding.finding_id || index}>
      <div className="action-card-top"><Badge tone={tone}>{finding.severity || 'review'}</Badge><span>#{index + 1}</span></div>
      <h3>{finding.title}</h3>
      <p className="finding-plain">{finding.plain_english || finding.reason}</p>
      <div className="finding-explain-grid">
        <FindingDetail label="What Sentinel Checked">{checked}</FindingDetail>
        <FindingDetail label="Likely Meaning">{meaning}</FindingDetail>
        <FindingDetail label="Next Step">{nextStep}</FindingDetail>
      </div>
      {evidence && <div className="finding-evidence"><span>Evidence Summary</span><code>{evidence}</code></div>}
    </article>
  })}</div>
}

function UrlCards({ urls }) {
  if (!urls.length) return <Empty>No URLs were extracted.</Empty>
  return <div className="record-grid evidence-record-grid">{urls.map((item, index) => <article className={`record-card evidence ${toneFor(item.severity)}`} key={`${item.url}-${index}`}>
    <div className="record-card-top"><Badge tone={toneFor(item.severity)}>{item.severity}</Badge><span>URL #{index + 1}</span></div>
    <h3>{item.host || 'Unknown host'}</h3>
    <p className="record-summary">{item.reason}</p>
    <div className="record-evidence-grid">
      <article className="record-evidence-field"><span>Scheme</span><strong>{item.scheme || 'Unknown'}</strong></article>
      <article className="record-evidence-field"><span>Root Domain</span><strong>{item.root_domain || 'Unknown'}</strong></article>
      <article className="record-evidence-field wide"><span>URL</span><strong>{item.url}</strong></article>
    </div>
  </article>)}</div>
}

function AttachmentCards({ attachments }) {
  if (!attachments.length) return <Empty>No attachments were found.</Empty>
  return <div className="record-grid evidence-record-grid">{attachments.map((item, index) => <article className={`record-card evidence ${toneFor(item.severity)}`} key={`${item.filename}-${index}`}>
    <div className="record-card-top"><Badge tone={toneFor(item.severity)}>{item.severity}</Badge><span>Attachment #{index + 1}</span></div>
    <h3>{item.filename}</h3>
    <p className="record-summary">{item.reason}</p>
    <div className="record-evidence-grid">
      <article className="record-evidence-field"><span>Content type</span><strong>{item.content_type || 'Unknown'}</strong></article>
      <article className="record-evidence-field"><span>Extension</span><strong>{item.extension || 'None'}</strong></article>
      <article className="record-evidence-field"><span>Size</span><strong>{item.size_bytes ?? 0} bytes</strong></article>
      <article className="record-evidence-field"><span>Double extension</span><strong>{item.double_extension ? 'Yes' : 'No'}</strong></article>
      <article className="record-evidence-field wide"><span>SHA256</span><strong>{item.sha256 || 'Not available'}</strong></article>
    </div>
  </article>)}</div>
}

export function PhishingEmailAnalyser() {
  const [rawEmail, setRawEmail] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const analysePaste = async () => {
    setLoading(true); setError(''); setResult(null)
    try {
      setResult(await api('/api/phish/analyse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_email: rawEmail, source_name: 'pasted-email.eml' }),
      }))
    } catch (e) { setError(e.message) } finally { setLoading(false) }
  }

  const analyseFile = async (file) => {
    if (!file) return
    setLoading(true); setError(''); setResult(null)
    try {
      const form = new FormData()
      form.append('file', file)
      setResult(await api('/api/phish/analyse-upload', { method: 'POST', body: form }))
    } catch (e) { setError(e.message) } finally { setLoading(false) }
  }

  const summary = result?.summary || {}
  const findings = arr(result?.findings)
  const urls = arr(result?.urls)
  const attachments = arr(result?.attachments)
  const linkMismatches = arr(result?.link_mismatches)

  return <div className="page-stack">
    <div className="page-title"><Badge tone="purple">Email Defence</Badge><h1>Phishing Email Analyser</h1><p>Analyse raw .eml content, copied headers, URLs and attachments without executing anything or collecting credentials.</p></div>

    <Panel title="Analyse Email" subtitle="Paste raw headers/body or upload a .eml file exported from the mailbox.">
      <input className="text-input" type="file" accept=".eml,message/rfc822,text/plain" onChange={e => analyseFile(e.target.files?.[0])} />
      <textarea className="input-area" rows="10" value={rawEmail} onChange={e => setRawEmail(e.target.value)} placeholder="Paste raw email headers and body here..." />
      <Button onClick={analysePaste} disabled={!rawEmail.trim() || loading}>{loading ? 'Analysing…' : 'Analyse Pasted Email'}</Button>
      {error && <div className="error-box">{error}</div>}
    </Panel>

    {result && <>
      <Verdict tone={toneFor(summary.severity)} eyebrow="Phishing verdict" title={summary.verdict || result.status} message="The email has been parsed into headers, authentication evidence, URL findings and attachment risk." />
      <div className="stats-grid three">
        <StatCard title="Risk Score" value={summary.risk_score ?? result.risk_score ?? '—'} subtitle="Higher is better" tone={(summary.risk_score ?? 0) > 80 ? 'green' : (summary.risk_score ?? 0) > 60 ? 'orange' : 'red'} />
        <StatCard title="Findings" value={summary.finding_count ?? findings.length} subtitle="Indicators requiring review" tone={findings.length ? 'orange' : 'green'} />
        <StatCard title="URLs / Attachments" value={`${summary.url_count ?? urls.length}/${summary.attachment_count ?? attachments.length}`} subtitle="Extracted evidence" tone={(urls.length || attachments.length) ? 'blue' : 'green'} />
      </div>
      <div className="stats-grid three">
        <StatCard title="Link Mismatches" value={linkMismatches.length} subtitle="Displayed link vs destination" tone={linkMismatches.length ? 'red' : 'green'} />
        <StatCard title="HTML Form" value={result.html_indicators?.has_form || result.html_indicators?.has_password_input ? 'Found' : 'None'} subtitle="Credential collection risk" tone={result.html_indicators?.has_form || result.html_indicators?.has_password_input ? 'red' : 'green'} />
        <StatCard title="Hidden HTML" value={result.html_indicators?.hidden_content ? 'Found' : 'None'} subtitle="Deceptive rendering check" tone={result.html_indicators?.hidden_content ? 'orange' : 'green'} />
      </div>
      <Panel title="Header Summary"><KeyGrid data={result.headers} /></Panel>
      <Panel title="Authentication Results"><div className="stats-grid three">
        {Object.entries(result.authentication || {}).map(([key, value]) => <StatCard key={key} title={key.toUpperCase()} value={value} subtitle="Header-derived result" tone={toneFor(value)} />)}
      </div></Panel>
      <Panel title="Findings"><FindingCards findings={findings} /></Panel>
      <Panel title="URLs"><UrlCards urls={urls} /></Panel>
      <Panel title="Link Mismatches"><KeyGrid data={{ count: linkMismatches.length, mismatches: linkMismatches }} /></Panel>
      <Panel title="Attachments"><AttachmentCards attachments={attachments} /></Panel>
      <Panel title="Recommended Actions"><div className="action-card-grid">{arr(result.recommended_actions).map((item, index) => <article className="action-card blue" key={index}><Badge>Action</Badge><h3>Step {index + 1}</h3><p>{item}</p></article>)}</div></Panel>
    </>}
  </div>
}
