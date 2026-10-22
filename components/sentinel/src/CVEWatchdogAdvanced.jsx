import { useEffect, useMemo, useState } from 'react'

const API = 'http://localhost:8000'
const arr = value => Array.isArray(value) ? value : []
const toneFor = value => {
  const raw = String(value || '').toLowerCase()
  if (['critical', 'known exploited', 'urgent', 'high'].some(v => raw.includes(v))) return raw.includes('high') && !raw.includes('critical') ? 'red' : 'red'
  if (['medium', 'warning', 'review', 'vulnerabilities found'].some(v => raw.includes(v))) return 'orange'
  if (['low', 'none', 'no matching', 'available', 'success'].some(v => raw.includes(v))) return 'green'
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

function VulnerabilityCards({ items }) {
  if (!items?.length) return <Empty>No matching vulnerabilities were found for this software/version from the currently loaded feeds.</Empty>
  return <div className="action-card-grid">{items.map((vuln, index) => {
    const tone = vuln.known_exploited ? 'red' : toneFor(vuln.severity)
    return <article className={`action-card ${tone}`} key={`${vuln.cve}-${index}`}>
      <div className="action-card-top">
        <Badge tone={tone}>{vuln.known_exploited ? 'KNOWN EXPLOITED' : vuln.severity || 'review'}</Badge>
        <span>Priority {vuln.priority_score ?? '—'}</span>
      </div>
      <h3>{vuln.cve}</h3>
      <p>{vuln.summary || 'No vulnerability summary supplied by the feed.'}</p>
      <div className="record-evidence-grid" style={{ marginTop: 14 }}>
        <article className="record-evidence-field"><span>Product</span><strong>{vuln.vendor} {vuln.product}</strong></article>
        <article className="record-evidence-field"><span>Detected Version</span><strong>{vuln.detected_version || 'Not supplied'}</strong></article>
        <article className="record-evidence-field"><span>Affected Versions</span><strong>{arr(vuln.affected_versions).join(', ') || 'Not supplied'}</strong></article>
        <article className="record-evidence-field"><span>CVSS</span><strong>{vuln.cvss ?? 'Unknown'}</strong></article>
        <article className="record-evidence-field"><span>Match Confidence</span><strong>{vuln.match_confidence || 'Unknown'}</strong></article>
        <article className="record-evidence-field"><span>Source</span><strong>{vuln.source || 'Local feed'}</strong></article>
      </div>
      <div className="nested-object-card" style={{ marginTop: 14 }}>
        <div className="nested-object-title">Recommended remediation</div>
        <p style={{ margin: 0, color: '#cbd5e1', lineHeight: 1.6 }}>{vuln.remediation || 'Confirm affected version and apply vendor remediation.'}</p>
      </div>
    </article>
  })}</div>
}

export function CVEWatchdog() {
  const [vendor, setVendor] = useState('')
  const [product, setProduct] = useState('')
  const [version, setVersion] = useState('')
  const [includeNonExact, setIncludeNonExact] = useState(true)
  const [result, setResult] = useState(null)
  const [feedStatus, setFeedStatus] = useState(null)
  const [agents, setAgents] = useState([])
  const [selectedAgentId, setSelectedAgentId] = useState('')
  const [latestEndpointScan, setLatestEndpointScan] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const selectedAgent = useMemo(() => agents.find(agent => String(agent.agent_id || agent.id || '') === selectedAgentId) || null, [agents, selectedAgentId])
  const inventoryItems = Array.isArray(selectedAgent?.latest_software_inventory?.inventory) ? selectedAgent.latest_software_inventory.inventory : []

  const loadLatestEndpointScan = async (agentId = selectedAgentId) => {
    if (!agentId) return
    try { setLatestEndpointScan(await api(`/api/cve/agent/${agentId}/latest`)) } catch (_) { setLatestEndpointScan(null) }
  }

  const loadAgents = async () => {
    try {
      const data = await api('/api/endpoint/agents')
      const loaded = Array.isArray(data?.agents) ? data.agents : []
      setAgents(loaded)
      const nextAgentId = selectedAgentId || (loaded.length ? String(loaded[0].agent_id || loaded[0].id || '') : '')
      if (!selectedAgentId && nextAgentId) setSelectedAgentId(nextAgentId)
      if (nextAgentId) await loadLatestEndpointScan(nextAgentId)
    } catch (e) {
      setError(e.message)
    }
  }

  const loadFeedStatus = async () => {
    try { setFeedStatus(await api('/api/cve/feed/status')) } catch (e) { setError(e.message) }
  }

  useEffect(() => {
    loadFeedStatus()
    loadAgents()
  }, [])

  useEffect(() => { loadLatestEndpointScan(selectedAgentId) }, [selectedAgentId])

  const runScan = async (payload) => {
    setLoading(true); setError(''); setResult(null)
    try {
      setResult(await api(payload.inventory ? '/api/cve/inventory-scan' : '/api/cve/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload.inventory ? { software: payload.inventory, agent_id: payload.agent_id || null } : { vendor: vendor || null, product, version, include_non_exact: includeNonExact }),
      }))
      if (payload.agent_id) await loadLatestEndpointScan(payload.agent_id)
    } catch (e) { setError(e.message) } finally { setLoading(false) }
  }

  const scanManual = async () => runScan({ vendor, product, version, include_non_exact: includeNonExact })

  const scanInventory = async () => {
    if (!inventoryItems.length) {
      setError('The selected endpoint does not have a stored software inventory yet.')
      return
    }
    await runScan({ inventory: inventoryItems, agent_id: selectedAgentId })
  }

  const vulns = arr(result?.vulnerabilities)
  const latestMatches = latestEndpointScan?.latest?.matches

  return <div className="page-stack">
    <div className="page-title"><Badge tone="purple">Vulnerability Intel</Badge><h1>CVE Watchdog</h1><p>Search local vulnerability and KEV-style feeds for CVEs affecting a software product and version, then prioritise what needs remediation first.</p></div>

    {feedStatus && <div className="stats-grid three">
      <StatCard title="Feed Items" value={feedStatus.feed_items} subtitle={feedStatus.using_seed_feed ? 'Built-in seed feed' : 'Local feed file'} tone={feedStatus.using_seed_feed ? 'orange' : 'green'} />
      <StatCard title="Feed State" value={feedStatus.status} subtitle="Matcher ready" tone="green" />
      <StatCard title="Feed Path" value="data/feeds" subtitle="Drop JSON feeds here" tone="blue" />
    </div>}

    <Panel title="Endpoint Inventory Scan" subtitle="Choose a registered endpoint to reuse its latest collected software inventory.">
      <select className="text-input" value={selectedAgentId} onChange={e => setSelectedAgentId(e.target.value)}>
        <option value="">Select an endpoint</option>
        {agents.map(agent => <option key={agent.agent_id || agent.id} value={agent.agent_id || agent.id}>{agent.hostname || agent.agent_id || 'Unnamed endpoint'}</option>)}
      </select>
      <div className="stats-grid three" style={{ marginBottom: 16 }}>
        <StatCard title="Inventory Items" value={inventoryItems.length} subtitle="Latest software snapshot" tone={inventoryItems.length ? 'green' : 'orange'} />
        <StatCard title="Selected Host" value={selectedAgent?.hostname || 'None'} subtitle={selectedAgent?.operating_system || 'No endpoint selected'} tone="blue" />
        <StatCard title="Latest Saved Scan" value={latestMatches?.count ?? 'None'} subtitle={latestMatches?.generated_at || 'No persisted scan yet'} tone={latestMatches ? 'green' : 'orange'} />
      </div>
      <Button onClick={scanInventory} disabled={!inventoryItems.length || loading}>{loading ? 'Scanning inventory…' : 'Scan Selected Inventory'}</Button>
      <Button onClick={loadAgents}>Refresh Endpoints</Button>
      {inventoryItems.length > 0 && <div className="record-grid evidence-record-grid" style={{ marginTop: 16 }}>
        {inventoryItems.slice(0, 12).map((item, index) => {
          const title = [item.vendor, item.product].filter(Boolean).join(' ') || item.name || `Software ${index + 1}`
          return <article className="record-card evidence blue" key={`${title}-${index}`}>
            <div className="record-card-top"><Badge tone="blue">Inventory</Badge><span>#{index + 1}</span></div>
            <h3>{title}</h3>
            <p className="record-summary">{item.version || 'Version not reported'}</p>
            <div className="record-evidence-grid">
              <article className="record-evidence-field"><span>Vendor</span><strong>{item.vendor || 'Not provided'}</strong></article>
              <article className="record-evidence-field"><span>Product</span><strong>{item.product || item.name || 'Not provided'}</strong></article>
              <article className="record-evidence-field"><span>Version</span><strong>{item.version || 'Not provided'}</strong></article>
            </div>
          </article>
        })}
      </div>}
    </Panel>

    <Panel title="Software Vulnerability Lookup" subtitle="Enter the software identity. Vendor is optional, but improves match quality.">
      <input className="text-input" value={vendor} onChange={e => setVendor(e.target.value)} placeholder="Vendor, e.g. Microsoft, Apache, Google" />
      <input className="text-input" value={product} onChange={e => setProduct(e.target.value)} placeholder="Product, e.g. Windows, Outlook, Log4j, Chrome, curl" />
      <input className="text-input" value={version} onChange={e => setVersion(e.target.value)} placeholder="Version, e.g. 11, 365, 2.14.1, 8.3.0" />
      <label className="investigation-scope-card selected" style={{ marginBottom: 12 }}>
        <input type="checkbox" checked={includeNonExact} onChange={e => setIncludeNonExact(e.target.checked)} />
        <div><strong>Include broader product matches</strong><p>Useful where exact version data is incomplete. Exact version matches are still marked with higher confidence.</p></div>
      </label>
      <Button onClick={scanManual} disabled={!product || loading}>{loading ? 'Searching feeds…' : 'Search Vulnerability Feeds'}</Button>
      <Button onClick={loadFeedStatus}>Refresh Feed Status</Button>
      {error && <div className="error-box">{error}</div>}
    </Panel>

    {result && <>
      <Verdict tone={toneFor(result.status)} eyebrow="CVE result" title={result.status} message={result.agent_id ? 'This endpoint inventory scan has been saved for later review and reporting.' : (result.feed_note || 'Vulnerability intelligence has been matched against the supplied software identity.')} />
      <div className="stats-grid three">
        <StatCard title="Matches" value={result.count || 0} subtitle={`${result.scanned_items || 1} software item scanned`} tone={vulns.length ? 'orange' : 'green'} />
        <StatCard title="Known Exploited" value={result.known_exploited_count || 0} subtitle="Treat as urgent" tone={result.known_exploited_count ? 'red' : 'green'} />
        <StatCard title="Critical / High" value={`${result.critical_count || 0}/${result.high_count || 0}`} subtitle="Critical and high findings" tone={(result.critical_count || result.high_count) ? 'red' : 'green'} />
      </div>
      <Panel title="Prioritised Vulnerabilities" subtitle="Sorted by known exploitation, severity, CVSS and match confidence."><VulnerabilityCards items={vulns} /></Panel>
    </>}
  </div>
}
