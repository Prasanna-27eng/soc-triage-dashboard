import { useState, useEffect } from 'react'
import { supabase } from '../supabaseClient.js'

/* ── Helpers ───────────────────────────────────────────────── */
function fmtDate(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  return `${String(d.getDate()).padStart(2,'0')}/${String(d.getMonth()+1).padStart(2,'0')}/${d.getFullYear()}`
}
function fmtFull(ts) {
  return ts ? new Date(ts).toLocaleString() : '—'
}

function severityBadge(sev) {
  const map = { P1:'p1', P2:'p2', P3:'p3', P4:'p4' }
  const k = (sev||'').toUpperCase()
  return <span className={`badge badge-${map[k]||'p4'}`}>{k||'—'}</span>
}

function verdictBadge(v) {
  return <span className={`badge badge-${(v||'unknown').toLowerCase()}`}>{v||'UNKNOWN'}</span>
}

function caseLabel(cases, caseObj) {
  const sorted = [...cases].sort((a,b) => new Date(a.created_at) - new Date(b.created_at))
  const idx = sorted.findIndex(c => c.id === caseObj.id)
  return `CASE-${String(idx + 1).padStart(3, '0')}`
}

/* ── Report renderer: parse lines ──────────────────────────── */
function ReportRenderer({ text }) {
  if (!text) return <div style={{ color: 'var(--text-secondary)', fontSize: 12 }}>No report content.</div>

  const lines = text.split('\n')
  return (
    <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 12, lineHeight: 1.8 }}>
      {lines.map((line, i) => {
        if (line.startsWith('═') || line.startsWith('─')) {
          return <hr key={i} className="report-rule" />
        }
        if (line.match(/^[A-Z ]{3,}$/) && line.trim().length > 2 && !line.includes('—') && !line.includes(':') && !line.includes('/')) {
          return <span key={i} className="report-heading">{line}</span>
        }
        return <div key={i} style={{ color: 'var(--text-primary)', minHeight: '1.5em' }}>{line || ' '}</div>
      })}
    </div>
  )
}

/* ── Generate report for a case ─────────────────────────────── */
function buildReport(caseObj, iocs, analystName) {
  const now = new Date().toLocaleString()
  const worstVerdict = (() => {
    if (iocs.some(i => i.verdict === 'MALICIOUS'))  return 'MALICIOUS'
    if (iocs.some(i => i.verdict === 'SUSPICIOUS')) return 'SUSPICIOUS'
    if (iocs.some(i => i.verdict === 'CLEAN'))      return 'CLEAN'
    return 'UNKNOWN'
  })()
  const avgScore = iocs.length
    ? Math.round(iocs.filter(i=>i.risk_score!=null).reduce((s,i)=>s+i.risk_score,0) / Math.max(1, iocs.filter(i=>i.risk_score!=null).length))
    : 0

  let md = `CASE INVESTIGATION REPORT
═══════════════════════════════════════════════════════
Case      : ${caseObj.title}
ID        : ${caseObj.id}
Severity  : ${caseObj.severity || '—'}
Status    : ${caseObj.status || '—'}
Analyst   : ${analystName || 'ANALYST'}
Created   : ${fmtFull(caseObj.created_at)}
Generated : ${now}
Verdict   : ${worstVerdict}
Avg Risk  : ${avgScore}/100
═══════════════════════════════════════════════════════

DESCRIPTION
${caseObj.description || 'No description provided.'}

ANALYST NOTES
${caseObj.notes || 'No notes recorded.'}

IOC SUMMARY (${iocs.length} total)
─────────────────────────────────────────────────────`

  iocs.forEach((ioc, idx) => {
    md += `\n
[${idx+1}] ${ioc.value}
    Type    : ${(ioc.type||'').toUpperCase()}
    Verdict : ${ioc.verdict || 'UNKNOWN'}
    Risk    : ${ioc.risk_score ?? 'N/A'}/100
    VT      : ${ioc.vt_malicious ?? 'N/A'}/${ioc.vt_total ?? 'N/A'} engines
    Abuse   : ${ioc.abuseipdb_score ?? 'N/A'}%
    URLScan : ${ioc.urlscan_score ?? 'N/A'}/100
    Country : ${ioc.geo_country || '—'}
    ISP     : ${ioc.isp || '—'}
    Date    : ${fmtFull(ioc.queried_at)}`
  })

  md += `\n\n═══════════════════════════════════════════════════════
RECOMMENDATION
${worstVerdict === 'MALICIOUS' ? 'BLOCK — High confidence malicious. Immediate firewall block recommended. Escalate to L2.' :
  worstVerdict === 'SUSPICIOUS' ? 'MONITOR — Suspicious indicators present. Add to watchlist. Correlate with other alerts.' :
  'CLEAN — No significant detections. Continue standard monitoring.'}

[End of Report]`
  return md
}

/* ── Report detail view ────────────────────────────────────── */
function ReportView({ caseObj, allCases, iocs, onBack, addToast, analystName }) {
  const [regenerating, setRegenerating] = useState(false)
  const [reportText, setReportText] = useState(caseObj.report_md || '')

  const worstVerdict = (() => {
    if (iocs.some(i => i.verdict === 'MALICIOUS'))  return 'MALICIOUS'
    if (iocs.some(i => i.verdict === 'SUSPICIOUS')) return 'SUSPICIOUS'
    if (iocs.some(i => i.verdict === 'CLEAN'))      return 'CLEAN'
    return 'UNKNOWN'
  })()

  async function regenerate() {
    setRegenerating(true)
    const text = buildReport(caseObj, iocs, analystName)
    const { error } = await supabase.from('cases')
      .update({ report_md: text, updated_at: new Date().toISOString() })
      .eq('id', caseObj.id)
    if (error) addToast(`Regen failed: ${error.message}`, 'error')
    else {
      setReportText(text)
      addToast('Report regenerated', 'success')
    }
    setRegenerating(false)
  }

  function copy() {
    navigator.clipboard.writeText(reportText)
      .then(() => addToast('Copied', 'success'))
      .catch(() => addToast('Copy failed', 'error'))
  }

  function download() {
    const blob = new Blob([reportText], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `report-${caseLabel(allCases, caseObj)}-${Date.now()}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  const label = caseLabel(allCases, caseObj)

  return (
    <div>
      <button className="back-btn" onClick={onBack}>← REPORTS</button>

      <div className="page-header">
        <div style={{ display:'flex', alignItems:'center', gap:10, flexWrap:'wrap' }}>
          {severityBadge(caseObj.severity)}
          <span style={{ fontFamily:'"JetBrains Mono",monospace', fontSize:12, color:'var(--gold)' }}>
            {label}
          </span>
          <h1 style={{ fontSize:18, fontWeight:700 }}>{caseObj.title}</h1>
        </div>
      </div>

      <div className="report-detail-grid">
        {/* Report content */}
        <div className="card">
          <div className="card-header">
            <span className="card-title card-title-gold">REPORT CONTENT</span>
          </div>
          <div style={{ maxHeight: '70vh', overflowY: 'auto', padding: '4px 0' }}>
            <ReportRenderer text={reportText} />
          </div>
        </div>

        {/* Sidebar */}
        <div style={{ display:'flex', flexDirection:'column', gap:16 }}>
          {/* Metadata */}
          <div className="card">
            <div className="card-header"><span className="card-title card-title-gold">CASE INFO</span></div>
            <div className="geo-row"><span className="geo-label">Case ID</span>
              <span className="geo-value text-mono" style={{ color:'var(--gold)', fontSize:11 }}>{label}</span></div>
            <div className="geo-row"><span className="geo-label">Severity</span>
              <span className="geo-value">{severityBadge(caseObj.severity)}</span></div>
            <div className="geo-row"><span className="geo-label">Status</span>
              <span className="geo-value">{caseObj.status || '—'}</span></div>
            <div className="geo-row"><span className="geo-label">IOCs</span>
              <span className="geo-value" style={{ color:'var(--cyan)' }}>{iocs.length}</span></div>
            <div className="geo-row"><span className="geo-label">Worst</span>
              <span className="geo-value">{verdictBadge(worstVerdict)}</span></div>
            <div className="geo-row"><span className="geo-label">Updated</span>
              <span className="geo-value text-mono" style={{ fontSize:10 }}>{fmtDate(caseObj.updated_at)}</span></div>
          </div>

          {/* Verdict summary */}
          {iocs.length > 0 && (
            <div className="card">
              <div className="card-header"><span className="card-title card-title-gold">VERDICTS</span></div>
              {['MALICIOUS','SUSPICIOUS','CLEAN','UNKNOWN'].map(v => {
                const count = iocs.filter(i => i.verdict === v || (!i.verdict && v === 'UNKNOWN')).length
                return (
                  <div key={v} className="geo-row">
                    <span className="geo-label">{v}</span>
                    <span className="geo-value" style={{ color: count > 0 ? undefined : 'var(--text-secondary)' }}>
                      {verdictBadge(count > 0 ? v : 'unknown')} {count}
                    </span>
                  </div>
                )
              })}
            </div>
          )}

          {/* Actions */}
          <div className="card">
            <div className="card-header"><span className="card-title card-title-gold">ACTIONS</span></div>
            <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
              <button className="btn btn-outline" onClick={regenerate} disabled={regenerating}>
                {regenerating ? '⟳ GENERATING...' : '⟳ REGENERATE'}
              </button>
              <button className="btn btn-ghost" onClick={copy}>⊕ COPY</button>
              <button className="btn btn-ghost" onClick={download}>⊞ DOWNLOAD .TXT</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

/* ── Reports Page ──────────────────────────────────────────── */
export default function Reports({ settings, addToast }) {
  const [cases, setCases]       = useState([])
  const [iocMap, setIocMap]     = useState({})
  const [loading, setLoading]   = useState(true)
  const [selected, setSelected] = useState(null)
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo]     = useState('')
  const [sevFilter, setSevFilter] = useState('')

  async function loadData() {
    setLoading(true)
    const { data: casesData } = await supabase.from('cases')
      .select('*')
      .not('report_md', 'is', null)
      .order('updated_at', { ascending: false })

    const { data: iocData } = await supabase.from('ioc_results').select('*')

    const map = {}
    ;(iocData || []).forEach(ioc => {
      if (!map[ioc.case_id]) map[ioc.case_id] = []
      map[ioc.case_id].push(ioc)
    })

    setCases(casesData || [])
    setIocMap(map)
    setLoading(false)
  }

  useEffect(() => { loadData() }, [])

  function worstVerdict(caseId) {
    const iocs = iocMap[caseId] || []
    if (iocs.some(i => i.verdict === 'MALICIOUS'))  return 'MALICIOUS'
    if (iocs.some(i => i.verdict === 'SUSPICIOUS')) return 'SUSPICIOUS'
    if (iocs.some(i => i.verdict === 'CLEAN'))      return 'CLEAN'
    return 'UNKNOWN'
  }

  /* If viewing a report */
  if (selected) {
    return (
      <ReportView
        caseObj={selected}
        allCases={cases}
        iocs={iocMap[selected.id] || []}
        onBack={() => { setSelected(null); loadData() }}
        addToast={addToast}
        analystName={settings?.analyst_name}
      />
    )
  }

  /* Filter */
  const filtered = cases.filter(c => {
    const matchSev = !sevFilter || c.severity === sevFilter
    const matchFrom = !dateFrom || new Date(c.updated_at) >= new Date(dateFrom)
    const matchTo   = !dateTo   || new Date(c.updated_at) <= new Date(dateTo + 'T23:59:59')
    return matchSev && matchFrom && matchTo
  })

  const allCasesSorted = [...cases].sort((a,b) => new Date(a.created_at) - new Date(b.created_at))

  function copyReport(c) {
    navigator.clipboard.writeText(c.report_md || '')
      .then(() => addToast('Report copied', 'success'))
      .catch(() => addToast('Copy failed', 'error'))
  }

  function downloadReport(c) {
    const label = caseLabel(allCasesSorted, c)
    const blob = new Blob([c.report_md || ''], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `report-${label}-${Date.now()}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">REPORTS</div>
          <div className="page-sub">{cases.length} reports available</div>
        </div>
      </div>

      {/* Filter bar */}
      <div className="filter-bar">
        <input type="date" className="input" style={{ maxWidth: 160 }}
          value={dateFrom} onChange={e => setDateFrom(e.target.value)} />
        <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>to</span>
        <input type="date" className="input" style={{ maxWidth: 160 }}
          value={dateTo} onChange={e => setDateTo(e.target.value)} />
        <select className="select" value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
          <option value="">All Severities</option>
          <option value="P1">P1 — Critical</option>
          <option value="P2">P2 — High</option>
          <option value="P3">P3 — Medium</option>
          <option value="P4">P4 — Low</option>
        </select>
        {(dateFrom || dateTo || sevFilter) && (
          <button className="btn btn-ghost btn-sm"
            onClick={() => { setDateFrom(''); setDateTo(''); setSevFilter('') }}>
            ✕ Clear
          </button>
        )}
      </div>

      {/* Reports table */}
      {loading ? (
        <div className="card">
          {[...Array(4)].map((_,i) => (
            <div key={i} className="skeleton" style={{ height: 44, marginBottom: 8 }} />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <div className="empty-state" style={{ marginTop: 40 }}>
          <span className="empty-icon">⊞</span>
          <span className="empty-title">
            {cases.length === 0 ? 'No reports generated yet' : 'No reports match your filters'}
          </span>
          <span className="empty-sub">
            {cases.length === 0 ? 'Generate reports from the Cases page' : 'Try adjusting your filters'}
          </span>
        </div>
      ) : (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>CASE ID</th>
                  <th>TITLE</th>
                  <th>SEVERITY</th>
                  <th style={{ textAlign:'right' }}>IOC COUNT</th>
                  <th>WORST VERDICT</th>
                  <th>LAST UPDATED</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(c => {
                  const label = caseLabel(allCasesSorted, c)
                  const iocs  = iocMap[c.id] || []
                  const worst = worstVerdict(c.id)
                  return (
                    <tr key={c.id}>
                      <td className="td-mono" style={{ color:'var(--gold)', fontSize:11 }}>{label}</td>
                      <td style={{ maxWidth:200, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', fontSize:13 }}>
                        {c.title}
                      </td>
                      <td>{severityBadge(c.severity)}</td>
                      <td className="td-mono" style={{ textAlign:'right', color:'var(--cyan)' }}>{iocs.length}</td>
                      <td>{verdictBadge(worst)}</td>
                      <td className="td-mono" style={{ fontSize:11, color:'var(--text-secondary)' }}>
                        {fmtDate(c.updated_at)}
                      </td>
                      <td>
                        <div style={{ display:'flex', gap:6 }}>
                          <button className="btn btn-outline btn-sm" onClick={() => setSelected(c)}>
                            VIEW
                          </button>
                          <button className="btn btn-ghost btn-sm" onClick={() => copyReport(c)}>
                            COPY
                          </button>
                          <button className="btn btn-ghost btn-sm" onClick={() => downloadReport(c)}>
                            ↓ TXT
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
