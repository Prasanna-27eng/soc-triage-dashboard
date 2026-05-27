import { useState, useEffect, useCallback } from 'react'
import { supabase } from '../supabaseClient.js'

/* ── Helpers ───────────────────────────────────────────────── */
function fmtDate(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  return `${String(d.getDate()).padStart(2,'0')}/${String(d.getMonth()+1).padStart(2,'0')}/${d.getFullYear()}`
}
function fmtFull(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString()
}

function severityBadge(sev) {
  const map = { P1:'p1', P2:'p2', P3:'p3', P4:'p4' }
  const k = (sev||'').toUpperCase()
  return <span className={`badge badge-${map[k]||'p4'}`}>{k||'—'}</span>
}
function statusBadge(st) {
  const k = (st||'').toLowerCase()
  return <span className={`badge badge-${k}`}>{(st||'—').replace('_',' ')}</span>
}
function verdictBadge(v) {
  return <span className={`badge badge-${(v||'unknown').toLowerCase()}`}>{v||'UNKNOWN'}</span>
}
function typeBadge(t) {
  const cls = ['md5','sha1','sha256'].includes(t) ? 'hash' : (t||'unknown')
  return <span className={`badge badge-${cls}`}>{(t||'—').toUpperCase()}</span>
}

function caseLabel(cases, caseObj) {
  const sorted = [...cases].sort((a,b) => new Date(a.created_at) - new Date(b.created_at))
  const idx = sorted.findIndex(c => c.id === caseObj.id)
  return `CASE-${String(idx + 1).padStart(3, '0')}`
}

/* ── Generate report markdown ──────────────────────────────── */
function generateReport(caseObj, iocs, analystName) {
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
───────────────────────────────────────────────────────`

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

/* ── New Case Panel ────────────────────────────────────────── */
function NewCasePanel({ onClose, onCreated, addToast, analystName }) {
  const [title, setTitle]     = useState('')
  const [severity, setSev]    = useState('P3')
  const [description, setDesc]= useState('')
  const [tagInput, setTagInput]= useState('')
  const [tags, setTags]       = useState([])
  const [saving, setSaving]   = useState(false)

  function addTag(val) {
    const t = val.trim()
    if (t && !tags.includes(t)) setTags(prev => [...prev, t])
    setTagInput('')
  }

  async function create() {
    if (!title.trim()) return
    setSaving(true)
    const id = `case-${Date.now()}-${Math.random().toString(36).slice(2,6)}`
    const { error } = await supabase.from('cases').insert({
      id,
      title: title.trim(),
      severity,
      status: 'OPEN',
      description: description.trim() || null,
      tags,
      analyst: analystName || 'ANALYST',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })
    if (error) {
      addToast(`Failed: ${error.message}`, 'error')
      setSaving(false)
      return
    }
    await supabase.from('activity_log').insert({
      action: 'CASE CREATED',
      detail: `New case: "${title.trim()}" [${severity}]`,
      created_at: new Date().toISOString(),
    })
    addToast('Case created', 'success')
    onCreated()
    onClose()
  }

  return (
    <div className="panel-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="panel-slide">
        <div className="panel-header">
          <span style={{ fontFamily:'Oxanium', fontWeight:700, fontSize:14, letterSpacing:'0.1em', color:'var(--gold)' }}>
            NEW CASE
          </span>
          <button className="panel-close" onClick={onClose}>✕</button>
        </div>

        <div style={{ display:'flex', flexDirection:'column', gap:16 }}>
          <div>
            <div className="section-label">TITLE *</div>
            <input className="input" value={title} onChange={e=>setTitle(e.target.value)}
              placeholder="Case title..." autoFocus />
          </div>
          <div>
            <div className="section-label">SEVERITY</div>
            <select className="select" value={severity} onChange={e=>setSev(e.target.value)}>
              <option value="P1">P1 — Critical</option>
              <option value="P2">P2 — High</option>
              <option value="P3">P3 — Medium</option>
              <option value="P4">P4 — Low</option>
            </select>
          </div>
          <div>
            <div className="section-label">DESCRIPTION</div>
            <textarea className="textarea" value={description} onChange={e=>setDesc(e.target.value)}
              placeholder="Case description..." rows={4} />
          </div>
          <div>
            <div className="section-label">TAGS</div>
            <div className="tags-row" style={{ marginBottom: 8 }}>
              {tags.map((t,i) => (
                <span key={i} className="tag">
                  {t}
                  <button className="tag-remove" onClick={() => setTags(prev=>prev.filter((_,j)=>j!==i))}>×</button>
                </span>
              ))}
            </div>
            <input className="input" value={tagInput} onChange={e=>setTagInput(e.target.value)}
              placeholder="Add tag, press Enter or comma..."
              onKeyDown={e => {
                if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); addTag(tagInput) }
              }}
              onBlur={() => tagInput.trim() && addTag(tagInput)}
            />
          </div>

          <button className="btn btn-primary" onClick={create} disabled={!title.trim() || saving}
            style={{ marginTop: 8 }}>
            {saving ? '⟳ CREATING...' : '✓ CREATE CASE'}
          </button>
        </div>
      </div>
    </div>
  )
}

/* ── IOC expand row ────────────────────────────────────────── */
function IocExpandRow({ ioc }) {
  return (
    <tr>
      <td colSpan={6} style={{ padding: 0 }}>
        <div className="ioc-expand-row">
          <div className="ioc-expand-grid">
            <div>
              <div className="section-label" style={{ fontSize: 9 }}>VIRUSTOTAL</div>
              <div className="geo-row"><span className="geo-label">Detections</span>
                <span className="geo-value">{ioc.vt_malicious ?? '—'}/{ioc.vt_total ?? '—'}</span></div>
              <div className="geo-row"><span className="geo-label">Votes</span>
                <span className="geo-value">👍{ioc.vt_community_up ?? 0} / 👎{ioc.vt_community_down ?? 0}</span></div>
              {ioc.malware_families?.length > 0 && (
                <div className="tags-row" style={{ marginTop: 6 }}>
                  {ioc.malware_families.map((f,i)=><span key={i} className="family-pill">{f}</span>)}
                </div>
              )}
            </div>
            <div>
              <div className="section-label" style={{ fontSize: 9 }}>ABUSEIPDB</div>
              <div className="geo-row"><span className="geo-label">Confidence</span>
                <span className="geo-value">{ioc.abuseipdb_score != null ? `${ioc.abuseipdb_score}%` : '—'}</span></div>
              <div className="geo-row"><span className="geo-label">Reports</span>
                <span className="geo-value">{ioc.abuseipdb_reports ?? '—'}</span></div>
              <div className="geo-row"><span className="geo-label">Country</span>
                <span className="geo-value">{ioc.geo_country || '—'}</span></div>
              <div className="geo-row"><span className="geo-label">ISP</span>
                <span className="geo-value">{ioc.isp || '—'}</span></div>
            </div>
            <div>
              <div className="section-label" style={{ fontSize: 9 }}>URLSCAN</div>
              <div className="geo-row"><span className="geo-label">Score</span>
                <span className="geo-value">{ioc.urlscan_score != null ? `${ioc.urlscan_score}/100` : '—'}</span></div>
              {ioc.urlscan_tags?.length > 0 && (
                <div className="tags-row" style={{ marginTop: 6 }}>
                  {ioc.urlscan_tags.map((t,i)=><span key={i} className="tag">{t}</span>)}
                </div>
              )}
              {ioc.urlscan_link && (
                <a className="urlscan-link" href={ioc.urlscan_link} target="_blank" rel="noreferrer"
                  style={{ marginTop: 8, display: 'block' }}>
                  VIEW SCAN →
                </a>
              )}
            </div>
          </div>
        </div>
      </td>
    </tr>
  )
}

/* ── Case Detail View ──────────────────────────────────────── */
function CaseDetail({ caseObj, allCases, onBack, addToast, analystName }) {
  const [c, setC]         = useState(caseObj)
  const [iocs, setIocs]   = useState([])
  const [expanded, setExpanded] = useState(null)
  const [saving, setSaving]     = useState(false)
  const [tagInput, setTagInput] = useState('')
  const [genLoading, setGenLoading] = useState(false)

  useEffect(() => {
    supabase.from('ioc_results').select('*').eq('case_id', caseObj.id)
      .order('queried_at', { ascending: false })
      .then(({ data }) => setIocs(data || []))
  }, [caseObj.id])

  async function updateField(field, value) {
    const { error } = await supabase.from('cases')
      .update({ [field]: value, updated_at: new Date().toISOString() })
      .eq('id', c.id)
    if (error) addToast(`Update failed: ${error.message}`, 'error')
    else setC(prev => ({ ...prev, [field]: value, updated_at: new Date().toISOString() }))
  }

  async function updateStatus(newStatus) {
    await updateField('status', newStatus)
    await supabase.from('activity_log').insert({
      action: 'STATUS CHANGE',
      detail: `${c.title} → ${newStatus}`,
      created_at: new Date().toISOString(),
    })
  }

  function addTag(val) {
    const t = val.trim()
    if (!t || (c.tags || []).includes(t)) return
    const newTags = [...(c.tags || []), t]
    updateField('tags', newTags)
    setTagInput('')
  }
  function removeTag(tag) {
    updateField('tags', (c.tags || []).filter(t => t !== tag))
  }

  async function generateReport() {
    setGenLoading(true)
    const reportMd = generateReport(c, iocs, analystName)
    const { error } = await supabase.from('cases')
      .update({ report_md: reportMd, updated_at: new Date().toISOString() })
      .eq('id', c.id)
    if (error) addToast(`Report gen failed: ${error.message}`, 'error')
    else {
      setC(prev => ({ ...prev, report_md: reportMd }))
      addToast('Report generated', 'success')
      await supabase.from('activity_log').insert({
        action: 'REPORT GENERATED',
        detail: `Report for "${c.title}"`,
        created_at: new Date().toISOString(),
      })
    }
    setGenLoading(false)
  }

  function copyReport() {
    if (!c.report_md) { addToast('Generate a report first', 'info'); return }
    navigator.clipboard.writeText(c.report_md)
      .then(() => addToast('Report copied', 'success'))
      .catch(() => addToast('Copy failed', 'error'))
  }

  const label = caseLabel(allCases, c)

  return (
    <div>
      {/* Back button */}
      <button className="back-btn" onClick={onBack}>← CASES</button>

      {/* Header */}
      <div className="page-header" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          {severityBadge(c.severity)}
          <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 12, color: 'var(--gold)' }}>
            {label}
          </span>
          <select className="select" value={c.status || 'OPEN'} onChange={e => updateStatus(e.target.value)}>
            <option value="OPEN">OPEN</option>
            <option value="IN_PROGRESS">IN PROGRESS</option>
            <option value="ESCALATED">ESCALATED</option>
            <option value="CLOSED">CLOSED</option>
          </select>
          <h1 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>{c.title}</h1>
        </div>
      </div>

      {/* Two-column layout */}
      <div className="detail-grid">
        {/* Left — description, notes, tags */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Description */}
          <div className="card">
            <div className="card-header"><span className="card-title card-title-gold">DESCRIPTION</span></div>
            <textarea className="textarea" style={{ minHeight: 100 }}
              defaultValue={c.description || ''}
              placeholder="Add case description..."
              onBlur={e => updateField('description', e.target.value)}
            />
          </div>
          {/* Notes */}
          <div className="card">
            <div className="card-header"><span className="card-title card-title-gold">ANALYST NOTES</span></div>
            <textarea className="textarea" style={{ minHeight: 120 }}
              defaultValue={c.notes || ''}
              placeholder="Add analyst notes..."
              onBlur={e => updateField('notes', e.target.value)}
            />
          </div>
          {/* Tags */}
          <div className="card">
            <div className="card-header"><span className="card-title card-title-gold">TAGS</span></div>
            <div className="tags-row" style={{ marginBottom: 10 }}>
              {(c.tags || []).map((t,i) => (
                <span key={i} className="tag">
                  {t}
                  <button className="tag-remove" onClick={() => removeTag(t)}>×</button>
                </span>
              ))}
            </div>
            <input className="input" value={tagInput} onChange={e=>setTagInput(e.target.value)}
              placeholder="Add tag, press Enter..."
              onKeyDown={e => {
                if (e.key === 'Enter') { e.preventDefault(); addTag(tagInput) }
              }}
              onBlur={() => tagInput.trim() && addTag(tagInput)}
            />
          </div>
        </div>

        {/* Right — metadata, report */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Metadata */}
          <div className="card">
            <div className="card-header"><span className="card-title card-title-gold">CASE METADATA</span></div>
            <div className="geo-row"><span className="geo-label">Case ID</span>
              <span className="geo-value text-mono" style={{ color:'var(--gold)', fontSize:11 }}>{label}</span></div>
            <div className="geo-row"><span className="geo-label">Analyst</span>
              <span className="geo-value">{c.analyst || analystName || '—'}</span></div>
            <div className="geo-row"><span className="geo-label">Created</span>
              <span className="geo-value text-mono" style={{ fontSize:10 }}>{fmtDate(c.created_at)}</span></div>
            <div className="geo-row"><span className="geo-label">Updated</span>
              <span className="geo-value text-mono" style={{ fontSize:10 }}>{fmtDate(c.updated_at)}</span></div>
            <div className="geo-row"><span className="geo-label">IOCs</span>
              <span className="geo-value" style={{ color:'var(--cyan)' }}>{iocs.length}</span></div>
          </div>

          {/* Report actions */}
          <div className="card">
            <div className="card-header"><span className="card-title card-title-gold">REPORT</span></div>
            {c.report_md ? (
              <div style={{ fontSize:11, color:'var(--green)', marginBottom:12 }}>✓ Report generated</div>
            ) : (
              <div style={{ fontSize:11, color:'var(--text-secondary)', marginBottom:12 }}>No report yet</div>
            )}
            <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
              <button className="btn btn-primary" onClick={generateReport} disabled={genLoading}>
                {genLoading ? '⟳ GENERATING...' : '⊞ GENERATE REPORT'}
              </button>
              <button className="btn btn-outline" onClick={copyReport}>⊕ COPY REPORT</button>
            </div>
          </div>
        </div>
      </div>

      {/* IOC Results section */}
      <div className="card">
        <div className="card-header">
          <span className="card-title card-title-gold">IOCs ({iocs.length})</span>
        </div>

        {iocs.length === 0 ? (
          <div className="empty-state" style={{ padding: '24px' }}>
            <span className="empty-title">No IOCs saved to this case</span>
            <span className="empty-sub">Use the Triage page to investigate and save IOCs</span>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>TYPE</th>
                  <th>VALUE</th>
                  <th>VERDICT</th>
                  <th style={{ textAlign:'right' }}>SCORE</th>
                  <th>DATE</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {iocs.map(ioc => (
                  <>
                    <tr key={ioc.id}>
                      <td>{typeBadge(ioc.type)}</td>
                      <td className="td-mono" style={{ maxWidth:200, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', fontSize:11 }}>
                        {ioc.value}
                      </td>
                      <td>{verdictBadge(ioc.verdict)}</td>
                      <td className="td-mono" style={{ textAlign:'right',
                        color: ioc.risk_score >= 70 ? 'var(--red)' :
                               ioc.risk_score >= 35 ? 'var(--orange)' : 'var(--green)'
                      }}>
                        {ioc.risk_score ?? '—'}
                      </td>
                      <td className="td-mono" style={{ fontSize:10, color:'var(--text-secondary)' }}>
                        {fmtDate(ioc.queried_at)}
                      </td>
                      <td>
                        <button className="btn btn-ghost btn-sm"
                          onClick={() => setExpanded(expanded === ioc.id ? null : ioc.id)}>
                          {expanded === ioc.id ? '▲' : '▼'}
                        </button>
                      </td>
                    </tr>
                    {expanded === ioc.id && <IocExpandRow key={`${ioc.id}-exp`} ioc={ioc} />}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

/* ── Cases Page ────────────────────────────────────────────── */
export default function Cases({ settings, addToast }) {
  const [cases, setCases]         = useState([])
  const [iocCounts, setIocCounts] = useState({})
  const [loading, setLoading]     = useState(true)
  const [search, setSearch]       = useState('')
  const [sevFilter, setSevFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [showNew, setShowNew]     = useState(false)
  const [selectedCase, setSelectedCase] = useState(null)

  async function loadCases() {
    setLoading(true)
    const { data, error } = await supabase.from('cases').select('*').order('created_at', { ascending: false })
    if (!error) setCases(data || [])

    // Load IOC counts
    const { data: iocData } = await supabase.from('ioc_results').select('case_id')
    const counts = {}
    ;(iocData || []).forEach(r => {
      if (r.case_id) counts[r.case_id] = (counts[r.case_id] || 0) + 1
    })
    setIocCounts(counts)
    setLoading(false)
  }

  useEffect(() => { loadCases() }, [])

  /* Filtered cases */
  const filtered = cases.filter(c => {
    const q = search.toLowerCase()
    const matchSearch = !q || (c.title||'').toLowerCase().includes(q) || (c.description||'').toLowerCase().includes(q)
    const matchSev    = !sevFilter || c.severity === sevFilter
    const matchStatus = !statusFilter || c.status === statusFilter
    return matchSearch && matchSev && matchStatus
  })

  /* If a case is selected, show detail view */
  if (selectedCase) {
    return (
      <CaseDetail
        caseObj={selectedCase}
        allCases={cases}
        onBack={() => { setSelectedCase(null); loadCases() }}
        addToast={addToast}
        analystName={settings?.analyst_name}
      />
    )
  }

  const sortedForLabel = [...cases].sort((a,b) => new Date(a.created_at) - new Date(b.created_at))

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">CASES</div>
          <div className="page-sub">{cases.length} total cases</div>
        </div>
        <button className="btn btn-primary" onClick={() => setShowNew(true)}>⊕ NEW CASE</button>
      </div>

      {/* Filter bar */}
      <div className="filter-bar">
        <input className="input" style={{ maxWidth: 260 }}
          placeholder="Search cases..." value={search} onChange={e => setSearch(e.target.value)} />
        <select className="select" value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
          <option value="">All Severities</option>
          <option value="P1">P1 — Critical</option>
          <option value="P2">P2 — High</option>
          <option value="P3">P3 — Medium</option>
          <option value="P4">P4 — Low</option>
        </select>
        <select className="select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="IN_PROGRESS">In Progress</option>
          <option value="ESCALATED">Escalated</option>
          <option value="CLOSED">Closed</option>
        </select>
        {(search || sevFilter || statusFilter) && (
          <button className="btn btn-ghost btn-sm" onClick={() => { setSearch(''); setSevFilter(''); setStatusFilter('') }}>
            ✕ Clear
          </button>
        )}
      </div>

      {/* Cases grid */}
      {loading ? (
        <div className="cases-grid">
          {[...Array(4)].map((_,i) => (
            <div key={i} className="card" style={{ height: 180 }}>
              <div className="skeleton" style={{ height: 14, width: '40%', marginBottom: 14 }} />
              <div className="skeleton" style={{ height: 18, width: '75%', marginBottom: 10 }} />
              <div className="skeleton" style={{ height: 12, width: '90%', marginBottom: 6 }} />
              <div className="skeleton" style={{ height: 12, width: '60%' }} />
            </div>
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <div className="empty-state" style={{ marginTop: 40 }}>
          <span className="empty-icon">☰</span>
          <span className="empty-title">{cases.length === 0 ? 'No cases yet' : 'No results match your filters'}</span>
          <span className="empty-sub">
            {cases.length === 0 ? 'Create your first case to get started' : 'Try adjusting your search or filters'}
          </span>
        </div>
      ) : (
        <div className="cases-grid">
          {filtered.map(c => {
            const idx = sortedForLabel.findIndex(x => x.id === c.id)
            const label = `CASE-${String(idx + 1).padStart(3, '0')}`
            return (
              <div key={c.id} className="case-card" onClick={() => setSelectedCase(c)}>
                {/* Header row */}
                <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:10 }}>
                  <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                    {severityBadge(c.severity)}
                    <span style={{ fontFamily:'"JetBrains Mono",monospace', fontSize:11, color:'var(--gold)' }}>
                      {label}
                    </span>
                  </div>
                  <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                    {statusBadge(c.status)}
                    <span style={{ fontSize:10, fontFamily:'"JetBrains Mono",monospace', color:'var(--text-secondary)' }}>
                      {fmtDate(c.created_at)}
                    </span>
                  </div>
                </div>

                {/* Title */}
                <div style={{ fontSize:15, fontWeight:600, marginBottom:8, lineHeight:1.3 }}>
                  {c.title}
                </div>

                {/* Description preview */}
                {c.description && (
                  <div className="line-clamp-2" style={{ fontSize:12, color:'var(--text-secondary)', marginBottom:10, lineHeight:1.5 }}>
                    {c.description}
                  </div>
                )}

                {/* Tags */}
                {(c.tags || []).length > 0 && (
                  <div className="tags-row" style={{ marginBottom:10 }}>
                    {(c.tags||[]).map((t,i) => <span key={i} className="tag">{t}</span>)}
                  </div>
                )}

                {/* Footer */}
                <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginTop:'auto', paddingTop:6 }}>
                  <span style={{ fontSize:11, color:'var(--cyan)', fontFamily:'"JetBrains Mono",monospace' }}>
                    {iocCounts[c.id] || 0} IOCs
                  </span>
                  <button className="btn-link" style={{ fontSize:11 }}
                    onClick={e => { e.stopPropagation(); setSelectedCase(c) }}>
                    OPEN CASE →
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* New case panel */}
      {showNew && (
        <NewCasePanel
          onClose={() => setShowNew(false)}
          onCreated={loadCases}
          addToast={addToast}
          analystName={settings?.analyst_name}
        />
      )}
    </div>
  )
}
