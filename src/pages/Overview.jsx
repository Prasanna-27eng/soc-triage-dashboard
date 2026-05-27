import { useState, useEffect, useRef } from 'react'
import { supabase } from '../supabaseClient.js'

/* ── Helpers ───────────────────────────────────────────────── */
function fmtTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  const hh = String(d.getHours()).padStart(2, '0')
  const mm = String(d.getMinutes()).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  const mo = String(d.getMonth() + 1).padStart(2, '0')
  return `${hh}:${mm} ${dd}/${mo}`
}

function fmtDate(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  return `${String(d.getDate()).padStart(2,'0')}/${String(d.getMonth()+1).padStart(2,'0')}/${d.getFullYear()}`
}

function severityBadge(sev) {
  const map = { P1:'p1', P2:'p2', P3:'p3', P4:'p4' }
  const key = (sev||'').toUpperCase()
  return <span className={`badge badge-${map[key]||'p4'}`}>{key||'—'}</span>
}

function statusBadge(st) {
  const key = (st||'').toLowerCase()
  return <span className={`badge badge-${key}`}>{(st||'—').replace('_',' ')}</span>
}

/* ── SVG Donut Chart ───────────────────────────────────────── */
function DonutChart({ counts }) {
  const CX = 90, CY = 90, R = 68, INNER = R * 0.60
  const data = [
    { label: 'MALICIOUS',  value: counts.malicious,  color: '#cc1833' },
    { label: 'SUSPICIOUS', value: counts.suspicious, color: '#e06020' },
    { label: 'CLEAN',      value: counts.clean,      color: '#00aa5e' },
    { label: 'UNKNOWN',    value: counts.unknown,    color: '#4a6a8a' },
  ]
  const total = data.reduce((s, d) => s + d.value, 0)

  if (total === 0) {
    return (
      <div className="donut-wrap">
        <svg viewBox="0 0 180 180" width="180" height="180">
          <circle cx={CX} cy={CY} r={R} fill="none" stroke="#122034" strokeWidth="18" />
          <text x={CX} y={CY} textAnchor="middle" dominantBaseline="middle" className="gauge-text-big" style={{fontSize:22, fill:'#4a6a8a'}}>0</text>
          <text x={CX} y={CY+20} textAnchor="middle" dominantBaseline="middle" className="gauge-text-small">IOCs</text>
        </svg>
        <div className="donut-legend">
          {data.map(d => (
            <div key={d.label} className="legend-row">
              <div className="legend-dot" style={{ background: d.color }} />
              <span>{d.label}</span>
              <span className="legend-count">0</span>
            </div>
          ))}
        </div>
      </div>
    )
  }

  let angle = -Math.PI / 2
  const arcs = data.map(d => {
    if (d.value === 0) return null
    const sweep = (d.value / total) * 2 * Math.PI
    const start = angle
    angle += sweep
    const end = angle
    const x1 = CX + R * Math.cos(start)
    const y1 = CY + R * Math.sin(start)
    const x2 = CX + R * Math.cos(end)
    const y2 = CY + R * Math.sin(end)
    const xi1 = CX + INNER * Math.cos(start)
    const yi1 = CY + INNER * Math.sin(start)
    const xi2 = CX + INNER * Math.cos(end)
    const yi2 = CY + INNER * Math.sin(end)
    const large = sweep > Math.PI ? 1 : 0
    return {
      d: `M ${x1} ${y1} A ${R} ${R} 0 ${large} 1 ${x2} ${y2} L ${xi2} ${yi2} A ${INNER} ${INNER} 0 ${large} 0 ${xi1} ${yi1} Z`,
      color: d.color,
      label: d.label,
      value: d.value,
    }
  })

  return (
    <div className="donut-wrap">
      <svg viewBox="0 0 180 180" width="180" height="180" style={{ filter: 'drop-shadow(0 0 12px rgba(0,0,0,0.5))' }}>
        {/* Background ring */}
        <circle cx={CX} cy={CY} r={(R + INNER) / 2} fill="none" stroke="#122034" strokeWidth={R - INNER} />
        {/* Arcs */}
        {arcs.map((arc, i) => arc && (
          <path key={i} d={arc.d} fill={arc.color} opacity="0.9" />
        ))}
        {/* Center text */}
        <text x={CX} y={CY - 6} textAnchor="middle" dominantBaseline="middle"
          style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 28, fontWeight: 500, fill: '#c9d8ec' }}>
          {total}
        </text>
        <text x={CX} y={CY + 16} textAnchor="middle" dominantBaseline="middle"
          style={{ fontFamily: 'Oxanium, sans-serif', fontSize: 10, letterSpacing: '0.1em', fill: '#4a6a8a' }}>
          IOCs
        </text>
      </svg>
      <div className="donut-legend">
        {data.map(d => (
          <div key={d.label} className="legend-row">
            <div className="legend-dot" style={{ background: d.color }} />
            <span style={{ fontSize: 11 }}>{d.label}</span>
            <span className="legend-count" style={{ color: d.color }}>{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Overview page ─────────────────────────────────────────── */
export default function Overview({ navigate, addToast }) {
  const [cases, setCases]         = useState([])
  const [iocResults, setIocResults] = useState([])
  const [activity, setActivity]   = useState([])
  const [loading, setLoading]     = useState(true)
  const intervalRef = useRef(null)

  async function loadData() {
    const [casesRes, iocRes, actRes] = await Promise.all([
      supabase.from('cases').select('*').order('created_at', { ascending: false }).limit(10),
      supabase.from('ioc_results').select('id, case_id, verdict, risk_score'),
      supabase.from('activity_log').select('*').order('created_at', { ascending: false }).limit(15),
    ])
    if (!casesRes.error) setCases(casesRes.data || [])
    if (!iocRes.error)   setIocResults(iocRes.data || [])
    if (!actRes.error)   setActivity(actRes.data || [])
    setLoading(false)
  }

  useEffect(() => {
    loadData()
    intervalRef.current = setInterval(() => {
      supabase.from('activity_log').select('*').order('created_at', { ascending: false }).limit(15)
        .then(({ data, error }) => { if (!error) setActivity(data || []) })
    }, 30000)
    return () => clearInterval(intervalRef.current)
  }, [])

  /* ── Computed stats ──────────────────────────────────────── */
  const totalCases  = cases.length
  const openCases   = cases.filter(c => c.status === 'OPEN' || c.status === 'IN_PROGRESS').length
  const totalIOCs   = iocResults.length
  const malicious   = iocResults.filter(r => r.verdict === 'MALICIOUS').length
  const suspicious  = iocResults.filter(r => r.verdict === 'SUSPICIOUS').length
  const clean       = iocResults.filter(r => r.verdict === 'CLEAN').length
  const unknown     = iocResults.filter(r => r.verdict === 'UNKNOWN' || !r.verdict).length
  const scores      = iocResults.map(r => r.risk_score).filter(s => s !== null && s !== undefined)
  const avgScore    = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0

  /* ── IOC count per case ──────────────────────────────────── */
  function iocCount(caseId) {
    return iocResults.filter(r => r.case_id === caseId).length
  }

  /* ── Case ID display ─────────────────────────────────────── */
  function caseIdLabel(c, idx) {
    return `CASE-${String(idx + 1).padStart(3, '0')}`
  }

  const recentCases = [...cases].sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
  const displayCases = [...cases].slice(0, 8)

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">OVERVIEW</div>
          <div className="page-sub">Grand Line Operations Dashboard</div>
        </div>
      </div>

      {/* ── Stat cards ──────────────────────────────────────── */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">TOTAL CASES</div>
          <div className="stat-value">{loading ? '—' : totalCases}</div>
          <div className="stat-sub">{openCases} open / in-progress</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">IOCs TRIAGED</div>
          <div className="stat-value">{loading ? '—' : totalIOCs}</div>
          <div className="stat-sub" style={{ color: 'var(--text-secondary)' }}>across all cases</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">MALICIOUS FOUND</div>
          <div className="stat-value" style={{ color: malicious > 0 ? 'var(--red)' : 'var(--gold)' }}>
            {loading ? '—' : malicious}
          </div>
          <div className="stat-sub" style={{ color: 'var(--red)' }}>
            {suspicious} suspicious
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">AVG RISK SCORE</div>
          <div className="stat-value"
            style={{ color: avgScore >= 70 ? 'var(--red)' : avgScore >= 35 ? 'var(--orange)' : 'var(--green)' }}>
            {loading ? '—' : avgScore}
          </div>
          <div className="stat-sub" style={{ fontFamily: '"JetBrains Mono", monospace' }}>/ 100</div>
        </div>
      </div>

      {/* ── Middle row ──────────────────────────────────────── */}
      <div className="overview-mid">
        {/* Recent cases table */}
        <div className="card">
          <div className="card-header">
            <span className="card-title card-title-gold">RECENT CASES</span>
            <button className="btn btn-ghost btn-sm" onClick={() => navigate('cases')}>VIEW ALL →</button>
          </div>
          <div className="table-wrap">
            {loading ? (
              <div style={{ padding: 20 }}>
                {[...Array(4)].map((_, i) => (
                  <div key={i} className="skeleton" style={{ height: 36, marginBottom: 8 }} />
                ))}
              </div>
            ) : displayCases.length === 0 ? (
              <div className="empty-state">
                <span className="empty-icon">☰</span>
                <span className="empty-title">No cases yet</span>
                <span className="empty-sub">Create a case in the Cases page</span>
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>SEV</th>
                    <th>CASE ID</th>
                    <th>TITLE</th>
                    <th>STATUS</th>
                    <th style={{ textAlign: 'right' }}>IOCs</th>
                    <th>DATE</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {displayCases.map((c, i) => {
                    const idx = recentCases.findIndex(x => x.id === c.id)
                    return (
                      <tr key={c.id}>
                        <td>{severityBadge(c.severity)}</td>
                        <td className="td-mono" style={{ color: 'var(--gold)', fontSize: 11 }}>
                          {caseIdLabel(c, idx)}
                        </td>
                        <td style={{ maxWidth: 180 }}>
                          <div className="truncate" style={{ fontSize: 12 }}>{c.title}</div>
                        </td>
                        <td>{statusBadge(c.status)}</td>
                        <td className="td-mono" style={{ textAlign: 'right', color: 'var(--cyan)' }}>
                          {iocCount(c.id)}
                        </td>
                        <td className="td-mono" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                          {fmtDate(c.created_at)}
                        </td>
                        <td>
                          <button
                            className="btn-link"
                            style={{ fontSize: 11 }}
                            onClick={() => navigate('cases')}
                          >
                            OPEN →
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Verdict donut */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div className="card-header" style={{ width: '100%' }}>
            <span className="card-title card-title-gold">VERDICT SPREAD</span>
          </div>
          {loading ? (
            <div className="skeleton" style={{ width: 180, height: 180, borderRadius: '50%' }} />
          ) : (
            <DonutChart counts={{ malicious, suspicious, clean, unknown }} />
          )}
        </div>
      </div>

      {/* ── Activity feed ───────────────────────────────────── */}
      <div className="card">
        <div className="card-header">
          <span className="card-title card-title-gold">ACTIVITY LOG</span>
          <span style={{ fontSize: 10, color: 'var(--text-secondary)', fontFamily: '"JetBrains Mono", monospace' }}>
            auto-refresh 30s
          </span>
        </div>
        {loading ? (
          <div>
            {[...Array(5)].map((_, i) => (
              <div key={i} className="skeleton" style={{ height: 28, marginBottom: 8 }} />
            ))}
          </div>
        ) : activity.length === 0 ? (
          <div className="empty-state" style={{ padding: '24px' }}>
            <span className="empty-title">No activity yet</span>
          </div>
        ) : (
          <div>
            {activity.map(a => (
              <div key={a.id} className="activity-row">
                <span className="activity-time">{fmtTime(a.created_at)}</span>
                <span className="activity-action">{a.action || 'ACTION'}</span>
                <span className="activity-detail">{a.detail}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
