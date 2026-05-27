import { useState, useEffect, useMemo } from 'react'
import { supabase } from '../supabaseClient.js'

/* ── IOC Type Detection ────────────────────────────────────── */
function detectType(value) {
  const v = (value || '').trim()
  if (!v) return null
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'ip'
  if (/^[0-9a-f:]+$/i.test(v) && v.includes(':') && v.split(':').length >= 4) return 'ipv6'
  if (/^https?:\/\//i.test(v)) return 'url'
  if (/^[a-f0-9]{64}$/i.test(v)) return 'sha256'
  if (/^[a-f0-9]{40}$/i.test(v)) return 'sha1'
  if (/^[a-f0-9]{32}$/i.test(v)) return 'md5'
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'email'
  if (/^[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}$/.test(v) && !v.includes('/')) return 'domain'
  return 'unknown'
}

/* ── Country flag helper ───────────────────────────────────── */
const FLAG_MAP = {
  US:'🇺🇸',GB:'🇬🇧',DE:'🇩🇪',FR:'🇫🇷',JP:'🇯🇵',CN:'🇨🇳',RU:'🇷🇺',BR:'🇧🇷',IN:'🇮🇳',CA:'🇨🇦',
  AU:'🇦🇺',NL:'🇳🇱',SG:'🇸🇬',KR:'🇰🇷',SE:'🇸🇪',NO:'🇳🇴',FI:'🇫🇮',CH:'🇨🇭',IT:'🇮🇹',ES:'🇪🇸',
  PL:'🇵🇱',UA:'🇺🇦',TR:'🇹🇷',ID:'🇮🇩',MX:'🇲🇽',ZA:'🇿🇦',NG:'🇳🇬',IR:'🇮🇷',VN:'🇻🇳',TH:'🇹🇭',
  HK:'🇭🇰',TW:'🇹🇼',IL:'🇮🇱',SA:'🇸🇦',AE:'🇦🇪',AR:'🇦🇷',CL:'🇨🇱',RO:'🇷🇴',CZ:'🇨🇿',HU:'🇭🇺',
}
function countryFlag(code) {
  return FLAG_MAP[(code||'').toUpperCase()] || '🌐'
}

/* ── Risk score calculation ────────────────────────────────── */
function calcRiskScore(vtData, abuseData, urlscanData) {
  let score = 0, weight = 0
  if (vtData && vtData.total > 0) {
    score += (vtData.malicious / vtData.total) * 100 * 0.5
    weight += 0.5
  }
  if (abuseData && abuseData.score !== null && abuseData.score !== undefined) {
    score += abuseData.score * 0.3
    weight += 0.3
  }
  if (urlscanData && urlscanData.score !== null && urlscanData.score !== undefined) {
    score += (urlscanData.score / 10) * 0.2
    weight += 0.2
  }
  if (weight === 0) return null
  return Math.round(Math.min(100, Math.max(0, score / weight)))
}

function getVerdict(score) {
  if (score === null || score === undefined) return 'UNKNOWN'
  if (score >= 70) return 'MALICIOUS'
  if (score >= 35) return 'SUSPICIOUS'
  return 'CLEAN'
}

/* ── SVG Risk Gauge ────────────────────────────────────────── */
function RiskGauge({ score, verdict }) {
  const CX = 90, CY = 90, R = 70
  const circ = 2 * Math.PI * R
  const dash = score !== null ? (score / 100) * circ : 0
  const gap  = circ - dash

  const color =
    verdict === 'MALICIOUS'  ? '#cc1833' :
    verdict === 'SUSPICIOUS' ? '#e06020' :
    verdict === 'CLEAN'      ? '#00aa5e' : '#4a6a8a'

  return (
    <svg viewBox="0 0 180 180" width="180" height="180">
      {/* Glow filter */}
      <defs>
        <filter id="gaugeGlow">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>
      {/* Background track */}
      <circle cx={CX} cy={CY} r={R} fill="none" stroke="#122034" strokeWidth="10" />
      {/* Score arc */}
      {score !== null && (
        <circle
          cx={CX} cy={CY} r={R}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={`${dash} ${gap}`}
          strokeLinecap="round"
          transform={`rotate(-90 ${CX} ${CY})`}
          style={{ filter: `drop-shadow(0 0 6px ${color}66)`, transition: 'stroke-dasharray 600ms ease' }}
        />
      )}
      {/* Score text */}
      <text x={CX} y={CY - 6} textAnchor="middle" dominantBaseline="middle"
        style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 32, fontWeight: 500, fill: color }}>
        {score !== null ? score : '?'}
      </text>
      <text x={CX} y={CY + 16} textAnchor="middle"
        style={{ fontFamily: 'Oxanium, sans-serif', fontSize: 11, letterSpacing: '0.12em', fill: '#4a6a8a' }}>
        / 100
      </text>
    </svg>
  )
}

/* ── Skeleton cards ────────────────────────────────────────── */
function SkeletonCards() {
  return (
    <div className="result-row">
      {[0,1,2].map(i => (
        <div key={i} className="card" style={{ minHeight: 280 }}>
          <div className="skeleton" style={{ height: 16, width: '60%', marginBottom: 20 }} />
          <div className="skeleton" style={{ height: 180, marginBottom: 16 }} />
          <div className="skeleton" style={{ height: 12, width: '80%', marginBottom: 8 }} />
          <div className="skeleton" style={{ height: 12, width: '50%' }} />
        </div>
      ))}
    </div>
  )
}

/* ── Report text generator ─────────────────────────────────── */
function buildReport(value, type, verdict, score, vtData, abuseData, urlscanData, analystName, caseTitle) {
  const now = new Date().toLocaleString()
  const rec =
    score >= 70 ? 'BLOCK — High confidence malicious. Immediate firewall block recommended. Escalate to L2.' :
    score >= 35 ? 'MONITOR — Suspicious indicators present. Add to watchlist. Correlate with other alerts.' :
    'CLEAN — No significant detections. Continue standard monitoring.'

  return `IOC TRIAGE REPORT
═══════════════════════════════
IOC     : ${value}
TYPE    : ${(type||'').toUpperCase()}
DATE    : ${now}
ANALYST : ${analystName || 'ANALYST'}
CASE    : ${caseTitle || 'Standalone'}
VERDICT : ${verdict}
RISK    : ${score !== null ? score : 'N/A'}/100
═══════════════════════════════

VIRUSTOTAL
Detections : ${vtData ? `${vtData.malicious}/${vtData.total} engines` : 'N/A'}
Votes      : ${vtData ? `${vtData.communityUp} clean / ${vtData.communityDown} malicious` : 'N/A'}
Families   : ${vtData?.families?.length ? vtData.families.join(', ') : 'None identified'}
Tags       : ${vtData?.tags?.length ? vtData.tags.join(', ') : 'None'}

ABUSEIPDB
Confidence : ${abuseData ? `${abuseData.score}%` : 'N/A'}
Reports    : ${abuseData?.reports ?? 'N/A'}
Country    : ${abuseData?.country || 'N/A'}
ISP        : ${abuseData?.isp || 'N/A'}
Usage      : ${abuseData?.usageType || 'N/A'}

URLSCAN
Score      : ${urlscanData ? `${urlscanData.score}/100` : 'N/A'}
Tags       : ${urlscanData?.tags?.join(', ') || 'None'}
Report     : ${urlscanData?.link || 'N/A'}

RECOMMENDATION
${rec}

ANALYST NOTES
[Add notes here]`
}

/* ── Triage Page ───────────────────────────────────────────── */
export default function Triage({ settings, addToast }) {
  const [input, setInput]         = useState('')
  const [selectedCase, setSelectedCase] = useState('')
  const [cases, setCases]         = useState([])
  const [loading, setLoading]     = useState(false)
  const [results, setResults]     = useState(null)
  const [saveLoading, setSaveLoading] = useState(false)

  const type    = useMemo(() => detectType(input), [input])
  const apiKeys = settings || {}
  const hasKeys = !!(apiKeys.vt_api_key || apiKeys.abuseipdb_api_key || apiKeys.urlscan_api_key)

  /* Load open cases for the selector */
  useEffect(() => {
    supabase.from('cases')
      .select('id, title, status')
      .in('status', ['OPEN','IN_PROGRESS'])
      .order('created_at', { ascending: false })
      .then(({ data }) => setCases(data || []))
  }, [])

  /* ── VirusTotal call ───────────────────────────────────── */
  async function callVT(value, iocType, key) {
    if (!key) return null
    const base = 'https://www.virustotal.com/api/v3'
    const headers = { 'x-apikey': key }
    try {
      let res
      if (iocType === 'ip' || iocType === 'ipv6') {
        res = await fetch(`${base}/ip_addresses/${encodeURIComponent(value)}`, { headers })
      } else if (iocType === 'domain') {
        res = await fetch(`${base}/domains/${encodeURIComponent(value)}`, { headers })
      } else if (iocType === 'url') {
        const fd = new FormData()
        fd.append('url', value)
        const submitRes = await fetch(`${base}/urls`, { method: 'POST', headers, body: fd })
        if (!submitRes.ok) return null
        // encode the URL for lookup
        const encoded = btoa(value).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
        await new Promise(r => setTimeout(r, 1200)) // brief wait
        res = await fetch(`${base}/urls/${encoded}`, { headers })
      } else if (iocType === 'md5' || iocType === 'sha1' || iocType === 'sha256') {
        res = await fetch(`${base}/files/${value}`, { headers })
      } else {
        return null
      }
      if (!res.ok) return null
      const json = await res.json()
      const attr = json?.data?.attributes || {}
      const stats = attr.last_analysis_stats || {}
      const votes = attr.total_votes || {}
      const threat = attr.popular_threat_classification || {}
      const tags   = attr.tags || []
      const families = threat.suggested_threat_label ? [threat.suggested_threat_label] : []
      const total = (stats.malicious||0) + (stats.suspicious||0) + (stats.harmless||0) + (stats.undetected||0)
      return {
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
        total,
        communityUp: votes.harmless || 0,
        communityDown: votes.malicious || 0,
        families,
        tags,
        lastDate: attr.last_analysis_date ? new Date(attr.last_analysis_date * 1000).toLocaleDateString() : null,
        raw: json,
      }
    } catch {
      return null
    }
  }

  /* ── AbuseIPDB call ────────────────────────────────────── */
  async function callAbuse(value, iocType, key) {
    if (!key || !['ip','ipv6'].includes(iocType)) return null
    try {
      const params = new URLSearchParams({ ipAddress: value, maxAgeInDays: 90, verbose: true })
      const res = await fetch(`https://api.abuseipdb.com/api/v2/check?${params}`, {
        headers: { 'Key': key, 'Accept': 'application/json' }
      })
      if (!res.ok) return null
      const json = await res.json()
      const d = json?.data || {}
      return {
        score: d.abuseConfidenceScore ?? null,
        reports: d.totalReports ?? 0,
        country: d.countryCode || null,
        isp: d.isp || null,
        usageType: d.usageType || null,
        isWhitelisted: d.isWhitelisted || false,
        raw: json,
      }
    } catch {
      return null
    }
  }

  /* ── URLScan call ──────────────────────────────────────── */
  async function callURLScan(value, iocType, key) {
    if (!key) return null
    try {
      const q = encodeURIComponent(value)
      const searchRes = await fetch(`https://urlscan.io/api/v1/search/?q=${q}&size=3`, {
        headers: { 'API-Key': key }
      })
      if (!searchRes.ok) return null
      const searchJson = await searchRes.json()
      const results = searchJson?.results || []
      if (results.length === 0) return { score: null, tags: [], link: null, raw: searchJson }
      const uuid = results[0]?.task?.uuid
      if (!uuid) return null
      const detailRes = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`, {
        headers: { 'API-Key': key }
      })
      if (!detailRes.ok) return null
      const detail = await detailRes.json()
      const verdicts = detail?.verdicts?.overall || {}
      const page = detail?.page || {}
      return {
        score: verdicts.score ?? null,
        tags: verdicts.tags || [],
        malicious: verdicts.malicious || false,
        country: page.country || null,
        asn: page.asn || null,
        isp: page.asnname || null,
        link: `https://urlscan.io/result/${uuid}/`,
        raw: detail,
      }
    } catch {
      return null
    }
  }

  /* ── Main investigate handler ──────────────────────────── */
  async function investigate() {
    const val = input.trim()
    if (!val || !type || type === 'unknown') return
    setLoading(true)
    setResults(null)

    const [vtResult, abuseResult, urlscanResult] = await Promise.allSettled([
      callVT(val, type, apiKeys.vt_api_key),
      callAbuse(val, type, apiKeys.abuseipdb_api_key),
      callURLScan(val, type, apiKeys.urlscan_api_key),
    ])

    const vtData      = vtResult.status === 'fulfilled'      ? vtResult.value      : null
    const abuseData   = abuseResult.status === 'fulfilled'   ? abuseResult.value   : null
    const urlscanData = urlscanResult.status === 'fulfilled' ? urlscanResult.value : null

    const score   = calcRiskScore(vtData, abuseData, urlscanData)
    const verdict = getVerdict(score)

    // Geo from available source
    const geo = {
      country: abuseData?.country || urlscanData?.country || null,
      asn:     urlscanData?.asn || null,
      isp:     abuseData?.isp || urlscanData?.isp || null,
    }

    setResults({ val, type, score, verdict, geo, vtData, abuseData, urlscanData })
    setLoading(false)

    // Log activity
    await supabase.from('activity_log').insert({
      action: 'TRIAGE',
      detail: `Investigated ${type?.toUpperCase()} — ${val} — Verdict: ${verdict} (${score ?? 'N/A'}/100)`,
      created_at: new Date().toISOString(),
    })
  }

  /* ── Save to case ──────────────────────────────────────── */
  async function saveToCase() {
    if (!results) return
    const { val, type, score, verdict, geo, vtData, abuseData, urlscanData } = results
    setSaveLoading(true)
    const row = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2,8)}`,
      case_id: selectedCase || null,
      value: val,
      type,
      queried_at: new Date().toISOString(),
      risk_score: score,
      verdict,
      geo_country: geo.country,
      asn: geo.asn,
      isp: geo.isp,
      vt_malicious: vtData?.malicious ?? null,
      vt_total: vtData?.total ?? null,
      vt_community_up: vtData?.communityUp ?? null,
      vt_community_down: vtData?.communityDown ?? null,
      malware_families: vtData?.families || [],
      tags: vtData?.tags || [],
      abuseipdb_score: abuseData?.score ?? null,
      abuseipdb_reports: abuseData?.reports ?? null,
      urlscan_score: urlscanData?.score ?? null,
      urlscan_tags: urlscanData?.tags || [],
      urlscan_link: urlscanData?.link || null,
      raw_vt: vtData?.raw || null,
      raw_abuseipdb: abuseData?.raw || null,
      raw_urlscan: urlscanData?.raw || null,
    }
    const { error } = await supabase.from('ioc_results').insert(row)
    if (error) {
      addToast(`Save failed: ${error.message}`, 'error')
    } else {
      await supabase.from('activity_log').insert({
        action: 'IOC SAVED',
        detail: `${type?.toUpperCase()} ${val} → ${verdict} saved to case`,
        created_at: new Date().toISOString(),
      })
      addToast('IOC saved to case', 'success')
    }
    setSaveLoading(false)
  }

  /* ── Copy report ───────────────────────────────────────── */
  function copyReport() {
    if (!results) return
    const caseObj = cases.find(c => c.id === selectedCase)
    const text = buildReport(
      results.val, results.type, results.verdict, results.score,
      results.vtData, results.abuseData, results.urlscanData,
      settings?.analyst_name, caseObj?.title
    )
    navigator.clipboard.writeText(text).then(() => addToast('Report copied', 'success'))
      .catch(() => addToast('Copy failed', 'error'))
  }

  /* ── Pct bar ───────────────────────────────────────────── */
  function PctBar({ label, count, total, color }) {
    const pct = total > 0 ? (count / total) * 100 : 0
    return (
      <div className="pct-bar-wrap">
        <span className="pct-bar-label">{label}</span>
        <div className="pct-bar-track">
          <div className="pct-bar-fill" style={{ width: `${Math.max(count>0?1:0, pct)}%`, background: color }} />
        </div>
        <span className="pct-bar-count">{count}</span>
      </div>
    )
  }

  /* ── Render ────────────────────────────────────────────── */
  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">TRIAGE</div>
          <div className="page-sub">IOC Enrichment & Threat Intelligence</div>
        </div>
      </div>

      {/* Input section */}
      <div className="card" style={{ marginBottom: 24 }}>
        <input
          className="ioc-input"
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="Paste IP, domain, URL, hash, or email..."
          onKeyDown={e => e.key === 'Enter' && !loading && hasKeys && type && type !== 'unknown' && investigate()}
        />
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 14, flexWrap: 'wrap' }}>
          {/* Type badge */}
          <span style={{ minWidth: 80 }}>
            {input.trim() ? (
              type && type !== 'unknown'
                ? <span className={`badge badge-${['md5','sha1','sha256'].includes(type) ? 'hash' : type}`}>
                    {type?.toUpperCase()}
                  </span>
                : <span className="badge badge-unknown">UNKNOWN</span>
            ) : (
              <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>— type</span>
            )}
          </span>

          {/* Case selector */}
          <select className="select" value={selectedCase} onChange={e => setSelectedCase(e.target.value)}
            style={{ minWidth: 180 }}>
            <option value="">Standalone (no case)</option>
            {cases.map(c => (
              <option key={c.id} value={c.id}>{c.title}</option>
            ))}
          </select>

          <button
            className="btn btn-primary"
            onClick={investigate}
            disabled={loading || !hasKeys || !input.trim() || !type || type === 'unknown'}
            style={{ marginLeft: 'auto' }}
          >
            {loading ? '⟳ SCANNING...' : '⊕ INVESTIGATE'}
          </button>

          {!hasKeys && (
            <span style={{ fontSize: 11, color: 'var(--orange)' }}>
              ⚠ Configure API keys in Settings
            </span>
          )}
        </div>
      </div>

      {/* Loading skeleton */}
      {loading && <SkeletonCards />}

      {/* Results */}
      {!loading && results && (
        <div className="result-row">

          {/* ── Card 1: Risk Overview ──────────────────────── */}
          <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="card-header">
              <span className="card-title card-title-gold">RISK OVERVIEW</span>
              <span className={`badge badge-${results.verdict.toLowerCase()}`}>{results.verdict}</span>
            </div>

            {/* Gauge */}
            <div style={{ display: 'flex', justifyContent: 'center' }}>
              <RiskGauge score={results.score} verdict={results.verdict} />
            </div>

            {/* Geo */}
            <div style={{ marginTop: 4 }}>
              <div className="section-label" style={{ fontSize: 9 }}>GEO</div>
              <div className="geo-row">
                <span className="geo-label">Country</span>
                <span className="geo-value">
                  {results.geo.country
                    ? `${countryFlag(results.geo.country)} ${results.geo.country}`
                    : '—'}
                </span>
              </div>
              <div className="geo-row">
                <span className="geo-label">ASN</span>
                <span className="geo-value">{results.geo.asn || '—'}</span>
              </div>
              <div className="geo-row">
                <span className="geo-label">ISP</span>
                <span className="geo-value">{results.geo.isp || '—'}</span>
              </div>
            </div>

            {/* Actions */}
            <div style={{ display: 'flex', gap: 8, marginTop: 'auto' }}>
              <button className="btn btn-primary" style={{ flex: 1 }}
                onClick={saveToCase} disabled={saveLoading}>
                {saveLoading ? '⟳ SAVING...' : '✓ SAVE TO CASE'}
              </button>
              <button className="btn btn-outline" onClick={copyReport}>⊕ COPY</button>
            </div>
          </div>

          {/* ── Card 2: VirusTotal ─────────────────────────── */}
          <div className="card relative">
            {!results.vtData && (
              <div className="unavailable-overlay">⊘ UNAVAILABLE</div>
            )}
            <div className="card-header">
              <span className="card-title card-title-gold">VIRUSTOTAL</span>
              {results.vtData?.lastDate && (
                <span style={{ fontSize: 10, fontFamily: '"JetBrains Mono", monospace', color: 'var(--text-secondary)' }}>
                  {results.vtData.lastDate}
                </span>
              )}
            </div>

            {results.vtData ? (
              <>
                {/* Detection count */}
                <div style={{ textAlign: 'center', margin: '12px 0 20px' }}>
                  <span style={{
                    fontFamily: '"JetBrains Mono", monospace',
                    fontSize: 36,
                    fontWeight: 500,
                    color: results.vtData.malicious > 0 ? 'var(--red)' : 'var(--green)',
                  }}>
                    {results.vtData.malicious}
                  </span>
                  <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 20, color: 'var(--text-secondary)' }}>
                    {' / '}{results.vtData.total}
                  </span>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)', letterSpacing: '0.1em', marginTop: 4 }}>
                    ENGINES
                  </div>
                </div>

                {/* Bars */}
                <PctBar label="Malicious"  count={results.vtData.malicious}  total={results.vtData.total} color="var(--red)" />
                <PctBar label="Suspicious" count={results.vtData.suspicious} total={results.vtData.total} color="var(--orange)" />
                <PctBar label="Harmless"   count={results.vtData.harmless}   total={results.vtData.total} color="var(--green)" />
                <PctBar label="Undetected" count={results.vtData.undetected} total={results.vtData.total} color="var(--text-secondary)" />

                {/* Community votes */}
                <div style={{ marginTop: 12 }}>
                  <div className="section-label" style={{ fontSize: 9 }}>COMMUNITY VOTES</div>
                  <div className="vote-row">
                    <span>👎 {results.vtData.communityDown} malicious</span>
                    <span>👍 {results.vtData.communityUp} clean</span>
                  </div>
                </div>

                {/* Malware families */}
                {results.vtData.families.length > 0 && (
                  <div style={{ marginTop: 12 }}>
                    <div className="section-label" style={{ fontSize: 9 }}>MALWARE FAMILIES</div>
                    <div className="tags-row">
                      {results.vtData.families.slice(0,5).map((f,i) => (
                        <span key={i} className="family-pill">{f}</span>
                      ))}
                      {results.vtData.families.length > 5 && (
                        <span className="family-pill">+{results.vtData.families.length - 5} more</span>
                      )}
                    </div>
                  </div>
                )}

                {/* Tags */}
                {results.vtData.tags.length > 0 && (
                  <div style={{ marginTop: 10 }}>
                    <div className="tags-row">
                      {results.vtData.tags.slice(0,6).map((t,i) => (
                        <span key={i} className="tag">{t}</span>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div style={{ height: 200 }} />
            )}
          </div>

          {/* ── Card 3: AbuseIPDB + URLScan ───────────────── */}
          <div className="card">
            {/* AbuseIPDB */}
            <div className="card-header" style={{ marginBottom: 12 }}>
              <span className="card-title card-title-gold">ABUSEIPDB</span>
            </div>

            {['ip','ipv6'].includes(results.type) ? (
              results.abuseData ? (
                <>
                  {/* Confidence bar */}
                  <div className="conf-bar-wrap">
                    <div className="conf-bar-header">
                      <span className="conf-bar-label">Confidence Score</span>
                      <span className="conf-bar-value" style={{
                        color: results.abuseData.score >= 70 ? 'var(--red)' :
                               results.abuseData.score >= 30 ? 'var(--orange)' : 'var(--green)'
                      }}>
                        {results.abuseData.score}%
                      </span>
                    </div>
                    <div className="conf-bar-track">
                      <div className="conf-bar-fill" style={{
                        width: `${results.abuseData.score}%`,
                        background: results.abuseData.score >= 70 ? 'var(--red)' :
                                    results.abuseData.score >= 30 ? 'var(--orange)' : 'var(--green)'
                      }} />
                    </div>
                  </div>

                  <div className="geo-row"><span className="geo-label">Reports</span>
                    <span className="geo-value">{results.abuseData.reports}</span></div>
                  <div className="geo-row"><span className="geo-label">Country</span>
                    <span className="geo-value">
                      {results.abuseData.country
                        ? `${countryFlag(results.abuseData.country)} ${results.abuseData.country}`
                        : '—'}
                    </span></div>
                  <div className="geo-row"><span className="geo-label">ISP</span>
                    <span className="geo-value">{results.abuseData.isp || '—'}</span></div>
                  <div className="geo-row"><span className="geo-label">Usage</span>
                    <span className="geo-value">{results.abuseData.usageType || '—'}</span></div>
                </>
              ) : (
                <div style={{ padding: '12px 0', color: 'var(--text-secondary)', fontSize: 12 }}>
                  ⊘ Data unavailable
                </div>
              )
            ) : (
              <div style={{ padding: '10px 0', fontSize: 11, color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                NOT APPLICABLE FOR {(results.type || '').toUpperCase()}
              </div>
            )}

            <div className="divider" />

            {/* URLScan */}
            <div className="card-header" style={{ marginBottom: 12 }}>
              <span className="card-title card-title-gold">URLSCAN.IO</span>
            </div>

            {results.urlscanData ? (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                  <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 24, fontWeight: 500,
                    color: results.urlscanData.score !== null
                      ? (results.urlscanData.score >= 70 ? 'var(--red)' : results.urlscanData.score >= 35 ? 'var(--orange)' : 'var(--green)')
                      : 'var(--text-secondary)'
                  }}>
                    {results.urlscanData.score ?? '—'}
                  </span>
                  <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>/100</span>
                  {results.urlscanData.malicious && (
                    <span className="badge badge-malicious">MALICIOUS</span>
                  )}
                </div>

                {results.urlscanData.tags.length > 0 && (
                  <div className="tags-row" style={{ marginBottom: 10 }}>
                    {results.urlscanData.tags.map((t,i) => (
                      <span key={i} className="tag">{t}</span>
                    ))}
                  </div>
                )}

                {results.urlscanData.link && (
                  <a className="urlscan-link" href={results.urlscanData.link} target="_blank" rel="noreferrer">
                    VIEW FULL SCAN →
                  </a>
                )}
              </>
            ) : (
              <div style={{ padding: '10px 0', color: 'var(--text-secondary)', fontSize: 12 }}>
                ⊘ Data unavailable
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
