import { useState, useEffect } from 'react'
import { supabase } from '../supabaseClient.js'

/* ── Settings Page ─────────────────────────────────────────── */
export default function Settings({ settings, setSettings, addToast }) {
  const [analystName, setAnalystName] = useState(settings?.analyst_name || '')
  const [vtKey, setVtKey]             = useState(settings?.vt_api_key || '')
  const [abuseKey, setAbuseKey]       = useState(settings?.abuseipdb_api_key || '')
  const [urlscanKey, setUrlscanKey]   = useState(settings?.urlscan_api_key || '')

  const [vtStatus, setVtStatus]       = useState('pending')   // pending | testing | ok | fail
  const [abuseStatus, setAbuseStatus] = useState('pending')
  const [urlscanStatus, setUrlscanStatus] = useState('pending')

  const [saving, setSaving] = useState(false)
  const [dbStats, setDbStats] = useState({ cases: 0, iocs: 0, logs: 0 })
  const [clearConfirm, setClearConfirm] = useState('')
  const [clearing, setClearing] = useState(false)
  const [exporting, setExporting] = useState(false)

  /* Sync from prop */
  useEffect(() => {
    if (settings) {
      setAnalystName(settings.analyst_name || '')
      setVtKey(settings.vt_api_key || '')
      setAbuseKey(settings.abuseipdb_api_key || '')
      setUrlscanKey(settings.urlscan_api_key || '')
    }
  }, [settings])

  /* Load DB stats */
  useEffect(() => {
    async function loadStats() {
      const [c, i, l] = await Promise.all([
        supabase.from('cases').select('id', { count: 'exact', head: true }),
        supabase.from('ioc_results').select('id', { count: 'exact', head: true }),
        supabase.from('activity_log').select('id', { count: 'exact', head: true }),
      ])
      setDbStats({
        cases: c.count || 0,
        iocs:  i.count || 0,
        logs:  l.count || 0,
      })
    }
    loadStats()
  }, [])

  /* ── Test API keys ─────────────────────────────────────── */
  async function testVT() {
    if (!vtKey.trim()) return
    setVtStatus('testing')
    try {
      const res = await fetch('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', {
        headers: { 'x-apikey': vtKey.trim() }
      })
      setVtStatus(res.ok ? 'ok' : 'fail')
    } catch { setVtStatus('fail') }
  }

  async function testAbuse() {
    if (!abuseKey.trim()) return
    setAbuseStatus('testing')
    try {
      const res = await fetch('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90', {
        headers: { 'Key': abuseKey.trim(), 'Accept': 'application/json' }
      })
      setAbuseStatus(res.ok ? 'ok' : 'fail')
    } catch { setAbuseStatus('fail') }
  }

  async function testURLScan() {
    if (!urlscanKey.trim()) return
    setUrlscanStatus('testing')
    try {
      const res = await fetch('https://urlscan.io/api/v1/search/?q=8.8.8.8&size=1', {
        headers: { 'API-Key': urlscanKey.trim() }
      })
      setUrlscanStatus(res.ok ? 'ok' : 'fail')
    } catch { setUrlscanStatus('fail') }
  }

  /* ── Save all settings ──────────────────────────────────── */
  async function saveAll() {
    setSaving(true)
    const payload = {
      id: 1,
      analyst_name: analystName.trim() || null,
      vt_api_key: vtKey.trim() || null,
      abuseipdb_api_key: abuseKey.trim() || null,
      urlscan_api_key: urlscanKey.trim() || null,
    }
    const { error } = await supabase.from('settings').upsert(payload, { onConflict: 'id' })
    if (error) {
      addToast(`Save failed: ${error.message}`, 'error')
    } else {
      setSettings(payload)
      await supabase.from('activity_log').insert({
        action: 'SETTINGS SAVED',
        detail: `API keys and analyst profile updated`,
        created_at: new Date().toISOString(),
      })
      addToast('Settings saved', 'success')
    }
    setSaving(false)
  }

  /* ── Save analyst name on blur ──────────────────────────── */
  async function saveAnalystName() {
    if (!analystName.trim()) return
    const { error } = await supabase.from('settings')
      .upsert({ id: 1, analyst_name: analystName.trim() }, { onConflict: 'id' })
    if (!error) {
      setSettings(prev => ({ ...prev, analyst_name: analystName.trim() }))
    }
  }

  /* ── Clear activity log ─────────────────────────────────── */
  async function clearActivityLog() {
    if (clearConfirm !== 'CLEAR') return
    setClearing(true)
    const { error } = await supabase.from('activity_log').delete().neq('id', 0)
    if (error) addToast(`Clear failed: ${error.message}`, 'error')
    else {
      addToast('Activity log cleared', 'success')
      setDbStats(prev => ({ ...prev, logs: 0 }))
    }
    setClearConfirm('')
    setClearing(false)
  }

  /* ── Export all data ────────────────────────────────────── */
  async function exportAll() {
    setExporting(true)
    const [cases, iocs, logs] = await Promise.all([
      supabase.from('cases').select('*'),
      supabase.from('ioc_results').select('*'),
      supabase.from('activity_log').select('*'),
    ])
    const exportData = {
      exported_at: new Date().toISOString(),
      cases: cases.data || [],
      ioc_results: iocs.data || [],
      activity_log: logs.data || [],
    }
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `soc-triage-export-${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)
    addToast('Data exported', 'success')
    setExporting(false)
  }

  /* ── Status indicator ───────────────────────────────────── */
  function StatusIndicator({ status }) {
    const map = {
      pending: { label: '— Not tested', cls: 'status-pending' },
      testing: { label: '⟳ Testing...', cls: 'status-testing' },
      ok:      { label: '✓ Connected',  cls: 'status-ok' },
      fail:    { label: '✗ Failed',     cls: 'status-fail' },
    }
    const s = map[status] || map.pending
    return <span className={`api-status ${s.cls}`}>{s.label}</span>
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">SETTINGS</div>
          <div className="page-sub">Configuration & API Key Management</div>
        </div>
      </div>

      {!settings && (
        <div className="card" style={{ borderColor: 'var(--yellow)', marginBottom: 24 }}>
          <div style={{ color: 'var(--yellow)', fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
            ⚠ First-time setup
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            Configure your Supabase connection and API keys to get started. Make sure your Supabase project
            has the required tables: <span style={{ fontFamily: '"JetBrains Mono", monospace', color: 'var(--cyan)' }}>
              settings, cases, ioc_results, activity_log
            </span>
          </div>
        </div>
      )}

      {/* ── Analyst Profile ─────────────────────────────── */}
      <div className="card settings-section" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <span className="card-title card-title-gold">ANALYST PROFILE</span>
        </div>
        <div style={{ maxWidth: 360 }}>
          <div className="section-label">ANALYST NAME</div>
          <input className="input" value={analystName}
            onChange={e => setAnalystName(e.target.value)}
            onBlur={saveAnalystName}
            placeholder="Enter your analyst name..."
          />
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 6 }}>
            Appears in reports and the sidebar. Saved on blur.
          </div>
        </div>
      </div>

      {/* ── API Keys ─────────────────────────────────────── */}
      <div className="card settings-section" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <span className="card-title card-title-gold">API KEYS</span>
          <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
            Stored in Supabase settings table
          </span>
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 20, lineHeight: 1.6 }}>
          Keys are stored in your Supabase database (not .env). They are loaded on app startup and used
          for direct browser API calls.
        </div>

        {/* VirusTotal */}
        <div style={{ marginBottom: 20 }}>
          <div className="section-label">VIRUSTOTAL</div>
          <div className="api-row">
            <span className="api-label">VT API Key</span>
            <input className="input input-mono" type="password" value={vtKey}
              onChange={e => { setVtKey(e.target.value); setVtStatus('pending') }}
              placeholder="Your VirusTotal API key..." />
            <button className="btn btn-ghost btn-sm" onClick={testVT} disabled={!vtKey.trim() || vtStatus === 'testing'}>
              TEST
            </button>
            <StatusIndicator status={vtStatus} />
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
            Free at <span style={{ color: 'var(--cyan)', fontFamily: '"JetBrains Mono", monospace' }}>
              virustotal.com/gui/join-us
            </span> — 4 requests/min on free tier
          </div>
        </div>

        {/* AbuseIPDB */}
        <div style={{ marginBottom: 20 }}>
          <div className="section-label">ABUSEIPDB</div>
          <div className="api-row">
            <span className="api-label">Abuse API Key</span>
            <input className="input input-mono" type="password" value={abuseKey}
              onChange={e => { setAbuseKey(e.target.value); setAbuseStatus('pending') }}
              placeholder="Your AbuseIPDB API key..." />
            <button className="btn btn-ghost btn-sm" onClick={testAbuse} disabled={!abuseKey.trim() || abuseStatus === 'testing'}>
              TEST
            </button>
            <StatusIndicator status={abuseStatus} />
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
            Free at <span style={{ color: 'var(--cyan)', fontFamily: '"JetBrains Mono", monospace' }}>
              abuseipdb.com
            </span> — IP/IPv6 lookups only (CORS proxy may be needed)
          </div>
        </div>

        {/* URLScan */}
        <div style={{ marginBottom: 24 }}>
          <div className="section-label">URLSCAN.IO</div>
          <div className="api-row">
            <span className="api-label">URLScan Key</span>
            <input className="input input-mono" type="password" value={urlscanKey}
              onChange={e => { setUrlscanKey(e.target.value); setUrlscanStatus('pending') }}
              placeholder="Your URLScan.io API key..." />
            <button className="btn btn-ghost btn-sm" onClick={testURLScan} disabled={!urlscanKey.trim() || urlscanStatus === 'testing'}>
              TEST
            </button>
            <StatusIndicator status={urlscanStatus} />
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
            Free at <span style={{ color: 'var(--cyan)', fontFamily: '"JetBrains Mono", monospace' }}>
              urlscan.io
            </span> — 1000 searches/day
          </div>
        </div>

        <button className="btn btn-primary" onClick={saveAll} disabled={saving}>
          {saving ? '⟳ SAVING...' : '✓ SAVE ALL KEYS'}
        </button>
      </div>

      {/* ── Database ─────────────────────────────────────── */}
      <div className="card settings-section" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <span className="card-title card-title-gold">DATABASE</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 24 }}>
          {[
            { label: 'Cases', value: dbStats.cases, color: 'var(--gold)' },
            { label: 'IOC Results', value: dbStats.iocs, color: 'var(--cyan)' },
            { label: 'Activity Logs', value: dbStats.logs, color: 'var(--text-secondary)' },
          ].map(stat => (
            <div key={stat.label} className="card" style={{ padding: 16, textAlign: 'center' }}>
              <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 28, fontWeight: 500, color: stat.color }}>
                {stat.value}
              </div>
              <div style={{ fontSize: 10, letterSpacing: '0.12em', color: 'var(--text-secondary)', marginTop: 4 }}>
                {stat.label.toUpperCase()}
              </div>
            </div>
          ))}
        </div>

        {/* Clear activity log */}
        <div style={{ marginBottom: 16 }}>
          <div className="section-label">CLEAR ACTIVITY LOG</div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <input className="input" style={{ maxWidth: 200 }}
              value={clearConfirm}
              onChange={e => setClearConfirm(e.target.value)}
              placeholder='Type "CLEAR" to confirm'
            />
            <button className="btn btn-danger" onClick={clearActivityLog}
              disabled={clearConfirm !== 'CLEAR' || clearing}>
              {clearing ? '⟳ CLEARING...' : '✕ CLEAR LOG'}
            </button>
          </div>
        </div>

        {/* Export */}
        <div>
          <div className="section-label">EXPORT ALL DATA</div>
          <button className="btn btn-outline" onClick={exportAll} disabled={exporting}>
            {exporting ? '⟳ EXPORTING...' : '⊞ EXPORT JSON'}
          </button>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 6 }}>
            Downloads all cases, IOC results, and activity logs as JSON
          </div>
        </div>
      </div>

      {/* ── About ────────────────────────────────────────── */}
      <div className="card">
        <div className="card-header">
          <span className="card-title card-title-gold">ABOUT</span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 12 }}>
          <div className="geo-row">
            <span className="geo-label">App</span>
            <span className="geo-value">SOC Triage Dashboard</span>
          </div>
          <div className="geo-row">
            <span className="geo-label">Version</span>
            <span className="geo-value text-mono">1.0.0</span>
          </div>
          <div className="geo-row">
            <span className="geo-label">Stack</span>
            <span className="geo-value">React 18 + Vite + Supabase</span>
          </div>
          <div className="geo-row">
            <span className="geo-label">Theme</span>
            <span className="geo-value">⚓ One Piece Grand Line</span>
          </div>
          <div className="geo-row">
            <span className="geo-label">GitHub</span>
            <span className="geo-value">
              <a href="https://github.com/placeholder/soc-triage-dashboard"
                target="_blank" rel="noreferrer"
                style={{ color: 'var(--cyan)', textDecoration: 'none', fontFamily: '"JetBrains Mono", monospace', fontSize: 11 }}>
                github.com/placeholder/soc-triage-dashboard
              </a>
            </span>
          </div>
        </div>

        <div className="op-rule" style={{ marginTop: 20 }}>
          <span className="op-rule-anchor">⚓</span>
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', textAlign: 'center', fontStyle: 'italic', lineHeight: 1.6 }}>
          "I'm going to be the King of the Pirates" — <span style={{ color: 'var(--gold)' }}>Monkey D. Luffy</span><br />
          "I'm going to catch all the threats" — <span style={{ color: 'var(--cyan)' }}>SOC Analyst</span>
        </div>
      </div>
    </div>
  )
}
