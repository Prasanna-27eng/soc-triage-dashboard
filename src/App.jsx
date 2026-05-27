import { useState, useEffect, useCallback, useRef } from 'react'
import { supabase } from './supabaseClient.js'
import Overview from './pages/Overview.jsx'
import Triage from './pages/Triage.jsx'
import Cases from './pages/Cases.jsx'
import Reports from './pages/Reports.jsx'
import Settings from './pages/Settings.jsx'

/* ── Deterministic star positions (golden-ratio spread) ───── */
const PHI = 1.6180339887
const STARS = Array.from({ length: 110 }, (_, i) => ({
  left:     `${((i * PHI * 100) % 100).toFixed(2)}%`,
  top:      `${((i * 73.618 + 5) % 63).toFixed(2)}%`,
  size:     i % 15 === 0 ? 2.5 : i % 5 === 0 ? 1.8 : 1,
  dur:      `${(3 + (i * 0.23) % 3.5).toFixed(2)}s`,
  delay:    `${((i * 0.37) % 6).toFixed(2)}s`,
  opLow:    (0.1 + (i % 8) * 0.06).toFixed(2),
  opHigh:   (0.5 + (i % 6) * 0.08).toFixed(2),
}))

/* ── Shooting stars ────────────────────────────────────────── */
const SHOOTERS = [
  { left: '20%', top: '8%',  delay: '4s',  dur: '2.5s' },
  { left: '55%', top: '15%', delay: '11s', dur: '2s'   },
  { left: '78%', top: '5%',  delay: '18s', dur: '3s'   },
  { left: '10%', top: '22%', delay: '26s', dur: '2.2s' },
]

/* ── Animated background component ────────────────────────── */
function AnimatedBackground() {
  return (
    <>
      {/* Star field */}
      {STARS.map((s, i) => (
        <div
          key={i}
          className="star"
          style={{
            left: s.left,
            top: s.top,
            width: `${s.size}px`,
            height: `${s.size}px`,
            '--dur': s.dur,
            '--delay': s.delay,
            '--op-low': s.opLow,
            '--op-high': s.opHigh,
          }}
        />
      ))}

      {/* Shooting stars */}
      {SHOOTERS.map((sh, i) => (
        <div
          key={i}
          className="shooting-star"
          style={{
            left: sh.left,
            top: sh.top,
            animationDelay: sh.delay,
            animationDuration: sh.dur,
          }}
        />
      ))}

      {/* Ocean glow at bottom */}
      <div className="ocean-glow" />

      {/* Wave layers */}
      <div className="wave-container">
        <svg
          viewBox="0 0 2880 120"
          preserveAspectRatio="none"
          style={{ position: 'absolute', bottom: 0, left: 0, height: '100%' }}
        >
          <defs>
            <linearGradient id="wg1" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#009fcc" stopOpacity="0.06" />
              <stop offset="100%" stopColor="#009fcc" stopOpacity="0.01" />
            </linearGradient>
            <linearGradient id="wg2" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#c8a000" stopOpacity="0.03" />
              <stop offset="100%" stopColor="#c8a000" stopOpacity="0" />
            </linearGradient>
          </defs>
          {/* Wave 1 - slower */}
          <g className="wave-svg-inner">
            <path
              d="M0,60 C180,100 360,20 540,60 C720,100 900,20 1080,60 C1260,100 1440,20 1440,60 C1620,100 1800,20 1980,60 C2160,100 2340,20 2520,60 C2700,100 2880,20 2880,60 L2880,120 L0,120 Z"
              fill="url(#wg1)"
            />
          </g>
          {/* Wave 2 - faster */}
          <g className="wave-svg-inner-2" style={{ position: 'absolute', bottom: 0, left: 0, width: '200%', height: '100%' }}>
            <path
              d="M0,80 C240,40 480,120 720,80 C960,40 1200,120 1440,80 C1680,40 1920,120 2160,80 C2400,40 2640,120 2880,80 L2880,120 L0,120 Z"
              fill="url(#wg2)"
            />
          </g>
        </svg>
      </div>

      {/* Scanline overlay */}
      <div className="scanline-overlay" />
    </>
  )
}

/* ── Toast system ──────────────────────────────────────────── */
export function useToast() {
  const [toasts, setToasts] = useState([])
  const addToast = useCallback((message, type = 'info') => {
    const id = Date.now() + Math.random()
    setToasts(prev => [...prev, { id, message, type }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 3200)
  }, [])
  return { toasts, addToast }
}

function ToastContainer({ toasts }) {
  return (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} className={`toast toast-${t.type}`}>
          {t.type === 'success' && '✓ '}
          {t.type === 'error' && '✗ '}
          {t.type === 'info' && '◈ '}
          {t.message}
        </div>
      ))}
    </div>
  )
}

/* ── Nav config ────────────────────────────────────────────── */
const NAV = [
  { id: 'overview',  label: 'OVERVIEW',  icon: '◈' },
  { id: 'triage',    label: 'TRIAGE',    icon: '⊕' },
  { id: 'cases',     label: 'CASES',     icon: '☰' },
  { id: 'reports',   label: 'REPORTS',   icon: '⊞' },
  { id: 'settings',  label: 'SETTINGS',  icon: '⚙' },
]

/* ── Main App ──────────────────────────────────────────────── */
export default function App() {
  const [page, setPage] = useState('overview')
  const [pageKey, setPageKey] = useState(0)
  const [settings, setSettings] = useState(null)
  const { toasts, addToast } = useToast()

  /* ── Navigate ──────────────────────────────────────────── */
  const navigate = useCallback((newPage) => {
    setPage(newPage)
    setPageKey(k => k + 1)
  }, [])

  /* ── Load settings from Supabase on init ───────────────── */
  useEffect(() => {
    async function loadSettings() {
      const { data, error } = await supabase
        .from('settings')
        .select('*')
        .eq('id', 1)
        .maybeSingle()
      if (error) {
        console.warn('Settings load error:', error.message)
        return
      }
      setSettings(data || {})
    }
    loadSettings()
  }, [])

  /* ── Shared props ──────────────────────────────────────── */
  const sharedProps = {
    settings,
    setSettings,
    navigate,
    addToast,
  }

  /* ── Page component ────────────────────────────────────── */
  function PageContent() {
    switch (page) {
      case 'overview': return <Overview {...sharedProps} />
      case 'triage':   return <Triage   {...sharedProps} />
      case 'cases':    return <Cases    {...sharedProps} />
      case 'reports':  return <Reports  {...sharedProps} />
      case 'settings': return <Settings {...sharedProps} />
      default:         return <Overview {...sharedProps} />
    }
  }

  return (
    <>
      {/* Animated background (z-index 0, fixed) */}
      <AnimatedBackground />

      <div className="app-shell">
        {/* ── Sidebar ──────────────────────────────────── */}
        <aside className="sidebar">
          {/* Logo */}
          <div className="sidebar-logo">
            <span className="logo-anchor">⚓</span>
            <div>
              <span className="logo-text">
                SOC TRIAGE
                <span className="logo-sub">GRAND LINE OPS</span>
              </span>
            </div>
          </div>

          {/* Nav */}
          <nav className="sidebar-nav">
            {NAV.map(n => (
              <div
                key={n.id}
                className={`nav-item${page === n.id ? ' active' : ''}`}
                onClick={() => navigate(n.id)}
              >
                <span className="nav-icon">{n.icon}</span>
                {n.label}
              </div>
            ))}
          </nav>

          {/* Footer */}
          <div className="sidebar-footer">
            <span className="analyst-name">
              {settings?.analyst_name || 'ANALYST'}
            </span>
            <div className="live-indicator">
              <div className="live-dot" />
              LIVE
            </div>
          </div>
        </aside>

        {/* ── Main content ─────────────────────────────── */}
        <main className="main-content">
          <div key={pageKey} className="page-fade">
            <PageContent />
          </div>
        </main>
      </div>

      {/* Toasts */}
      <ToastContainer toasts={toasts} />
    </>
  )
}
