import React, { useEffect, useMemo, useRef, useState } from 'react'

const HTTP_BASE = import.meta.env.VITE_BACKEND_HTTP || 'http://localhost:8000'
const WS_URL = import.meta.env.VITE_BACKEND_WS || 'ws://localhost:8000/ws/alerts'

function severityColor(sev) {
  switch ((sev || '').toLowerCase()) {
    case 'critical':
      return '#7f1d1d'
    case 'high':
      return '#9a3412'
    case 'medium':
      return '#92400e'
    case 'low':
      return '#1f2937'
    default:
      return '#111827'
  }
}

export default function App() {
  const [connected, setConnected] = useState(false)
  const [alerts, setAlerts] = useState([])
  const wsRef = useRef(null)

  useEffect(() => {
    fetch(`${HTTP_BASE}/alerts?limit=200`)
      .then(r => r.json())
      .then(data => {
        setAlerts((data.items || []).slice().reverse())
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    const ws = new WebSocket(WS_URL)
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      // keep-alive for servers that expect client messages
      const t = setInterval(() => {
        try { ws.send('ping') } catch {}
      }, 25000)
      ws._pingTimer = t
    }

    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data)
        setAlerts(prev => {
          const next = [...prev, msg]
          return next.length > 500 ? next.slice(next.length - 500) : next
        })
      } catch {
        // ignore
      }
    }

    ws.onclose = () => {
      setConnected(false)
      if (ws._pingTimer) clearInterval(ws._pingTimer)
    }

    ws.onerror = () => {
      setConnected(false)
    }

    return () => {
      try { ws.close() } catch {}
    }
  }, [])

  const stats = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 }
    const bySrc = new Map()
    for (const a of alerts) {
      const sev = (a.severity || '').toLowerCase()
      if (counts[sev] !== undefined) counts[sev] += 1
      const src = a.src_ip || 'unknown'
      bySrc.set(src, (bySrc.get(src) || 0) + 1)
    }
    const top = [...bySrc.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)
    return { counts, top }
  }, [alerts])

  return (
    <div style={{ fontFamily: 'system-ui, -apple-system, Segoe UI, Roboto, sans-serif', padding: 16 }}>
      <h1 style={{ margin: 0 }}>AI Anomaly IDS Dashboard</h1>
      <div style={{ marginTop: 6, color: '#374151' }}>
        Status: <b>{connected ? 'WebSocket connected' : 'disconnected'}</b>
      </div>

      <div style={{ display: 'flex', gap: 12, marginTop: 16, flexWrap: 'wrap' }}>
        {Object.entries(stats.counts).map(([sev, n]) => (
          <div key={sev} style={{ border: '1px solid #e5e7eb', borderRadius: 10, padding: 12, minWidth: 140 }}>
            <div style={{ color: '#6b7280', textTransform: 'capitalize' }}>{sev}</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: severityColor(sev) }}>{n}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 16 }}>
        <div style={{ border: '1px solid #e5e7eb', borderRadius: 10, padding: 12 }}>
          <h3 style={{ marginTop: 0 }}>Top Attacker IPs</h3>
          <ol style={{ margin: 0, paddingLeft: 18 }}>
            {stats.top.map(([ip, n]) => (
              <li key={ip} style={{ margin: '6px 0' }}>
                <b>{ip}</b> — {n}
              </li>
            ))}
          </ol>
        </div>

        <div style={{ border: '1px solid #e5e7eb', borderRadius: 10, padding: 12 }}>
          <h3 style={{ marginTop: 0 }}>Live Alerts</h3>
          <div style={{ maxHeight: 420, overflow: 'auto', fontSize: 13 }}>
            {alerts.slice().reverse().map((a) => (
              <div key={a.alert_id || Math.random()} style={{ borderBottom: '1px solid #f3f4f6', padding: '8px 0' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
                  <div>
                    <b style={{ color: severityColor(a.severity) }}>{(a.severity || 'unknown').toUpperCase()}</b>
                    <span style={{ marginLeft: 8 }}>{a.label || 'unknown'}</span>
                  </div>
                  <div style={{ color: '#6b7280' }}>{a.created_at ? new Date(a.created_at).toLocaleString() : ''}</div>
                </div>
                <div style={{ color: '#374151', marginTop: 4 }}>
                  {a.src_ip}:{a.src_port} → {a.dst_ip}:{a.dst_port} ({a.protocol})
                </div>
                {a.geoip?.country_name ? (
                  <div style={{ color: '#6b7280', marginTop: 2 }}>
                    GeoIP: {a.geoip.city_name ? `${a.geoip.city_name}, ` : ''}{a.geoip.country_name}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
