import React, { useState, useEffect } from 'react';
import AlertFeed from './components/AlertFeed';
import ThreatChart from './components/ThreatChart';
import StatusBar from './components/StatusBar';
import PipelineStatus from './components/PipelineStatus';

const SEVERITY_COLOR = {
  ddos:  '#ef4444',   // red
  recon: '#f97316',   // orange
  c2:    '#a855f7',   // purple
};

const THREAT_LABELS = {
  ddos:  'DDoS / SYN Flood',
  recon: 'Recon / Port Scan',
  c2:    'C2 Beaconing',
};

export default function App() {
  const [alerts, setAlerts]   = useState([]);
  const [stats, setStats]     = useState({ ddos: 0, recon: 0, c2: 0, total: 0 });
  const [connected, setConnected] = useState(false);

  // Poll for alerts/stats on an interval. This is the primary,
  // authoritative update path: it re-fetches the full current state from
  // the server every 2s and replaces local state wholesale, so it can't
  // drift or duplicate, and it keeps working even if the SSE connection
  // below stalls (a long-lived EventSource through the dev-server proxy
  // has proven unreliable in practice -- a browser tab's connection can
  // go stale without a clean visible error). The "connected" badge is
  // driven by whether this poll succeeds, not by SSE state, so it
  // actually reflects whether the dashboard is getting live data.
  useEffect(() => {
    const poll = () => {
      Promise.all([
        fetch('/api/alerts').then(r => r.json()),
        fetch('/api/stats').then(r => r.json()),
      ])
        .then(([alertsData, statsData]) => {
          setAlerts(alertsData.slice().reverse());  // newest first
          setStats(statsData);
          setConnected(true);
        })
        .catch(() => setConnected(false));
    };
    poll();
    const id = setInterval(poll, 2000);
    return () => clearInterval(id);
  }, []);

  // SSE is kept as a push-based fast path on top of the polling above --
  // when it's healthy, new alerts can appear sooner than the next poll
  // tick. It is not relied on for correctness.
  useEffect(() => {
    const es = new EventSource('/api/stream');

    es.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'connected') return;

      setAlerts(prev => (prev.some(a => a.flow_id && a.flow_id === data.flow_id)
        ? prev
        : [data, ...prev].slice(0, 200)));
    };

    return () => es.close();
  }, []);

  const clearAlerts = () => {
    fetch('/api/clear', { method: 'POST' })
      .then(() => { setAlerts([]); setStats({ ddos:0,recon:0,c2:0,total:0 }); });
  };

  return (
    <div style={styles.root}>
      {/* Header */}
      <header style={styles.header}>
        <div style={styles.headerLeft}>
          <span style={styles.logo}>◈</span>
          <div>
            <div style={styles.titleRow}>
              <span style={styles.title}>HYBRID 1</span>
              <span style={styles.titleSep}>·</span>
              <span style={styles.titleMid}>Passive Cyber Threat Detection</span>
            </div>
            <span style={styles.subtitle}>
              Unidirectional Network Monitoring Enclave
            </span>
          </div>
        </div>
        <div style={styles.headerRight}>
          <span style={{
            ...styles.badge,
            background: connected ? '#16a34a' : '#dc2626'
          }}>
            {connected ? '● LIVE' : '○ OFFLINE'}
          </span>
          <button style={styles.clearBtn} onClick={clearAlerts}>
            Reset Demo
          </button>
        </div>
      </header>

      {/* Status Bar */}
      <StatusBar stats={stats} connected={connected} />

      {/* Main Grid */}
      <div style={styles.grid}>
        <div style={styles.chartPanel}>
          <PipelineStatus />
          <ThreatChart stats={stats} colors={SEVERITY_COLOR} labels={THREAT_LABELS} />
        </div>
        <div style={styles.feedPanel}>
          <AlertFeed
            alerts={alerts}
            colors={SEVERITY_COLOR}
            labels={THREAT_LABELS}
          />
        </div>
      </div>
    </div>
  );
}

const styles = {
  root: {
    minHeight: '100vh',
    display: 'flex',
    flexDirection: 'column',
    background: '#0a0e1a',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '16px 24px',
    borderBottom: '1px solid #1e293b',
    background: '#0f172a',
  },
  headerLeft: { display: 'flex', alignItems: 'center', gap: '12px' },
  logo: { fontSize: '24px', color: '#3b82f6' },
  titleRow: { display: 'flex', alignItems: 'baseline', gap: '8px' },
  title: { fontSize: '18px', fontWeight: 'bold', color: '#f1f5f9', letterSpacing: '1px' },
  titleSep: { color: '#334155' },
  titleMid: { fontSize: '13px', color: '#94a3b8' },
  subtitle: { fontSize: '12px', color: '#64748b' },
  headerRight: { display: 'flex', alignItems: 'center', gap: '12px' },
  badge: {
    padding: '4px 12px',
    borderRadius: '12px',
    fontSize: '12px',
    fontWeight: 'bold',
    color: '#fff',
  },
  clearBtn: {
    padding: '6px 14px',
    background: '#1e293b',
    color: '#94a3b8',
    border: '1px solid #334155',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '12px',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: '380px 1fr',
    gap: '16px',
    padding: '16px 24px',
    flex: 1,
  },
  chartPanel: { display: 'flex', flexDirection: 'column', gap: '16px' },
  feedPanel: { overflow: 'hidden' },
};
