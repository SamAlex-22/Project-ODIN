import React from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Cell
} from 'recharts';

const PLANNED = ['DGA / DNS Tunneling', 'Malware-in-TLS', 'Exfiltration'];

export default function ThreatChart({ stats, colors, labels }) {
  const data = ['ddos', 'recon', 'c2'].map(key => ({
    name: labels[key],
    count: stats[key] || 0,
    color: colors[key],
  }));

  return (
    <div style={styles.panel}>
      <div style={styles.panelTitle}>Threat Distribution</div>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis
            dataKey="name"
            tick={{ fill: '#64748b', fontSize: 11 }}
            axisLine={false}
          />
          <YAxis
            tick={{ fill: '#64748b', fontSize: 11 }}
            axisLine={false}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              background: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '6px',
              color: '#f1f5f9',
            }}
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {data.map((entry, index) => (
              <Cell key={index} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      {/* Threat class coverage -- no fabricated detections for inactive classes */}
      <div style={styles.coverage}>
        <div style={styles.coverageTitle}>3 / 6 Threat Classes Active</div>
        <div style={styles.coverageRow}>
          {['DDoS', 'Reconnaissance', 'C2 Beaconing'].map(t => (
            <span key={t} style={styles.activeChip}>✓ {t}</span>
          ))}
        </div>
        <div style={styles.coverageRow}>
          {PLANNED.map(t => (
            <span key={t} style={styles.plannedChip}>○ {t}</span>
          ))}
        </div>
        <div style={styles.plannedHint}>Architecture ready -- planned for Phase 2, not currently detected</div>
      </div>

      {/* Why "Hybrid 1": NSM parsing + streaming stateful analysis */}
      <div style={styles.archNote}>
        <div style={styles.archTitle}>Why Hybrid 1</div>
        <div style={styles.layer}>
          <div style={styles.layerName}>NSM Layer</div>
          <div style={styles.layerDesc}>Protocol-aware network telemetry (Zeek)</div>
        </div>
        <div style={styles.layer}>
          <div style={styles.layerName}>Streaming Layer</div>
          <div style={styles.layerDesc}>Cross-flow and temporal state (Kafka + stream processor)</div>
        </div>
        <div style={styles.layer}>
          <div style={styles.layerName}>Detection Layer</div>
          <div style={styles.layerDesc}>Threat-specific behavioral inference (pluggable detectors)</div>
        </div>
      </div>

      {/* Prototype vs production -- never claim this IS the production system */}
      <div style={styles.protoNote}>
        Prototype uses a lightweight Python stateful streaming processor for
        rapid validation. The production architecture can replace this
        processing layer with Apache Flink/Spark without changing the
        normalized event or alert contracts.
      </div>
    </div>
  );
}

const styles = {
  panel: {
    background: '#0f172a',
    border: '1px solid #1e293b',
    borderRadius: '8px',
    padding: '16px',
  },
  panelTitle: {
    fontSize: '13px',
    fontWeight: 'bold',
    color: '#94a3b8',
    marginBottom: '12px',
    textTransform: 'uppercase',
    letterSpacing: '1px',
  },
  coverage: {
    marginTop: '16px',
    padding: '12px',
    background: '#0a0e1a',
    borderRadius: '6px',
    border: '1px solid #1e293b',
  },
  coverageTitle: {
    fontSize: '11px',
    color: '#94a3b8',
    fontWeight: 'bold',
    marginBottom: '8px',
    textTransform: 'uppercase',
    letterSpacing: '1px',
  },
  coverageRow: { display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '4px' },
  activeChip: {
    fontSize: '11px',
    color: '#22c55e',
    background: 'rgba(34,197,94,0.1)',
    border: '1px solid rgba(34,197,94,0.3)',
    borderRadius: '4px',
    padding: '2px 6px',
  },
  plannedChip: {
    fontSize: '11px',
    color: '#64748b',
    background: 'rgba(100,116,139,0.08)',
    border: '1px solid #1e293b',
    borderRadius: '4px',
    padding: '2px 6px',
  },
  plannedHint: { fontSize: '10px', color: '#475569', marginTop: '4px' },
  archNote: {
    marginTop: '12px',
    padding: '12px',
    background: '#0a0e1a',
    borderRadius: '6px',
    border: '1px solid #1e293b',
  },
  archTitle: {
    fontSize: '11px',
    color: '#64748b',
    textTransform: 'uppercase',
    letterSpacing: '1px',
    marginBottom: '10px',
  },
  layer: { marginBottom: '8px' },
  layerName: { fontSize: '12px', color: '#e2e8f0', fontWeight: 'bold' },
  layerDesc: { fontSize: '11px', color: '#94a3b8', marginTop: '1px' },
  protoNote: {
    marginTop: '12px',
    fontSize: '11px',
    color: '#64748b',
    lineHeight: '1.5',
    padding: '10px',
    borderLeft: '2px solid #3b82f6',
    background: 'rgba(59,130,246,0.05)',
  },
};
