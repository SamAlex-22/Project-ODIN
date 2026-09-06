import React, { useEffect, useState } from 'react';

export default function SystemHealth() {
  const [health, setHealth] = useState(null);
  useEffect(() => { fetch('/api/health').then(r => r.json()).then(setHealth); }, []);

  if (!health) return <div>Loading...</div>;

  return (
    <div>
      <h2 style={{borderBottom: '1px solid #1e293b', paddingBottom: '10px', marginBottom: '20px'}}>System & Pipeline Health</h2>
      <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px'}}>
        <div style={styles.card}>
          <div style={styles.row}><span>Pipeline Status:</span> <span style={{color:'#22c55e'}}>{health.status}</span></div>
          <div style={styles.row}><span>One-Way Ingest:</span> <span style={{color:'#22c55e'}}>{health.ingest}</span></div>
          <div style={styles.row}><span>Kafka Transport:</span> <span>{health.kafka}</span></div>
          <div style={styles.row}><span>Flink Processing:</span> <span>{health.flink}</span></div>
          <div style={styles.row}><span>Time-Series DB:</span> <span>{health.database}</span></div>
        </div>
        <div style={styles.card}>
          <div style={styles.row}><span>Throughput:</span> <span>{health.throughput_mbps} Mbps</span></div>
          <div style={styles.row}><span>Detection Latency:</span> <span>{health.latency_ms} ms</span></div>
        </div>
      </div>
    </div>
  );
}
const styles = { 
  card: { background: '#0f172a', padding: '20px', borderRadius: '8px', border: '1px solid #1e293b' },
  row: { display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #1e293b', fontSize: '13px' }
};
