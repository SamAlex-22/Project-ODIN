import React from 'react';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#a855f7', '#14b8a6'];

export default function ThreatDistribution({ stats }) {
  const data = ['ddos', 'c2', 'recon', 'dga', 'malware', 'exfiltration']
    .map(t => ({ name: t.toUpperCase(), value: stats[t] || 0 }))
    .filter(d => d.value > 0);

  return (
    <div>
      <h2 style={{borderBottom: '1px solid #1e293b', paddingBottom: '10px', marginBottom: '20px'}}>Threat Distribution</h2>
      
      <div style={{display: 'flex', gap: '40px', alignItems: 'flex-start'}}>
        <div style={{flex: 1, height: '400px', background: '#0f172a', borderRadius: '8px', padding: '20px', border: '1px solid #1e293b'}}>
          {data.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={data} cx="50%" cy="50%" innerRadius={80} outerRadius={120} paddingAngle={5} dataKey="value">
                  {data.map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{background: '#1e293b', border: 'none', borderRadius: '4px', color: '#f1f5f9'}} />
                <Legend verticalAlign="bottom" height={36} iconType="circle" />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: '#64748b'}}>
              No threats detected yet.
            </div>
          )}
        </div>

        <div style={{flex: 1}}>
          <table style={{width: '100%', textAlign: 'left', borderCollapse: 'collapse'}}>
            <thead>
              <tr style={{borderBottom: '1px solid #1e293b'}}>
                <th style={styles.th}>Threat Class</th>
                <th style={styles.th}>Detections</th>
              </tr>
            </thead>
            <tbody>
              {['ddos', 'c2', 'recon', 'dga', 'malware', 'exfiltration'].map(t => (
                <tr key={t} style={{borderBottom: '1px solid #1e293b', background: '#0f172a'}}>
                  <td style={styles.td}>{t.toUpperCase()}</td>
                  <td style={{...styles.td, color: stats[t] > 0 ? '#ef4444' : '#f1f5f9', fontWeight: stats[t] > 0 ? 'bold' : 'normal'}}>{stats[t] || 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
const styles = { th: { padding: '12px', color: '#94a3b8' }, td: { padding: '12px' } };
