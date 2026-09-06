import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function NetworkAnalytics({ alerts }) {
  // Group alerts by second to create a timeseries
  const timeseries = {};
  alerts.forEach(a => {
    const timeStr = new Date(a.timestamp).toLocaleTimeString();
    if (!timeseries[timeStr]) {
      timeseries[timeStr] = { time: timeStr, DDoS: 0, Recon: 0, C2: 0, Total: 0 };
    }
    timeseries[timeStr].Total += 1;
    if (a.threat_class === 'ddos') timeseries[timeStr].DDoS += 1;
    if (a.threat_class === 'recon') timeseries[timeStr].Recon += 1;
    if (a.threat_class === 'c2') timeseries[timeStr].C2 += 1;
  });

  const data = Object.values(timeseries).slice(-20); // Last 20 seconds of activity

  return (
    <div>
      <h2 style={{borderBottom: '1px solid #1e293b', paddingBottom: '10px', marginBottom: '20px'}}>Network Analytics & Volume</h2>
      
      <div style={{height: '400px', background: '#0f172a', borderRadius: '8px', padding: '20px', border: '1px solid #1e293b'}}>
        <h3 style={{marginBottom: '20px', color: '#f1f5f9'}}>Threat Volume (Alerts / Second)</h3>
        {data.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data}>
              <defs>
                <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip contentStyle={{background: '#1e293b', border: 'none', borderRadius: '4px', color: '#f1f5f9'}} />
              <Area type="monotone" dataKey="Total" stroke="#ef4444" fillOpacity={1} fill="url(#colorTotal)" />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div style={{display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: '#64748b'}}>
            No traffic spikes detected yet.
          </div>
        )}
      </div>
    </div>
  );
}
