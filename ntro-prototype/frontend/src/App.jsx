import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink, useNavigate } from 'react-router-dom';
import { Activity, ShieldAlert, FileSearch, Network, PieChart, ServerCrash, PlayCircle, ShieldCheck } from 'lucide-react';

import SOCOverview from './pages/SOCOverview';
import LiveDetections from './pages/LiveDetections';
import ThreatAnalysis from './pages/ThreatAnalysis';
import AlertInvestigation from './pages/AlertInvestigation';
import NetworkAnalytics from './pages/NetworkAnalytics';
import ThreatDistribution from './pages/ThreatDistribution';
import SystemHealth from './pages/SystemHealth';
import ReplayDemo from './pages/ReplayDemo';

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ ddos: 0, recon: 0, c2: 0, dga: 0, malware: 0, exfiltration: 0, total: 0 });

  useEffect(() => {
    fetch('/api/alerts').then(r => r.json()).then(data => setAlerts(data.reverse()));
    fetch('/api/stats').then(r => r.json()).then(setStats);
    
    const es = new EventSource('/api/stream');
    es.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'connected') return;
      setAlerts(prev => [data, ...prev].slice(0, 500));
      setStats(prev => ({ ...prev, total: prev.total + 1, [data.threat_class]: (prev[data.threat_class] || 0) + 1 }));
    };
    return () => es.close();
  }, []);

  const clearAlerts = () => {
    fetch('/api/clear', { method: 'POST' })
      .then(() => { setAlerts([]); setStats({ ddos: 0, recon: 0, c2: 0, dga: 0, malware: 0, exfiltration: 0, total: 0 }); });
  };

  return (
    <Router>
      <div style={styles.container}>
        {/* Sidebar */}
        <div style={styles.sidebar}>
          <div style={styles.brand}>
            <ShieldCheck size={28} color="#3b82f6" />
            <span style={{fontWeight: 'bold', fontSize: '18px', color: '#f1f5f9'}}>Project ODIN</span>
          </div>
          <nav style={styles.nav}>
            <NavLink to="/" style={({isActive}) => isActive ? styles.navItemActive : styles.navItem}><Activity size={18}/> SOC Overview</NavLink>
            <NavLink to="/live" style={({isActive}) => isActive ? styles.navItemActive : styles.navItem}><ShieldAlert size={18}/> Live Detections</NavLink>
            <NavLink to="/analysis" style={({isActive}) => isActive ? styles.navItemActive : styles.navItem}><FileSearch size={18}/> Threat Analysis</NavLink>
            <NavLink to="/investigate" style={({isActive}) => isActive ? styles.navItemActive : styles.navItem}><FileSearch size={18}/> Alert Investigation</NavLink>
            <NavLink to="/network" style={({isActive}) => isActive ? styles.navItemActive : styles.navItem}><Network size={18}/> Network Analytics</NavLink>
            <NavLink to="/distribution" style={({isActive}) => isActive ? styles.navItemActive : styles.navItem}><PieChart size={18}/> Threat Distribution</NavLink>
            <NavLink to="/health" style={({isActive}) => isActive ? styles.navItemActive : styles.navItem}><ServerCrash size={18}/> System Health</NavLink>
            <NavLink to="/replay" style={({isActive}) => isActive ? styles.navItemActive : styles.navItem}><PlayCircle size={18}/> Replay / Demo</NavLink>
          </nav>
          
          <div style={{marginTop: 'auto', padding: '20px'}}>
            <button onClick={clearAlerts} style={styles.resetBtn}>Reset Demo</button>
          </div>
        </div>

        {/* Main Content */}
        <div style={styles.main}>
          {/* Architecture Banner */}
          <div style={styles.banner}>
            READ-ONLY • PASSIVE MONITORING • NO RETURN PATH • NO PAYLOAD DECRYPTION
          </div>
          
          <div style={styles.content}>
            <Routes>
              <Route path="/" element={<SOCOverview stats={stats} alerts={alerts} />} />
              <Route path="/live" element={<LiveDetections alerts={alerts} />} />
              <Route path="/analysis" element={<ThreatAnalysis />} />
              <Route path="/investigate" element={<AlertInvestigation alerts={alerts} />} />
              <Route path="/network" element={<NetworkAnalytics alerts={alerts} />} />
              <Route path="/distribution" element={<ThreatDistribution stats={stats} />} />
              <Route path="/health" element={<SystemHealth />} />
              <Route path="/replay" element={<ReplayDemo />} />
            </Routes>
          </div>
        </div>
      </div>
    </Router>
  );
}

const styles = {
  container: { display: 'flex', minHeight: '100vh', background: '#0a0e1a', color: '#e2e8f0', fontFamily: 'monospace' },
  sidebar: { width: '250px', background: '#0f172a', borderRight: '1px solid #1e293b', padding: '20px 0', display: 'flex', flexDirection: 'column' },
  resetBtn: { width: '100%', padding: '10px', background: '#dc2626', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold' },
  brand: { display: 'flex', alignItems: 'center', gap: '10px', padding: '0 20px', marginBottom: '30px' },
  nav: { display: 'flex', flexDirection: 'column' },
  navItem: { display: 'flex', alignItems: 'center', gap: '12px', padding: '12px 20px', color: '#94a3b8', textDecoration: 'none' },
  navItemActive: { display: 'flex', alignItems: 'center', gap: '12px', padding: '12px 20px', color: '#f1f5f9', background: '#1e293b', borderRight: '3px solid #3b82f6', textDecoration: 'none' },
  main: { flex: 1, display: 'flex', flexDirection: 'column' },
  banner: { background: '#dc2626', color: 'white', textAlign: 'center', padding: '8px', fontSize: '12px', fontWeight: 'bold', letterSpacing: '2px' },
  content: { padding: '24px', flex: 1, overflowY: 'auto' }
};
