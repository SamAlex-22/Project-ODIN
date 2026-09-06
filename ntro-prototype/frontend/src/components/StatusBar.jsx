// Displays threat/alert counts only. Connection status lives solely in the
// global topbar — this component has no opinion on `connected`.
function StatusBar({ stats }) {
  const cards = [
    { key: 'total', label: 'TOTAL ALERTS', value: stats.total ?? 0, accent: 'var(--accent)' },
    { key: 'ddos', label: 'DDoS DETECTED', value: stats.ddos ?? 0, accent: 'var(--threat-ddos)' },
    { key: 'recon', label: 'RECON DETECTED', value: stats.recon ?? 0, accent: 'var(--threat-recon)' },
    { key: 'c2', label: 'C2 BEACONING', value: stats.c2 ?? 0, accent: 'var(--threat-c2)' },
  ]

  return (
    <div className="status-bar">
      {cards.map((card) => (
        <div key={card.key} className="status-bar__card">
          <div className="status-bar__value" style={{ color: card.accent }}>
            {card.value}
          </div>
          <div className="status-bar__label">{card.label}</div>
        </div>
      ))}
    </div>
  )
}

export default StatusBar
