// Static scope statement — exactly the three detectors this prototype
// implements (backend/detectors/ddos.py, recon.py, c2.py). Not derived
// from stats (a class could legitimately have a zero count and still be
// "active"), and never implies the other three SIH threat categories are
// covered.
const DETECTORS = [
  {
    key: 'ddos',
    label: 'DDoS / SYN Flood',
    accent: 'var(--threat-ddos)',
    description: 'Detects high-rate traffic patterns associated with SYN flood activity.',
  },
  {
    key: 'recon',
    label: 'Recon / Port Scan',
    accent: 'var(--threat-recon)',
    description: 'Detects scanning and reconnaissance patterns across ports and hosts.',
  },
  {
    key: 'c2',
    label: 'C2 Beaconing',
    accent: 'var(--threat-c2)',
    description:
      'Detects periodic communication patterns associated with command-and-control activity.',
  },
]

function ActiveDetectors({ compact = false }) {
  if (compact) {
    return (
      <div className="active-detectors">
        <ul className="active-detectors__list">
          {DETECTORS.map((d) => (
            <li key={d.key} className="active-detectors__item" style={{ color: d.accent }}>
              <span aria-hidden="true">✓</span> {d.label}
            </li>
          ))}
        </ul>
        <span className="active-detectors__caption">3 active prototype detectors</span>
      </div>
    )
  }

  return (
    <div className="active-detectors">
      <div className="panel-title">Active Prototype Detectors</div>
      <p className="panel-subtitle active-detectors__subtitle">
        Detection capabilities currently enabled in this prototype
      </p>

      <ul className="active-detectors__detail-list">
        {DETECTORS.map((d) => (
          <li key={d.key} className="active-detectors__detail-item">
            <span
              className="active-detectors__detail-accent"
              style={{ background: d.accent }}
              aria-hidden="true"
            />
            <div>
              <div className="active-detectors__detail-label" style={{ color: d.accent }}>
                {d.label}
              </div>
              <div className="active-detectors__detail-description">{d.description}</div>
            </div>
          </li>
        ))}
      </ul>

      <span className="active-detectors__caption">3 active prototype detectors</span>
    </div>
  )
}

export default ActiveDetectors
