import { useState } from 'react'
import AlertFeed from '../components/AlertFeed'

// Evidence signals listed here are the fields the corresponding detector
// already emits in `alert.evidence` per the fixed API contract — nothing
// invented, no telemetry beyond what the backend provides.
const THREAT_DEFINITIONS = {
  ddos: {
    label: 'DDoS / SYN Flood',
    accent: 'var(--threat-ddos)',
    summary:
      'Flags a surge of connections arriving from many distinct source addresses within a short window.',
    signals: [
      'Packet rate over a 10-second window',
      'Number of unique source IPs',
      'Source IP entropy versus a configured threshold',
    ],
  },
  recon: {
    label: 'Recon / Port Scan',
    accent: 'var(--threat-recon)',
    summary:
      'Flags a single source probing an unusually large number of destination ports or hosts.',
    signals: [
      'Unique destination ports contacted',
      'Unique destination hosts contacted',
      'Comparison against a configured port threshold',
    ],
  },
  c2: {
    label: 'C2 Beaconing',
    accent: 'var(--threat-c2)',
    summary:
      'Flags recurring connections to the same destination with unusually regular timing.',
    signals: [
      'Mean interval and standard deviation between connections',
      'Coefficient of variation versus a configured threshold',
      'Number of observed connections',
    ],
  },
}

// Threat-class-focused view of the active prototype detectors. Reuses
// AlertFeed for the selected class's alerts instead of duplicating rendering.
function ThreatAnalysisPage({ stats, alerts }) {
  const [selected, setSelected] = useState('ddos')

  const definition = THREAT_DEFINITIONS[selected]
  const safeAlerts = Array.isArray(alerts) ? alerts : []
  const relatedAlerts = safeAlerts.filter((alert) => alert && alert.threat_class === selected)
  const count = stats?.[selected] ?? 0

  return (
    <div className="page">
      <div className="page-intro">
        <h1 className="page-intro__title">Threat Analysis</h1>
        <p className="page-intro__subtitle">Analyze active detector classes</p>
      </div>

      <div className="threat-tabs" role="tablist" aria-label="Threat class">
        {Object.entries(THREAT_DEFINITIONS).map(([key, def]) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={selected === key}
            className={`pill-toggle ${selected === key ? 'is-active' : ''}`}
            style={{ '--tab-accent': def.accent }}
            onClick={() => setSelected(key)}
          >
            {def.label}
          </button>
        ))}
      </div>

      <div className="panel threat-detail">
        <div className="threat-detail__header">
          <span className="threat-detail__label" style={{ color: definition.accent }}>
            {definition.label}
          </span>
          <span className="threat-detail__count">{count} DETECTED</span>
        </div>
        <p className="threat-detail__summary">{definition.summary}</p>
        <div className="threat-detail__signals">
          <span className="threat-detail__signals-title">
            Evidence signals used by this detector
          </span>
          <ul>
            {definition.signals.map((signal) => (
              <li key={signal}>{signal}</li>
            ))}
          </ul>
        </div>
      </div>

      <AlertFeed alerts={relatedAlerts} />
    </div>
  )
}

export default ThreatAnalysisPage
