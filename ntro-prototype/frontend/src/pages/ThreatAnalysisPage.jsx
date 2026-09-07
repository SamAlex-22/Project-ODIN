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
  const [replayState, setReplayState] = useState({ status: 'idle' })

  const definition = THREAT_DEFINITIONS[selected]
  const safeAlerts = Array.isArray(alerts) ? alerts : []
  const relatedAlerts = safeAlerts.filter((alert) => alert && alert.threat_class === selected)
  const count = stats?.[selected] ?? 0

  // Replays a pre-recorded pcap for the selected threat through the same
  // live pipeline real traffic uses (see backend/app.py's /api/replay) --
  // a reliable, on-demand way to trigger a specific detection for a demo,
  // instead of depending on manually timed traffic generator scripts.
  const runReplay = () => {
    setReplayState({ status: 'running' })
    fetch(`/api/replay/${selected}`, { method: 'POST' })
      .then((r) => r.json().then((body) => ({ ok: r.ok, body })))
      .then(({ ok, body }) => {
        if (!ok) throw new Error(body.message || 'replay failed')
        setReplayState({ status: 'done', events: body.events_injected })
      })
      .catch((err) => setReplayState({ status: 'error', message: err.message }))
  }

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
            onClick={() => {
              setSelected(key)
              setReplayState({ status: 'idle' })
            }}
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

        <div className="threat-detail__replay">
          <button
            type="button"
            className="btn"
            onClick={runReplay}
            disabled={replayState.status === 'running'}
          >
            {replayState.status === 'running' ? 'Replaying…' : `Replay ${definition.label} Traffic`}
          </button>
          {replayState.status === 'done' && (
            <span className="threat-detail__replay-note is-ok">
              Injected {replayState.events} events from a recorded pcap into the live pipeline.
            </span>
          )}
          {replayState.status === 'error' && (
            <span className="threat-detail__replay-note is-error">
              Replay failed: {replayState.message}
            </span>
          )}
        </div>
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
