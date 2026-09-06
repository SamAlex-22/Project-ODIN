// Single source of truth for Hybrid 1 pipeline stage metadata — read by
// HybridPipeline.jsx (the stage-by-stage diagram) and ArchitecturePage.jsx
// (the component-responsibility grid), so the two views can never drift
// out of sync with each other.
export const STAGES = [
  {
    name: 'Passive Input',
    description: 'Receives mirrored network traffic through TAP/SPAN infrastructure.',
    responsibility: 'Traffic acquisition',
  },
  {
    name: 'Zeek',
    description: 'Transforms network traffic into structured security metadata.',
    responsibility: 'Network metadata generation',
  },
  {
    name: 'Kafka',
    description: 'Provides event streaming between network monitoring and processing.',
    responsibility: 'Event transport',
  },
  {
    name: 'Stream Processor',
    description: 'Consumes events and prepares them for detection.',
    responsibility: 'Event processing',
  },
  {
    name: 'Detection Engine',
    description: 'Runs the active prototype threat detectors.',
    responsibility: 'Threat detection',
  },
  {
    name: 'Alert Engine',
    description: 'Produces evidence-backed alerts with severity and confidence.',
    responsibility: 'Alert generation',
  },
  {
    name: 'Dashboard',
    description: 'Presents alerts, statistics, evidence and pipeline state.',
    responsibility: 'Visualization',
  },
]
