import React from 'react';
import { Finding, APCAPEvent } from '../types';

interface FindingsViewProps {
  findings: Finding[];
  events: APCAPEvent[];
  onSelectEvent: (ev: APCAPEvent) => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  events,
  onSelectEvent,
}) => {
  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'HIGH':
        return <span className="badge badge-error">HIGH SEVERITY</span>;
      case 'MEDIUM':
        return <span className="badge badge-tool">MEDIUM SEVERITY</span>;
      default:
        return <span className="badge badge-a2a">LOW SEVERITY</span>;
    }
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: 'calc(100vh - 54px)',
      backgroundColor: 'var(--bg-app)',
      padding: 24,
      overflowY: 'auto',
    }}>
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
          Pathology & Forensic Findings ({findings.length})
        </h2>
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
          Deterministic, rule-based anomaly detection for loops, retry storms, duplicate discoveries, and bottlenecks.
        </p>
      </div>

      {findings.length === 0 ? (
        <div style={{
          backgroundColor: 'rgba(34, 197, 94, 0.08)',
          border: '1px solid rgba(34, 197, 94, 0.25)',
          borderRadius: 8,
          padding: 32,
          textAlign: 'center',
          color: '#4ade80',
          fontFamily: 'var(--font-mono)',
        }}>
          <div style={{ fontSize: 28, marginBottom: 8 }}>✓</div>
          <div style={{ fontWeight: 700, fontSize: 16 }}>ZERO PATHOLOGIES DETECTED</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
            The agent graph executed cleanly without loops, retry storms, or abnormal token spikes.
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {findings.map((f, i) => (
            <div
              key={i}
              style={{
                backgroundColor: 'var(--bg-card)',
                border: `1px solid ${f.severity === 'HIGH' ? 'rgba(239, 68, 68, 0.4)' : 'var(--border-subtle)'}`,
                borderRadius: 8,
                padding: 18,
                display: 'flex',
                flexDirection: 'column',
                gap: 10,
              }}
            >
              {/* Header */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  {getSeverityBadge(f.severity)}
                  <span style={{ fontSize: 15, fontWeight: 700, color: '#f8fafc' }}>{f.title}</span>
                </div>
                <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                  Analyzer v{f.analyzer_version}
                </span>
              </div>

              {/* Explanation */}
              <p style={{ fontSize: 13, color: 'var(--text-main)', lineHeight: 1.5 }}>
                {f.explanation}
              </p>

              {/* Evidence dictionary */}
              {f.evidence && Object.keys(f.evidence).length > 0 && (
                <div style={{
                  backgroundColor: '#0a0f1c',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 6,
                  padding: '8px 12px',
                  fontSize: 11,
                  fontFamily: 'var(--font-mono)',
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: 16,
                }}>
                  {Object.entries(f.evidence).map(([k, v]) => (
                    <div key={k}>
                      <span style={{ color: 'var(--text-dim)' }}>{k}: </span>
                      <span style={{ color: '#38bdf8', fontWeight: 600 }}>{String(v)}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Affected Event Deep Links */}
              {f.event_ids && f.event_ids.length > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                  <span style={{ color: 'var(--text-dim)' }}>AFFECTED EVENTS:</span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {f.event_ids.map(id => (
                      <button
                        key={id}
                        onClick={() => {
                          const match = events.find(e => e.id === id);
                          if (match) onSelectEvent(match);
                        }}
                        style={{
                          backgroundColor: 'var(--bg-surface)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 4,
                          padding: '2px 6px',
                          color: '#38bdf8',
                          cursor: 'pointer',
                          fontSize: 11,
                        }}
                      >
                        #{id}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Suggested Fix */}
              <div style={{
                backgroundColor: 'rgba(56, 189, 248, 0.05)',
                borderLeft: '3px solid #38bdf8',
                padding: '8px 12px',
                fontSize: 12,
                color: '#cbd5e1',
              }}>
                <span style={{ fontWeight: 700, color: '#38bdf8' }}>SUGGESTED INVESTIGATION: </span>
                {f.suggested_fix}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
