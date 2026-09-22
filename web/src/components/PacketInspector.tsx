import React, { useState } from 'react';
import { APCAPEvent } from '../types';

interface PacketInspectorProps {
  event: APCAPEvent | null;
  onClose: () => void;
}

export const PacketInspector: React.FC<PacketInspectorProps> = ({ event, onClose }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'attributes' | 'payload' | 'json'>('overview');
  const [copied, setCopied] = useState(false);

  if (!event) return null;

  const handleCopyJSON = () => {
    navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isErr = event.status === 'ERROR' || event.status === 'TIMEOUT';

  return (
    <div style={{
      position: 'fixed',
      bottom: 0,
      right: 0,
      width: 520,
      height: 'calc(100vh - 54px)',
      backgroundColor: '#0c1322',
      borderLeft: '1px solid var(--border-subtle)',
      boxShadow: '-8px 0 24px rgba(0,0,0,0.5)',
      display: 'flex',
      flexDirection: 'column',
      zIndex: 50,
    }}>
      {/* Header */}
      <div style={{
        padding: '14px 18px',
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        backgroundColor: 'var(--bg-card)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, overflow: 'hidden' }}>
          <span className={`badge badge-${event.protocol.toLowerCase()}`}>
            {event.protocol}
          </span>
          <span style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={event.operation}>
            {event.operation}
          </span>
          <span className={`badge ${isErr ? 'badge-error' : 'badge-model'}`}>
            {event.status}
          </span>
        </div>
        <button
          onClick={onClose}
          style={{ background: 'none', border: 'none', color: 'var(--text-dim)', fontSize: 16, cursor: 'pointer' }}
        >
          ✕
        </button>
      </div>

      {/* Sub Tabs */}
      <div style={{
        display: 'flex',
        borderBottom: '1px solid var(--border-subtle)',
        backgroundColor: '#0a0f1c',
        padding: '0 12px',
      }}>
        {(['overview', 'attributes', 'payload', 'json'] as const).map(tab => {
          const isActive = activeTab === tab;
          return (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                padding: '8px 14px',
                fontSize: 12,
                fontWeight: 600,
                fontFamily: 'var(--font-mono)',
                color: isActive ? '#38bdf8' : 'var(--text-dim)',
                background: 'none',
                border: 'none',
                borderBottom: isActive ? '2px solid #38bdf8' : '2px solid transparent',
                cursor: 'pointer',
                textTransform: 'uppercase',
              }}
            >
              {tab}
            </button>
          );
        })}

        <button
          onClick={handleCopyJSON}
          className="btn"
          style={{ marginLeft: 'auto', padding: '3px 8px', fontSize: 11, alignSelf: 'center' }}
        >
          {copied ? '✓ Copied' : 'Copy JSON'}
        </button>
      </div>

      {/* Tab Content Body */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
        {activeTab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14, fontSize: 13, fontFamily: 'var(--font-mono)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
              <span style={{ color: 'var(--text-dim)' }}>Event ID</span>
              <span style={{ color: 'var(--text-main)' }}>{event.id}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
              <span style={{ color: 'var(--text-dim)' }}>Trace ID</span>
              <span style={{ color: 'var(--text-main)' }}>{event.trace_id}</span>
            </div>
            {event.parent_id && (
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
                <span style={{ color: 'var(--text-dim)' }}>Parent ID</span>
                <span style={{ color: 'var(--text-main)' }}>{event.parent_id}</span>
              </div>
            )}
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
              <span style={{ color: 'var(--text-dim)' }}>Source</span>
              <span style={{ color: '#38bdf8' }}>{event.source.name} ({event.source.kind})</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
              <span style={{ color: 'var(--text-dim)' }}>Destination</span>
              <span style={{ color: '#c084fc' }}>{event.destination.name} ({event.destination.kind})</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
              <span style={{ color: 'var(--text-dim)' }}>Duration</span>
              <span style={{ color: 'var(--text-main)', fontWeight: 700 }}>{event.duration_ms.toFixed(2)} ms</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
              <span style={{ color: 'var(--text-dim)' }}>Provenance</span>
              <span className="badge" style={{ backgroundColor: 'rgba(255,255,255,0.06)', color: 'var(--text-muted)' }}>
                {event.provenance}
              </span>
            </div>

            {/* Token details if model/llm */}
            {event.tokens && (
              <div style={{
                marginTop: 10,
                backgroundColor: 'rgba(56, 189, 248, 0.05)',
                border: '1px solid rgba(56, 189, 248, 0.2)',
                borderRadius: 8,
                padding: 14,
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
              }}>
                <div style={{ fontWeight: 700, color: '#38bdf8' }}>TOKEN USAGE</div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-dim)' }}>Input Tokens:</span>
                  <span>{event.tokens.input_tokens.toLocaleString()}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-dim)' }}>Output Tokens:</span>
                  <span>{event.tokens.output_tokens.toLocaleString()}</span>
                </div>
                {event.tokens.cached_tokens ? (
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-dim)' }}>Cached Tokens:</span>
                    <span>{event.tokens.cached_tokens.toLocaleString()}</span>
                  </div>
                ) : null}
                <div style={{ display: 'flex', justifyContent: 'space-between', borderTop: '1px solid var(--border-subtle)', paddingTop: 6, fontWeight: 700 }}>
                  <span style={{ color: 'var(--text-main)' }}>Total:</span>
                  <span>{event.tokens.total_tokens.toLocaleString()}</span>
                </div>
              </div>
            )}

            {/* Cost details if available */}
            {event.cost && (
              <div style={{
                backgroundColor: 'rgba(52, 211, 153, 0.05)',
                border: '1px solid rgba(52, 211, 153, 0.2)',
                borderRadius: 8,
                padding: 14,
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
              }}>
                <div style={{ fontWeight: 700, color: '#34d399' }}>COST ESTIMATE</div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-dim)' }}>Estimated Cost:</span>
                  <span style={{ fontWeight: 700, color: '#34d399' }}>${event.cost.amount.toFixed(5)} USD</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                  <span style={{ color: 'var(--text-dim)' }}>Status:</span>
                  <span>{event.cost.status}</span>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'attributes' && (
          <div>
            {event.attributes && Object.keys(event.attributes).length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                {Object.entries(event.attributes).map(([k, v]) => (
                  <div key={k} style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
                    <div style={{ color: '#38bdf8', fontWeight: 600 }}>{k}</div>
                    <div style={{ color: '#f1f5f9', marginTop: 2, wordBreak: 'break-all' }}>
                      {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ color: 'var(--text-dim)', textAlign: 'center', padding: 40 }}>
                No protocol attributes recorded for this event.
              </div>
            )}
          </div>
        )}

        {activeTab === 'payload' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span className="badge" style={{ backgroundColor: 'rgba(34, 197, 94, 0.1)', color: '#4ade80' }}>
                PRIVACY GUARD ACTIVE
              </span>
              <span className="badge" style={{ backgroundColor: 'rgba(255, 255, 255, 0.05)', color: 'var(--text-dim)' }}>
                METADATA ONLY
              </span>
            </div>

            <p style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Raw prompts and secrets are omitted by default to ensure zero credential leakage. To capture sanitized payloads, launch with <code style={{ color: '#38bdf8' }}>--capture-content</code>.
            </p>

            {event.payload?.preview ? (
              <div style={{
                backgroundColor: 'var(--bg-app)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 6,
                padding: 12,
                fontFamily: 'var(--font-mono)',
                fontSize: 12,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}>
                {event.payload.preview}
              </div>
            ) : (
              <div style={{
                padding: 20,
                border: '1px dashed var(--border-subtle)',
                borderRadius: 6,
                textAlign: 'center',
                color: 'var(--text-dim)',
                fontSize: 12,
                fontFamily: 'var(--font-mono)',
              }}>
                Payload omitted (metadata-only mode)
              </div>
            )}
          </div>
        )}

        {activeTab === 'json' && (
          <pre style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 11,
            color: '#cbd5e1',
            backgroundColor: 'var(--bg-app)',
            padding: 14,
            borderRadius: 6,
            border: '1px solid var(--border-subtle)',
            overflowX: 'auto',
          }}>
            {JSON.stringify(event, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
};
