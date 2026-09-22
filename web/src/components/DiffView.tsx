import React from 'react';
import { DiffResult } from '../types';

interface DiffViewProps {
  diffResult?: DiffResult | null;
  onCompareFiles?: (fileA: File, fileB: File) => void;
}

export const DiffView: React.FC<DiffViewProps> = ({ diffResult }) => {
  // Demo fallback diff if none loaded
  const displayDiff: DiffResult = diffResult || {
    before_id: 'run_baseline.apcap',
    after_id: 'run_candidate.apcap',
    latency_ms: { before: 8200, after: 4100, delta: -4100, pct: -50.0 },
    tokens: { before: 21440, after: 13210, delta: -8230, pct: -38.4 },
    cost: { before: 0.12, after: 0.07, delta: -0.05, pct: -41.7 },
    errors: { before: 3, after: 0, delta: -3, pct: -100.0 },
    model_calls: { before: 8, after: 5, delta: -3 },
    tool_calls: { before: 12, after: 7, delta: -5 },
    delegations: { before: 4, after: 2, delta: -2 },
    changed_ops: [
      { operation: 'gemini-1.5-pro retry', before: 3, after: 0, delta: -3 },
      { operation: 'mcp:analytics_query', before: 4, after: 1, delta: -3 },
      { operation: 'task/delegate:research', before: 2, after: 1, delta: -1 },
    ],
    resolved_pathologies: [
      'RETRY_STORM (gemini-1.5-pro retry storm resolved)',
      'DUPLICATE_DISCOVERY (repeated tools/list eliminated)',
    ],
    introduced_pathologies: [],
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
      <div style={{ marginBottom: 20, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
            Run Difference Engine
          </h2>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            Comparing baseline <code style={{ color: '#38bdf8' }}>{displayDiff.before_id}</code> against candidate <code style={{ color: '#34d399' }}>{displayDiff.after_id}</code>
          </p>
        </div>
      </div>

      {/* Metrics Delta Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: 14,
        marginBottom: 24,
      }}>
        {/* Latency */}
        <div style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>WALL-CLOCK LATENCY</div>
          <div style={{ fontSize: 22, fontWeight: 800, color: '#f8fafc', margin: '4px 0' }}>
            {(displayDiff.latency_ms.after / 1000).toFixed(2)}s
          </div>
          <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: displayDiff.latency_ms.delta <= 0 ? '#34d399' : '#f87171' }}>
            {displayDiff.latency_ms.delta <= 0 ? '▼' : '▲'} {Math.abs(displayDiff.latency_ms.pct).toFixed(1)}% (was {(displayDiff.latency_ms.before / 1000).toFixed(2)}s)
          </div>
        </div>

        {/* Tokens */}
        <div style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>TOTAL TOKENS</div>
          <div style={{ fontSize: 22, fontWeight: 800, color: '#38bdf8', margin: '4px 0' }}>
            {Math.round(displayDiff.tokens.after).toLocaleString()}
          </div>
          <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: displayDiff.tokens.delta <= 0 ? '#34d399' : '#f87171' }}>
            {displayDiff.tokens.delta <= 0 ? '▼' : '▲'} {Math.abs(displayDiff.tokens.pct).toFixed(1)}% (was {Math.round(displayDiff.tokens.before).toLocaleString()})
          </div>
        </div>

        {/* Cost */}
        <div style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>ESTIMATED COST</div>
          <div style={{ fontSize: 22, fontWeight: 800, color: '#34d399', margin: '4px 0' }}>
            ${displayDiff.cost.after.toFixed(4)}
          </div>
          <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: displayDiff.cost.delta <= 0 ? '#34d399' : '#f87171' }}>
            {displayDiff.cost.delta <= 0 ? '▼' : '▲'} {Math.abs(displayDiff.cost.pct).toFixed(1)}% (was ${displayDiff.cost.before.toFixed(4)})
          </div>
        </div>

        {/* Errors */}
        <div style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>ERROR COUNT</div>
          <div style={{ fontSize: 22, fontWeight: 800, color: displayDiff.errors.after === 0 ? '#34d399' : '#f87171', margin: '4px 0' }}>
            {displayDiff.errors.after}
          </div>
          <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: displayDiff.errors.delta <= 0 ? '#34d399' : '#f87171' }}>
            {displayDiff.errors.delta <= 0 ? '▼' : '▲'} {displayDiff.errors.delta} errors (was {displayDiff.errors.before})
          </div>
        </div>
      </div>

      {/* Changed Operations Table */}
      <div style={{
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 8,
        padding: 16,
        marginBottom: 20,
      }}>
        <h3 style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc', marginBottom: 12 }}>
          Call Frequency Changes
        </h3>

        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 100px 100px 120px',
          padding: '6px 12px',
          borderBottom: '1px solid var(--border-subtle)',
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
          color: 'var(--text-dim)',
          fontWeight: 700,
        }}>
          <div>OPERATION</div>
          <div style={{ textAlign: 'center' }}>BEFORE</div>
          <div style={{ textAlign: 'center' }}>AFTER</div>
          <div style={{ textAlign: 'right' }}>DELTA</div>
        </div>

        {displayDiff.changed_ops?.map((op, i) => (
          <div
            key={i}
            style={{
              display: 'grid',
              gridTemplateColumns: '1fr 100px 100px 120px',
              padding: '8px 12px',
              borderBottom: '1px solid rgba(255,255,255,0.03)',
              fontSize: 12,
              fontFamily: 'var(--font-mono)',
              alignItems: 'center',
            }}
          >
            <div style={{ color: '#f1f5f9', fontWeight: 600 }}>{op.operation}</div>
            <div style={{ textAlign: 'center', color: 'var(--text-muted)' }}>{op.before}</div>
            <div style={{ textAlign: 'center', color: '#f8fafc' }}>{op.after}</div>
            <div style={{
              textAlign: 'right',
              fontWeight: 700,
              color: op.delta < 0 ? '#34d399' : '#f87171',
            }}>
              {op.delta > 0 ? `+${op.delta}` : op.delta} calls
            </div>
          </div>
        ))}
      </div>

      {/* Pathologies Resolved / Introduced */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
        {/* Resolved */}
        <div style={{
          backgroundColor: 'rgba(34, 197, 94, 0.05)',
          border: '1px solid rgba(34, 197, 94, 0.25)',
          borderRadius: 8,
          padding: 16,
        }}>
          <h4 style={{ fontSize: 13, fontWeight: 700, color: '#34d399', marginBottom: 8 }}>
            ✓ RESOLVED PATHOLOGIES
          </h4>
          {displayDiff.resolved_pathologies && displayDiff.resolved_pathologies.length > 0 ? (
            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12, fontFamily: 'var(--font-mono)' }}>
              {displayDiff.resolved_pathologies.map((p, i) => (
                <li key={i} style={{ color: '#cbd5e1' }}>• {p}</li>
              ))}
            </ul>
          ) : (
            <div style={{ color: 'var(--text-dim)', fontSize: 12 }}>None resolved</div>
          )}
        </div>

        {/* Introduced */}
        <div style={{
          backgroundColor: 'rgba(239, 68, 68, 0.05)',
          border: '1px solid rgba(239, 68, 68, 0.25)',
          borderRadius: 8,
          padding: 16,
        }}>
          <h4 style={{ fontSize: 13, fontWeight: 700, color: '#f87171', marginBottom: 8 }}>
            ⚠ NEW PATHOLOGIES INTRODUCED
          </h4>
          {displayDiff.introduced_pathologies && displayDiff.introduced_pathologies.length > 0 ? (
            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12, fontFamily: 'var(--font-mono)' }}>
              {displayDiff.introduced_pathologies.map((p, i) => (
                <li key={i} style={{ color: '#cbd5e1' }}>• {p}</li>
              ))}
            </ul>
          ) : (
            <div style={{ color: 'var(--text-dim)', fontSize: 12 }}>None introduced</div>
          )}
        </div>
      </div>
    </div>
  );
};
