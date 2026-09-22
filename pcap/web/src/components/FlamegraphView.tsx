import React, { useState } from 'react';
import { APCAPEvent } from '../types';

interface FlamegraphViewProps {
  events: APCAPEvent[];
}

type FlameMode = 'COST' | 'TOKENS' | 'TIME' | 'CALLS';

export const FlamegraphView: React.FC<FlamegraphViewProps> = ({ events }) => {
  const [mode, setMode] = useState<FlameMode>('COST');

  // Compute hierarchical aggregation
  const { total, items } = React.useMemo(() => {
    let sum = 0;
    const targets = new Map<string, { name: string; category: string; value: number; count: number; subItems: Map<string, number> }>();

    events.forEach(ev => {
      let val = 0;
      switch (mode) {
        case 'COST':
          val = ev.cost ? ev.cost.amount : 0;
          break;
        case 'TOKENS':
          val = ev.tokens ? ev.tokens.total_tokens : 0;
          break;
        case 'TIME':
          val = ev.duration_ms;
          break;
        case 'CALLS':
          val = 1;
          break;
      }

      const target = ev.destination.name || ev.operation;
      const cat = ev.protocol.toLowerCase();

      if (!targets.has(target)) {
        targets.set(target, {
          name: target,
          category: cat,
          value: 0,
          count: 0,
          subItems: new Map(),
        });
      }

      const t = targets.get(target)!;
      t.value += val;
      t.count++;
      sum += val;

      const subVal = t.subItems.get(ev.operation) || 0;
      t.subItems.set(ev.operation, subVal + val);
    });

    const itemList = Array.from(targets.values()).sort((a, b) => b.value - a.value);
    return { total: sum, items: itemList };
  }, [events, mode]);

  const formatValue = (v: number) => {
    switch (mode) {
      case 'COST': return `$${v.toFixed(4)}`;
      case 'TOKENS': return `${Math.round(v).toLocaleString()} tok`;
      case 'TIME': return `${v.toFixed(1)} ms`;
      case 'CALLS': return `${v} calls`;
    }
  };

  const getColor = (cat: string) => {
    switch (cat) {
      case 'model': return '#34d399';
      case 'mcp': return '#c084fc';
      case 'tool': return '#fbbf24';
      case 'a2a': return '#38bdf8';
      default: return '#64748b';
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
      {/* Flamegraph Controls Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 20,
      }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>Hierarchical Spend Flamegraph</h2>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            Visualize where budget, tokens, time, or calls were concentrated across the agent graph.
          </p>
        </div>

        {/* Mode Selector */}
        <div style={{ display: 'flex', gap: 6, backgroundColor: 'var(--bg-card)', padding: 4, borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
          {(['COST', 'TOKENS', 'TIME', 'CALLS'] as const).map(m => (
            <button
              key={m}
              onClick={() => setMode(m)}
              style={{
                padding: '4px 12px',
                borderRadius: 4,
                fontSize: 12,
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
                border: 'none',
                backgroundColor: mode === m ? 'var(--bg-surface)' : 'transparent',
                color: mode === m ? '#38bdf8' : 'var(--text-muted)',
                cursor: 'pointer',
              }}
            >
              {m}
            </button>
          ))}
        </div>
      </div>

      {/* Root Summary Strip */}
      <div style={{
        backgroundColor: '#0a0f1c',
        border: '1px solid var(--border-subtle)',
        borderRadius: 8,
        padding: '12px 18px',
        marginBottom: 16,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        fontFamily: 'var(--font-mono)',
        fontSize: 13,
      }}>
        <div>
          <span style={{ color: 'var(--text-dim)' }}>TOTAL {mode}: </span>
          <span style={{ fontWeight: 700, color: '#f8fafc' }}>{formatValue(total)}</span>
        </div>
        <div>
          <span style={{ color: 'var(--text-dim)' }}>AGGREGATED TARGETS: </span>
          <span style={{ fontWeight: 700, color: 'var(--text-main)' }}>{items.length}</span>
        </div>
      </div>

      {/* Flamegraph Visual Partition Chart */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {items.map(item => {
          const pct = total > 0 ? (item.value / total) * 100 : 0;
          const color = getColor(item.category);

          return (
            <div
              key={item.name}
              style={{
                backgroundColor: 'var(--bg-card)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 8,
                padding: 14,
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: color }} />
                  <span style={{ fontWeight: 700, color: '#f8fafc', fontSize: 14 }}>{item.name}</span>
                  <span className="badge" style={{ fontSize: 10, backgroundColor: 'rgba(255,255,255,0.06)' }}>
                    {item.category.toUpperCase()}
                  </span>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>
                  <span style={{ fontWeight: 700, color: '#f1f5f9' }}>{formatValue(item.value)}</span>
                  <span style={{ color: 'var(--text-dim)', marginLeft: 8 }}>({pct.toFixed(1)}%)</span>
                </div>
              </div>

              {/* Proportional Width Bar */}
              <div style={{ width: '100%', height: 10, backgroundColor: 'rgba(255,255,255,0.05)', borderRadius: 5, overflow: 'hidden' }}>
                <div style={{
                  width: `${Math.max(1, pct)}%`,
                  height: '100%',
                  backgroundColor: color,
                  borderRadius: 5,
                  transition: 'width 0.3s ease',
                }} />
              </div>

              {/* Sub-operations breakdown */}
              {item.subItems.size > 1 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 4 }}>
                  {Array.from(item.subItems.entries()).map(([op, val]) => {
                    const subPct = item.value > 0 ? (val / item.value) * 100 : 0;
                    return (
                      <div
                        key={op}
                        style={{
                          backgroundColor: 'var(--bg-surface)',
                          borderRadius: 4,
                          padding: '3px 8px',
                          fontSize: 11,
                          fontFamily: 'var(--font-mono)',
                          display: 'flex',
                          gap: 6,
                          color: 'var(--text-muted)',
                        }}
                      >
                        <span style={{ color: '#cbd5e1' }}>{op}:</span>
                        <span style={{ fontWeight: 600 }}>{formatValue(val)}</span>
                        <span style={{ color: 'var(--text-dim)' }}>({subPct.toFixed(0)}%)</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
