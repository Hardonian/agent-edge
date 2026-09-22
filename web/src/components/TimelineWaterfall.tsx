import React, { useMemo } from 'react';
import { APCAPEvent, CriticalPathReport } from '../types';

interface TimelineWaterfallProps {
  events: APCAPEvent[];
  criticalPath?: CriticalPathReport;
  onSelectEvent: (ev: APCAPEvent) => void;
  selectedEventId?: string;
}

export const TimelineWaterfall: React.FC<TimelineWaterfallProps> = ({
  events,
  criticalPath,
  onSelectEvent,
  selectedEventId,
}) => {
  // Compute timeline boundaries
  const { minTime, totalDurationMs } = useMemo(() => {
    if (events.length === 0) {
      return { minTime: 0, totalDurationMs: 1000 };
    }
    let min = new Date(events[0].timestamp).getTime();
    let max = min + events[0].duration_ms;

    events.forEach(ev => {
      const start = new Date(ev.timestamp).getTime();
      const end = start + ev.duration_ms;
      if (start < min) min = start;
      if (end > max) max = end;
    });

    const diff = Math.max(10, max - min);
    return { minTime: min, maxTime: max, totalDurationMs: diff };
  }, [events]);

  const getBarColor = (ev: APCAPEvent) => {
    if (ev.status === 'ERROR' || ev.status === 'TIMEOUT') return '#f87171';
    switch (ev.protocol) {
      case 'A2A': return '#38bdf8';
      case 'MCP': return '#c084fc';
      case 'MODEL': return '#34d399';
      case 'TOOL': return '#fbbf24';
      case 'HTTP': return '#60a5fa';
      default: return '#94a3b8';
    }
  };

  const criticalEventIds = useMemo(() => {
    const set = new Set<string>();
    criticalPath?.steps?.forEach(s => set.add(s.event_id));
    return set;
  }, [criticalPath]);

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: 'calc(100vh - 54px)',
      backgroundColor: 'var(--bg-app)',
      overflowY: 'auto',
      padding: '16px 24px',
    }}>
      {/* Critical Path Notice Banner */}
      {criticalPath?.summary && (
        <div style={{
          backgroundColor: 'rgba(56, 189, 248, 0.08)',
          border: '1px solid rgba(56, 189, 248, 0.25)',
          borderRadius: 8,
          padding: '10px 16px',
          marginBottom: 16,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: 13,
        }}>
          <div>
            <span style={{ fontWeight: 700, color: '#38bdf8' }}>⚡ CRITICAL PATH: </span>
            <span style={{ color: 'var(--text-main)' }}>{criticalPath.summary}</span>
          </div>
          <span className="badge" style={{ backgroundColor: 'rgba(56,189,248,0.2)', color: '#38bdf8' }}>
            {criticalPath.dominant_event.duration_ms.toFixed(1)} ms
          </span>
        </div>
      )}

      {/* Timeline Header Scale */}
      <div style={{
        display: 'flex',
        borderBottom: '1px solid var(--border-subtle)',
        paddingBottom: 8,
        fontSize: 11,
        fontFamily: 'var(--font-mono)',
        color: 'var(--text-dim)',
      }}>
        <div style={{ width: 320, paddingLeft: 8 }}>OPERATION / SPAN</div>
        <div style={{ flex: 1, position: 'relative' }}>
          <span style={{ position: 'absolute', left: 0 }}>0 ms</span>
          <span style={{ position: 'absolute', left: '25%' }}>{(totalDurationMs * 0.25).toFixed(0)} ms</span>
          <span style={{ position: 'absolute', left: '50%' }}>{(totalDurationMs * 0.50).toFixed(0)} ms</span>
          <span style={{ position: 'absolute', left: '75%' }}>{(totalDurationMs * 0.75).toFixed(0)} ms</span>
          <span style={{ position: 'absolute', right: 0 }}>{totalDurationMs.toFixed(0)} ms</span>
        </div>
      </div>

      {/* Waterfall Rows */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 8 }}>
        {events.map((ev, index) => {
          const startOffset = new Date(ev.timestamp).getTime() - minTime;
          const leftPct = Math.max(0, Math.min(100, (startOffset / totalDurationMs) * 100));
          const widthPct = Math.max(0.8, Math.min(100 - leftPct, (ev.duration_ms / totalDurationMs) * 100));
          const isSelected = selectedEventId === ev.id;
          const isCritical = criticalEventIds.has(ev.id);
          const barColor = getBarColor(ev);

          return (
            <div
              key={ev.id || index}
              onClick={() => onSelectEvent(ev)}
              style={{
                display: 'flex',
                alignItems: 'center',
                height: 32,
                borderRadius: 4,
                backgroundColor: isSelected ? 'var(--bg-surface)' : 'transparent',
                cursor: 'pointer',
                transition: 'background-color 0.1s ease',
              }}
              onMouseEnter={e => {
                if (!isSelected) e.currentTarget.style.backgroundColor = 'var(--bg-card-hover)';
              }}
              onMouseLeave={e => {
                if (!isSelected) e.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              {/* Left Info Column */}
              <div style={{
                width: 320,
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                paddingLeft: ev.parent_id ? 24 : 8,
                overflow: 'hidden',
                whiteSpace: 'nowrap',
                textOverflow: 'ellipsis',
              }}>
                <span className={`badge badge-${ev.protocol.toLowerCase()}`} style={{ fontSize: 10, padding: '1px 5px' }}>
                  {ev.protocol}
                </span>
                <span style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9' }} title={ev.operation}>
                  {ev.operation}
                </span>
                {isCritical && (
                  <span style={{ color: '#38bdf8', fontSize: 11, fontWeight: 'bold' }} title="On Critical Path">
                    ⚡
                  </span>
                )}
              </div>

              {/* Right Gantt Bar Column */}
              <div style={{ flex: 1, position: 'relative', height: '100%', display: 'flex', alignItems: 'center' }}>
                {/* Visual duration bar */}
                <div
                  style={{
                    position: 'absolute',
                    left: `${leftPct}%`,
                    width: `${widthPct}%`,
                    height: 18,
                    borderRadius: 4,
                    backgroundColor: barColor,
                    opacity: isCritical ? 1 : 0.8,
                    display: 'flex',
                    alignItems: 'center',
                    padding: '0 6px',
                    fontSize: 10,
                    fontWeight: 700,
                    fontFamily: 'var(--font-mono)',
                    color: '#080c14',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    boxShadow: isCritical ? `0 0 10px ${barColor}` : 'none',
                  }}
                >
                  {ev.duration_ms >= 20 && `${ev.duration_ms.toFixed(1)}ms`}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
