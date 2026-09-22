import React, { useState, useMemo } from 'react';
import { APCAPEvent } from '../types';

interface PacketsListProps {
  events: APCAPEvent[];
  onSelectEvent: (ev: APCAPEvent) => void;
  selectedEventId?: string;
}

export const PacketsList: React.FC<PacketsListProps> = ({
  events,
  onSelectEvent,
  selectedEventId,
}) => {
  const [search, setSearch] = useState('');
  const [selectedProto, setSelectedProto] = useState<string>('ALL');

  const filteredEvents = useMemo(() => {
    return events.filter(ev => {
      // Protocol filter
      if (selectedProto !== 'ALL') {
        if (selectedProto === 'ERROR') {
          if (ev.status !== 'ERROR' && ev.status !== 'TIMEOUT') return false;
        } else if (ev.protocol !== selectedProto) {
          return false;
        }
      }

      // Search filter
      if (search.trim()) {
        const q = search.toLowerCase();
        const opMatch = ev.operation.toLowerCase().includes(q);
        const srcMatch = ev.source.name.toLowerCase().includes(q);
        const dstMatch = ev.destination.name.toLowerCase().includes(q);
        const protoMatch = ev.protocol.toLowerCase().includes(q);
        const idMatch = ev.id.toLowerCase().includes(q);
        return opMatch || srcMatch || dstMatch || protoMatch || idMatch;
      }

      return true;
    });
  }, [events, search, selectedProto]);

  const protocols: { id: string; label: string }[] = [
    { id: 'ALL', label: 'All Protocols' },
    { id: 'A2A', label: 'A2A' },
    { id: 'MCP', label: 'MCP' },
    { id: 'MODEL', label: 'Model' },
    { id: 'TOOL', label: 'Tool' },
    { id: 'HTTP', label: 'HTTP' },
    { id: 'ERROR', label: 'Errors Only' },
  ];

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: 'calc(100vh - 54px)',
      backgroundColor: 'var(--bg-app)',
    }}>
      {/* Filter / Search Tool Bar */}
      <div style={{
        padding: '10px 16px',
        borderBottom: '1px solid var(--border-subtle)',
        backgroundColor: 'var(--bg-card)',
        display: 'flex',
        alignItems: 'center',
        gap: 12,
      }}>
        {/* Search Input */}
        <div style={{ position: 'relative', width: 280 }}>
          <input
            type="text"
            placeholder="Filter packets (e.g. mcp, error, gemini)..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              width: '100%',
              padding: '6px 10px',
              backgroundColor: 'var(--bg-app)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 6,
              color: 'var(--text-main)',
              fontSize: 13,
              fontFamily: 'var(--font-sans)',
              outline: 'none',
            }}
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              style={{
                position: 'absolute',
                right: 8,
                top: 6,
                background: 'none',
                border: 'none',
                color: 'var(--text-dim)',
                cursor: 'pointer',
              }}
            >
              ✕
            </button>
          )}
        </div>

        {/* Protocol Pills */}
        <div style={{ display: 'flex', gap: 6 }}>
          {protocols.map(p => {
            const isActive = selectedProto === p.id;
            return (
              <button
                key={p.id}
                onClick={() => setSelectedProto(p.id)}
                style={{
                  padding: '4px 10px',
                  borderRadius: 4,
                  fontSize: 12,
                  fontWeight: 600,
                  fontFamily: 'var(--font-mono)',
                  border: `1px solid ${isActive ? '#38bdf8' : 'var(--border-subtle)'}`,
                  backgroundColor: isActive ? 'rgba(56, 189, 248, 0.15)' : 'var(--bg-card)',
                  color: isActive ? '#38bdf8' : 'var(--text-muted)',
                  cursor: 'pointer',
                }}
              >
                {p.label}
              </button>
            );
          })}
        </div>

        <div style={{ marginLeft: 'auto', fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
          Showing {filteredEvents.length} of {events.length} packets
        </div>
      </div>

      {/* Packet Table Header */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '80px 80px 180px 180px 1fr 100px 100px 90px 90px',
        padding: '8px 16px',
        borderBottom: '1px solid var(--border-subtle)',
        fontSize: 11,
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
        color: 'var(--text-dim)',
        backgroundColor: '#0a0f1c',
      }}>
        <div># / ID</div>
        <div>PROTO</div>
        <div>SOURCE</div>
        <div>DESTINATION</div>
        <div>OPERATION</div>
        <div style={{ textAlign: 'right' }}>DURATION</div>
        <div style={{ textAlign: 'right' }}>TOKENS</div>
        <div style={{ textAlign: 'right' }}>COST</div>
        <div style={{ textAlign: 'center' }}>STATUS</div>
      </div>

      {/* Packet Rows */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {filteredEvents.map((ev, i) => {
          const isSelected = selectedEventId === ev.id;
          const isErr = ev.status === 'ERROR' || ev.status === 'TIMEOUT';

          return (
            <div
              key={ev.id || i}
              onClick={() => onSelectEvent(ev)}
              style={{
                display: 'grid',
                gridTemplateColumns: '80px 80px 180px 180px 1fr 100px 100px 90px 90px',
                padding: '6px 16px',
                borderBottom: '1px solid rgba(255,255,255,0.03)',
                fontSize: 12,
                fontFamily: 'var(--font-mono)',
                alignItems: 'center',
                backgroundColor: isSelected
                  ? 'var(--bg-surface)'
                  : isErr
                  ? 'rgba(239, 68, 68, 0.08)'
                  : (i % 2 === 0 ? 'rgba(255,255,255,0.01)' : 'transparent'),
                cursor: 'pointer',
              }}
              onMouseEnter={e => {
                if (!isSelected) e.currentTarget.style.backgroundColor = 'var(--bg-card-hover)';
              }}
              onMouseLeave={e => {
                if (!isSelected) {
                  e.currentTarget.style.backgroundColor = isErr
                    ? 'rgba(239, 68, 68, 0.08)'
                    : (i % 2 === 0 ? 'rgba(255,255,255,0.01)' : 'transparent');
                }
              }}
            >
              <div style={{ color: 'var(--text-dim)', fontSize: 11 }}>
                {i + 1}
              </div>

              <div>
                <span className={`badge badge-${ev.protocol.toLowerCase()}`}>
                  {ev.protocol}
                </span>
              </div>

              <div style={{ color: '#f1f5f9', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ev.source.name}>
                {ev.source.name || 'client'}
              </div>

              <div style={{ color: '#f1f5f9', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ev.destination.name}>
                {ev.destination.name || 'service'}
              </div>

              <div style={{ color: '#f8fafc', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ev.operation}>
                {ev.operation}
              </div>

              <div style={{ textAlign: 'right', color: 'var(--text-main)' }}>
                {ev.duration_ms.toFixed(1)}ms
              </div>

              <div style={{ textAlign: 'right', color: ev.tokens ? '#38bdf8' : 'var(--text-dim)' }}>
                {ev.tokens ? ev.tokens.total_tokens.toLocaleString() : '-'}
              </div>

              <div style={{ textAlign: 'right', color: ev.cost ? '#34d399' : 'var(--text-dim)' }}>
                {ev.cost ? `$${ev.cost.amount.toFixed(4)}` : '-'}
              </div>

              <div style={{ textAlign: 'center' }}>
                <span className={`badge ${isErr ? 'badge-error' : 'badge-model'}`} style={{ fontSize: 10 }}>
                  {ev.status}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
