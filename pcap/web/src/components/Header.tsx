import React from 'react';
import { Manifest, CaptureMetadata, Finding } from '../types';

interface HeaderProps {
  manifest?: Manifest;
  metadata?: CaptureMetadata;
  findings: Finding[];
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isLive: boolean;
  onOpenFile: () => void;
  onRunSimulation: () => void;
  isSimulating: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  manifest,
  metadata,
  findings,
  activeTab,
  setActiveTab,
  isLive,
  onOpenFile,
  onRunSimulation,
  isSimulating,
}) => {
  const tabs = [
    { id: 'topology', label: 'Topology', icon: '⛶' },
    { id: 'timeline', label: 'Timeline', icon: '☰' },
    { id: 'packets', label: 'Packets', icon: '☷' },
    { id: 'flamegraph', label: 'Flamegraph', icon: '▲' },
    { id: 'findings', label: `Findings (${findings.length})`, icon: '⚠', alert: findings.length > 0 },
    { id: 'diff', label: 'Diff', icon: '◫' },
    { id: 'metadata', label: 'Metadata', icon: 'ℹ' },
  ];

  const totalTokens = metadata?.total_tokens?.total_tokens || 0;
  const totalCost = metadata?.total_cost || 0;
  const durationSec = ((metadata?.total_duration_ms || 0) / 1000).toFixed(2);
  const errorCount = metadata?.error_count || 0;

  return (
    <header style={{
      height: 54,
      backgroundColor: 'var(--bg-card)',
      borderBottom: '1px solid var(--border-subtle)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 16px',
      gap: 16,
      zIndex: 20,
    }}>
      {/* Brand & Status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <svg width="22" height="22" viewBox="0 0 32 32" fill="none">
            <rect width="32" height="32" rx="6" fill="#1e293b"/>
            <circle cx="7" cy="16" r="3" fill="#38bdf8" />
            <circle cx="16" cy="8" r="3" fill="#c084fc" />
            <circle cx="16" cy="24" r="3" fill="#34d399" />
            <circle cx="25" cy="16" r="3" fill="#fbbf24" />
            <path d="M9 15L14 9M9 17L14 23M18 9L23 15M18 23L23 17" stroke="#64748b" strokeWidth="1.5" strokeLinecap="round" />
            <path d="M12 16H20" stroke="#38bdf8" strokeWidth="2" strokeDasharray="2 2" />
          </svg>
          <span style={{ fontWeight: 800, fontSize: 16, letterSpacing: '-0.02em', color: '#f8fafc' }}>
            Agent<span style={{ color: '#38bdf8' }}>PCAP</span>
          </span>
          <span className="badge" style={{ backgroundColor: 'rgba(255,255,255,0.06)', color: 'var(--text-muted)' }}>
            v1.0.0
          </span>
          {manifest?.capture_id && (
            <span className="badge" style={{ backgroundColor: 'rgba(56, 189, 248, 0.08)', color: '#38bdf8' }}>
              {manifest.capture_id}
            </span>
          )}
        </div>

        {/* Live Indicator */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          padding: '2px 8px',
          borderRadius: 12,
          backgroundColor: isLive ? 'rgba(34, 197, 94, 0.12)' : 'rgba(100, 116, 139, 0.15)',
          border: `1px solid ${isLive ? 'rgba(34, 197, 94, 0.3)' : 'rgba(100, 116, 139, 0.3)'}`,
          fontSize: 11,
          fontWeight: 700,
          fontFamily: 'var(--font-mono)',
          color: isLive ? '#4ade80' : 'var(--text-dim)',
        }}>
          <span style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            backgroundColor: isLive ? '#22c55e' : '#64748b',
            boxShadow: isLive ? '0 0 8px #22c55e' : 'none',
          }} />
          {isLive ? 'LIVE CAPTURE' : 'LOADED'}
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        {tabs.map(tab => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '6px 12px',
                borderRadius: 6,
                fontSize: 13,
                fontWeight: 600,
                border: 'none',
                background: isActive ? 'var(--bg-surface)' : 'transparent',
                color: isActive ? '#38bdf8' : 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                boxShadow: isActive ? 'inset 0 -2px 0 #38bdf8' : 'none',
              }}
            >
              <span>{tab.icon}</span>
              <span>{tab.label}</span>
              {tab.alert && (
                <span style={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  backgroundColor: '#f59e0b',
                }} />
              )}
            </button>
          );
        })}
      </nav>

      {/* Metrics Summary Strip */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, fontSize: 12, fontFamily: 'var(--font-mono)' }}>
        <div>
          <span style={{ color: 'var(--text-dim)' }}>TIME: </span>
          <span style={{ color: 'var(--text-main)', fontWeight: 600 }}>{durationSec}s</span>
        </div>
        <div>
          <span style={{ color: 'var(--text-dim)' }}>TOKENS: </span>
          <span style={{ color: '#38bdf8', fontWeight: 600 }}>{totalTokens.toLocaleString()}</span>
        </div>
        <div>
          <span style={{ color: 'var(--text-dim)' }}>COST: </span>
          <span style={{ color: '#34d399', fontWeight: 600 }}>${totalCost.toFixed(4)}</span>
        </div>
        <div>
          <span style={{ color: 'var(--text-dim)' }}>ERRORS: </span>
          <span style={{ color: errorCount > 0 ? '#f87171' : 'var(--text-muted)', fontWeight: 600 }}>
            {errorCount}
          </span>
        </div>

        <button
          className="btn btn-primary"
          onClick={onRunSimulation}
          disabled={isSimulating}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            backgroundColor: isSimulating ? 'rgba(56, 189, 248, 0.2)' : '#0284c7',
            color: '#ffffff',
            border: '1px solid #38bdf8',
            boxShadow: isSimulating ? '0 0 12px rgba(56, 189, 248, 0.5)' : 'none',
            fontWeight: 700,
            fontSize: 12,
            padding: '4px 10px',
            cursor: isSimulating ? 'not-allowed' : 'pointer',
          }}
          title="Stream live multi-agent simulation"
        >
          <span>{isSimulating ? '⏳' : '▶'}</span>
          <span>{isSimulating ? 'Simulating...' : 'Simulate Run'}</span>
        </button>

        <button className="btn" onClick={onOpenFile} title="Open an .apcap file">
          📂 Open
        </button>
      </div>
    </header>
  );
};
