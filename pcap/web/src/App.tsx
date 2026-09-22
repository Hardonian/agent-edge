import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { TopologyView } from './components/TopologyView';
import { TimelineWaterfall } from './components/TimelineWaterfall';
import { PacketsList } from './components/PacketsList';
import { PacketInspector } from './components/PacketInspector';
import { FlamegraphView } from './components/FlamegraphView';
import { FindingsView } from './components/FindingsView';
import { DiffView } from './components/DiffView';
import { MetadataView } from './components/MetadataView';
import { APCAPEvent, Manifest, CaptureMetadata, Finding, CriticalPathReport } from './types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('topology');
  const [events, setEvents] = useState<APCAPEvent[]>([]);
  const [manifest, setManifest] = useState<Manifest | undefined>();
  const [metadata, setMetadata] = useState<CaptureMetadata | undefined>();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [criticalPath, setCriticalPath] = useState<CriticalPathReport | undefined>();
  const [selectedEvent, setSelectedEvent] = useState<APCAPEvent | null>(null);
  const [isLive, setIsLive] = useState(true);
  const [dragOver, setDragOver] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);

  // Fetch initial session state
  const fetchSession = useCallback(async () => {
    try {
      const res = await fetch('/api/session');
      if (res.ok) {
        const data = await res.json();
        if (data.manifest) setManifest(data.manifest);
        if (data.metadata) setMetadata(data.metadata);
        if (data.events) setEvents(data.events);
      }
    } catch {
      // Offline / standalone mode fallback
    }

    try {
      const fRes = await fetch('/api/findings');
      if (fRes.ok) {
        const fData = await fRes.json();
        setFindings(fData);
      }
    } catch {}

    try {
      const cpRes = await fetch('/api/critical-path');
      if (cpRes.ok) {
        const cpData = await cpRes.json();
        setCriticalPath(cpData);
      }
    } catch {}
  }, []);

  const handleRunSimulation = async () => {
    setIsSimulating(true);
    setEvents([]);
    try {
      await fetch('/api/simulate', { method: 'POST' });
    } catch (err) {
      console.error('Failed to trigger simulation', err);
    }
    setTimeout(() => {
      setIsSimulating(false);
      fetchSession();
    }, 2000);
  };

  const handleLoadDemo = async () => {
    try {
      await fetch('/api/load-demo', { method: 'POST' });
      fetchSession();
    } catch (err) {
      console.error('Failed loading demo', err);
    }
  };

  useEffect(() => {
    fetchSession();

    // Setup Live SSE stream
    const eventSource = new EventSource('/api/stream');
    eventSource.onopen = () => setIsLive(true);
    eventSource.onmessage = (e) => {
      try {
        const newEv: APCAPEvent = JSON.parse(e.data);
        setEvents(prev => [...prev, newEv]);

        // Refresh findings periodically or after events
        fetchSession();
      } catch {}
    };
    eventSource.onerror = () => {
      setIsLive(false);
    };

    return () => {
      eventSource.close();
    };
  }, [fetchSession]);

  // Handle Drag & Drop of .apcap file
  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      const formData = new FormData();
      formData.append('file', file);

      try {
        const res = await fetch('/api/upload', {
          method: 'POST',
          body: formData,
        });
        if (res.ok) {
          fetchSession();
        }
      } catch (err) {
        console.error('Failed uploading .apcap', err);
      }
    }
  };

  const handleOpenFileInput = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.apcap';
    input.onchange = async (e: any) => {
      const file = e.target.files?.[0];
      if (!file) return;
      const formData = new FormData();
      formData.append('file', file);
      try {
        const res = await fetch('/api/upload', { method: 'POST', body: formData });
        if (res.ok) fetchSession();
      } catch (err) {
        console.error('Failed uploading file', err);
      }
    };
    input.click();
  };

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        width: '100vw',
        backgroundColor: 'var(--bg-app)',
        position: 'relative',
      }}
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
    >
      {/* Top Header Navigation */}
      <Header
        manifest={manifest}
        metadata={metadata}
        findings={findings}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isLive={isLive}
        onOpenFile={handleOpenFileInput}
        onRunSimulation={handleRunSimulation}
        isSimulating={isSimulating}
      />

      {/* Main View Area */}
      <main style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
        {events.length === 0 && (
          <div style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: 'rgba(10, 14, 23, 0.95)',
            zIndex: 10,
            padding: 32,
          }}>
            <div style={{
              maxWidth: 680,
              width: '100%',
              backgroundColor: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 16,
              padding: 36,
              textAlign: 'center',
              boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6), 0 0 40px rgba(56, 189, 248, 0.08)',
            }}>
              <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 64, height: 64, borderRadius: 16, backgroundColor: 'rgba(56, 189, 248, 0.12)', border: '1px solid rgba(56, 189, 248, 0.3)', marginBottom: 20 }}>
                <span style={{ fontSize: 28 }}>🔍</span>
              </div>
              <h2 style={{ fontSize: 26, fontWeight: 800, color: '#f8fafc', margin: '0 0 10px 0', letterSpacing: '-0.02em' }}>
                Wireshark for AI Agents
              </h2>
              <p style={{ fontSize: 14, color: 'var(--text-muted)', lineHeight: 1.6, margin: '0 0 24px 0' }}>
                Capture A2A, MCP, model, and tool traffic in one local timeline. See the whole agent graph live with zero external accounts or API keys.
              </p>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12, marginBottom: 28, flexWrap: 'wrap' }}>
                <button
                  className="btn btn-primary"
                  onClick={handleRunSimulation}
                  disabled={isSimulating}
                  style={{
                    padding: '10px 20px',
                    fontSize: 14,
                    fontWeight: 700,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    backgroundColor: '#0284c7',
                    border: '1px solid #38bdf8',
                    boxShadow: '0 0 20px rgba(56, 189, 248, 0.4)',
                    cursor: 'pointer',
                  }}
                >
                  <span>{isSimulating ? '⏳' : '▶'}</span>
                  <span>{isSimulating ? 'Streaming Simulation...' : 'Run Live Simulation'}</span>
                </button>
                <button
                  className="btn"
                  onClick={handleLoadDemo}
                  style={{ padding: '10px 18px', fontSize: 14, fontWeight: 600 }}
                >
                  ⚡ Load Demo Capture
                </button>
                <button
                  className="btn"
                  onClick={handleOpenFileInput}
                  style={{ padding: '10px 18px', fontSize: 14, fontWeight: 600 }}
                >
                  📂 Open .apcap File
                </button>
              </div>

              <div style={{ display: 'flex', justifyContent: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span className="badge" style={{ backgroundColor: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', border: '1px solid rgba(168, 85, 247, 0.3)' }}>A2A Delegation</span>
                <span className="badge" style={{ backgroundColor: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.3)' }}>MCP JSON-RPC</span>
                <span className="badge" style={{ backgroundColor: 'rgba(6, 182, 212, 0.15)', color: '#22d3ee', border: '1px solid rgba(6, 182, 212, 0.3)' }}>Gemini & OpenAI</span>
                <span className="badge" style={{ backgroundColor: 'rgba(16, 185, 129, 0.15)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.3)' }}>Cost Flamegraphs</span>
                <span className="badge" style={{ backgroundColor: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.3)' }}>Pathology Detection</span>
              </div>
            </div>
          </div>
        )}
        {activeTab === 'topology' && (
          <TopologyView events={events} onSelectEvent={setSelectedEvent} />
        )}
        {activeTab === 'timeline' && (
          <TimelineWaterfall
            events={events}
            criticalPath={criticalPath}
            onSelectEvent={setSelectedEvent}
            selectedEventId={selectedEvent?.id}
          />
        )}
        {activeTab === 'packets' && (
          <PacketsList
            events={events}
            onSelectEvent={setSelectedEvent}
            selectedEventId={selectedEvent?.id}
          />
        )}
        {activeTab === 'flamegraph' && (
          <FlamegraphView events={events} />
        )}
        {activeTab === 'findings' && (
          <FindingsView
            findings={findings}
            events={events}
            onSelectEvent={setSelectedEvent}
          />
        )}
        {activeTab === 'diff' && (
          <DiffView />
        )}
        {activeTab === 'metadata' && (
          <MetadataView manifest={manifest} metadata={metadata} />
        )}

        {/* Slide-over Packet Inspector */}
        <PacketInspector
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />

        {/* Drag and drop overlay */}
        {dragOver && (
          <div style={{
            position: 'absolute',
            inset: 0,
            backgroundColor: 'rgba(8, 12, 20, 0.88)',
            border: '2px dashed #38bdf8',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100,
            fontSize: 18,
            fontWeight: 700,
            color: '#38bdf8',
            fontFamily: 'var(--font-mono)',
          }}>
            Drop .apcap capture file to inspect
          </div>
        )}
      </main>
    </div>
  );
};
export default App;
