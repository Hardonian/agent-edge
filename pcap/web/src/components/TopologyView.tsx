import React, { useState, useMemo } from 'react';
import { APCAPEvent } from '../types';

interface TopologyViewProps {
  events: APCAPEvent[];
  onSelectEvent: (event: APCAPEvent) => void;
}

interface GraphNode {
  id: string;
  name: string;
  kind: string;
  column: 'clients' | 'agents' | 'tools' | 'models';
  x: number;
  y: number;
  callCount: number;
  errorCount: number;
  totalDurationMs: number;
  totalTokens: number;
  totalCost: number;
  operations: string[];
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  protocol: string;
  operation: string;
  calls: number;
  errors: number;
  lastDurationMs: number;
  lastActive: number;
}

export const TopologyView: React.FC<TopologyViewProps> = ({ events, onSelectEvent }) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [zoom, setZoom] = useState<number>(1);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  // Compute Nodes and Edges from Events
  const { nodes, edges } = useMemo(() => {
    const nodeMap = new Map<string, GraphNode>();
    const edgeMap = new Map<string, GraphEdge>();

    events.forEach(ev => {
      const srcName = ev.source.name || 'client';
      const dstName = ev.destination.name || 'service';
      const srcKind = ev.source.kind || 'agent';
      const dstKind = ev.destination.kind || (ev.protocol === 'MODEL' ? 'model' : ev.protocol === 'MCP' ? 'mcp_server' : 'tool');

      // Determine appropriate swimlane column
      const getColumn = (kind: string, name: string): 'clients' | 'agents' | 'tools' | 'models' => {
        if (kind === 'client' || name.toLowerCase().includes('client') || name.toLowerCase().includes('user')) return 'clients';
        if (kind === 'agent') return 'agents';
        if (kind === 'model' || name.toLowerCase().includes('gemini') || name.toLowerCase().includes('gpt') || name.toLowerCase().includes('claude')) return 'models';
        return 'tools';
      };

      // Add/update source node
      if (!nodeMap.has(srcName)) {
        nodeMap.set(srcName, {
          id: srcName,
          name: srcName,
          kind: srcKind,
          column: getColumn(srcKind, srcName),
          x: 0,
          y: 0,
          callCount: 0,
          errorCount: 0,
          totalDurationMs: 0,
          totalTokens: 0,
          totalCost: 0,
          operations: [],
        });
      }
      const sNode = nodeMap.get(srcName)!;
      sNode.callCount++;

      // Add/update destination node
      if (!nodeMap.has(dstName)) {
        nodeMap.set(dstName, {
          id: dstName,
          name: dstName,
          kind: dstKind,
          column: getColumn(dstKind, dstName),
          x: 0,
          y: 0,
          callCount: 0,
          errorCount: 0,
          totalDurationMs: 0,
          totalTokens: 0,
          totalCost: 0,
          operations: [],
        });
      }
      const dNode = nodeMap.get(dstName)!;
      dNode.callCount++;
      dNode.totalDurationMs += ev.duration_ms;
      if (ev.tokens) dNode.totalTokens += ev.tokens.total_tokens;
      if (ev.cost) dNode.totalCost += ev.cost.amount;
      if (ev.status === 'ERROR' || ev.status === 'TIMEOUT') {
        dNode.errorCount++;
      }
      if (ev.operation && !dNode.operations.includes(ev.operation)) {
        dNode.operations.push(ev.operation);
      }

      // Add/update edge with operation name
      const edgeKey = `${srcName}->${dstName}`;
      if (!edgeMap.has(edgeKey)) {
        edgeMap.set(edgeKey, {
          id: edgeKey,
          source: srcName,
          target: dstName,
          protocol: ev.protocol,
          operation: ev.operation || '',
          calls: 0,
          errors: 0,
          lastDurationMs: ev.duration_ms,
          lastActive: new Date(ev.timestamp).getTime(),
        });
      }
      const edge = edgeMap.get(edgeKey)!;
      edge.calls++;
      edge.lastDurationMs = ev.duration_ms;
      if (ev.status === 'ERROR' || ev.status === 'TIMEOUT') {
        edge.errors++;
      }
    });

    // Layout nodes into clean, spacious swimlane columns
    const columns: Record<'clients' | 'agents' | 'tools' | 'models', GraphNode[]> = {
      clients: [],
      agents: [],
      tools: [],
      models: [],
    };

    nodeMap.forEach(n => {
      columns[n.column].push(n);
    });

    const colX = {
      clients: 160,
      agents: 510,
      tools: 880,
      models: 1220,
    };

    Object.entries(columns).forEach(([colKey, colNodes]) => {
      const x = colX[colKey as keyof typeof colX] || 500;
      const spacing = 140;
      const startY = 160 + Math.max(0, (4 - colNodes.length) * 45);

      colNodes.forEach((node, i) => {
        node.x = x;
        node.y = startY + i * spacing;
      });
    });

    return {
      nodes: Array.from(nodeMap.values()),
      edges: Array.from(edgeMap.values()),
    };
  }, [events]);

  // Node Styling Constants
  const getNodeMeta = (kind: string) => {
    switch (kind) {
      case 'agent':
        return { color: '#38bdf8', bg: '#0b192e', border: '#0284c7', icon: '🤖', label: 'AUTONOMOUS AGENT' };
      case 'model':
        return { color: '#34d399', bg: '#062016', border: '#059669', icon: '🧠', label: 'LLM INFERENCE' };
      case 'tool':
        return { color: '#c084fc', bg: '#1c132b', border: '#9333ea', icon: '🛠️', label: 'SYSTEM TOOL' };
      case 'mcp_server':
        return { color: '#fbbf24', bg: '#241b0b', border: '#d97706', icon: '⚡', label: 'MCP SERVER' };
      default:
        return { color: '#94a3b8', bg: '#131926', border: '#475569', icon: '👤', label: 'CLIENT DISPATCH' };
    }
  };

  const getEdgeColor = (proto: string) => {
    switch (proto) {
      case 'A2A': return '#38bdf8';
      case 'MCP': return '#fbbf24';
      case 'MODEL': return '#34d399';
      case 'TOOL': return '#c084fc';
      case 'POLICY': return '#f43f5e';
      default: return '#64748b';
    }
  };

  // Check if a node or edge is involved in the active workflow
  const activeFocusId = selectedNode?.id || hoveredNodeId;

  const isConnected = (nodeId: string) => {
    if (!activeFocusId) return true;
    if (nodeId === activeFocusId) return true;
    return edges.some(e =>
      (e.source === activeFocusId && e.target === nodeId) ||
      (e.target === activeFocusId && e.source === nodeId)
    );
  };

  const isEdgeConnected = (edge: GraphEdge) => {
    if (!activeFocusId) return true;
    return edge.source === activeFocusId || edge.target === activeFocusId;
  };

  const filteredEdges = useMemo(() => {
    if (protocolFilter === 'ALL') return edges;
    return edges.filter(e => e.protocol.toUpperCase() === protocolFilter);
  }, [edges, protocolFilter]);

  return (
    <div style={{ position: 'relative', width: '100%', height: 'calc(100vh - 54px)', backgroundColor: 'var(--bg-app)', display: 'flex', overflow: 'hidden' }}>
      {/* Interactive Controls Overlay Toolbar */}
      <div style={{
        position: 'absolute',
        top: 16,
        left: 20,
        zIndex: 10,
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        backgroundColor: 'rgba(13, 19, 31, 0.92)',
        backdropFilter: 'blur(12px)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 10,
        padding: '6px 14px',
        boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, borderRight: '1px solid var(--border-subtle)', paddingRight: 12 }}>
          <span style={{ fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>WORKFLOW FILTER:</span>
          {['ALL', 'A2A', 'MCP', 'MODEL', 'TOOL'].map(proto => (
            <button
              key={proto}
              onClick={() => setProtocolFilter(proto)}
              style={{
                padding: '4px 8px',
                borderRadius: 6,
                fontSize: 11,
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
                border: 'none',
                cursor: 'pointer',
                backgroundColor: protocolFilter === proto ? '#0284c7' : 'rgba(255,255,255,0.06)',
                color: protocolFilter === proto ? '#ffffff' : 'var(--text-muted)',
                transition: 'all 0.15s ease',
              }}
            >
              {proto}
            </button>
          ))}
        </div>

        {/* Zoom Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>ZOOM:</span>
          <button
            onClick={() => setZoom(z => Math.min(1.5, z + 0.1))}
            style={{ width: 26, height: 26, borderRadius: 6, backgroundColor: 'rgba(255,255,255,0.08)', border: 'none', color: '#fff', cursor: 'pointer', fontWeight: 'bold' }}
            title="Zoom In"
          >
            +
          </button>
          <button
            onClick={() => setZoom(z => Math.max(0.6, z - 0.1))}
            style={{ width: 26, height: 26, borderRadius: 6, backgroundColor: 'rgba(255,255,255,0.08)', border: 'none', color: '#fff', cursor: 'pointer', fontWeight: 'bold' }}
            title="Zoom Out"
          >
            -
          </button>
          <button
            onClick={() => setZoom(1)}
            style={{ padding: '2px 8px', height: 26, borderRadius: 6, backgroundColor: 'rgba(255,255,255,0.08)', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 11, fontFamily: 'var(--font-mono)' }}
            title="Reset Zoom"
          >
            {(zoom * 100).toFixed(0)}%
          </button>
        </div>

        {activeFocusId && (
          <button
            onClick={() => { setSelectedNode(null); setSelectedEdge(null); setHoveredNodeId(null); }}
            style={{
              padding: '4px 10px',
              borderRadius: 6,
              backgroundColor: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid rgba(239, 68, 68, 0.4)',
              color: '#f87171',
              fontSize: 11,
              fontWeight: 700,
              cursor: 'pointer',
            }}
          >
            ✕ Reset Isolation
          </button>
        )}
      </div>

      {/* Main Interactive Canvas */}
      <div style={{ flex: 1, height: '100%', position: 'relative', overflow: 'hidden' }}>
        <svg
          width="100%"
          height="100%"
          viewBox="0 0 1440 850"
          style={{
            transform: `scale(${zoom})`,
            transformOrigin: 'center center',
            transition: 'transform 0.2s ease-out',
          }}
        >
          <defs>
            {/* Arrowhead Markers */}
            <marker id="arrow" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
            </marker>
            <marker id="arrow-a2a" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />
            </marker>
            <marker id="arrow-mcp" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#fbbf24" />
            </marker>
            <marker id="arrow-model" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#34d399" />
            </marker>
            <marker id="arrow-tool" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#c084fc" />
            </marker>

            {/* Grid background dots */}
            <pattern id="grid-dots" width="36" height="36" patternUnits="userSpaceOnUse">
              <circle cx="18" cy="18" r="1.2" fill="rgba(255, 255, 255, 0.06)" />
            </pattern>

            {/* Glow Filter */}
            <filter id="card-glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="8" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Background Canvas Grid */}
          <rect width="100%" height="100%" fill="url(#grid-dots)" />

          {/* Swimlane Column Cards (Visual Workflow Lanes) */}
          <g>
            {/* Lane 1: Orchestrators */}
            <g transform="translate(30, 70)">
              <rect width="260" height="740" rx="14" fill="rgba(15, 23, 42, 0.45)" stroke="rgba(255, 255, 255, 0.05)" strokeWidth="1" />
              <rect width="260" height="42" rx="14" fill="rgba(30, 41, 59, 0.6)" />
              <text x="16" y="26" fill="#94a3b8" fontSize="12" fontWeight="800" fontFamily="var(--font-mono)" letterSpacing="0.05em">
                👤 ORCHESTRATION &amp; CLIENTS
              </text>
            </g>

            {/* Lane 2: Autonomous Agents */}
            <g transform="translate(370, 70)">
              <rect width="280" height="740" rx="14" fill="rgba(2, 132, 199, 0.04)" stroke="rgba(56, 189, 248, 0.15)" strokeWidth="1" />
              <rect width="280" height="42" rx="14" fill="rgba(2, 132, 199, 0.15)" />
              <text x="16" y="26" fill="#38bdf8" fontSize="12" fontWeight="800" fontFamily="var(--font-mono)" letterSpacing="0.05em">
                🤖 AUTONOMOUS AGENTS (A2A)
              </text>
            </g>

            {/* Lane 3: MCP Servers & Tools */}
            <g transform="translate(740, 70)">
              <rect width="280" height="740" rx="14" fill="rgba(245, 158, 11, 0.03)" stroke="rgba(251, 191, 36, 0.15)" strokeWidth="1" />
              <rect width="280" height="42" rx="14" fill="rgba(245, 158, 11, 0.12)" />
              <text x="16" y="26" fill="#fbbf24" fontSize="12" fontWeight="800" fontFamily="var(--font-mono)" letterSpacing="0.05em">
                ⚡ MCP SERVERS &amp; TOOLS
              </text>
            </g>

            {/* Lane 4: Model Inference */}
            <g transform="translate(1080, 70)">
              <rect width="280" height="740" rx="14" fill="rgba(16, 185, 129, 0.03)" stroke="rgba(52, 211, 153, 0.15)" strokeWidth="1" />
              <rect width="280" height="42" rx="14" fill="rgba(16, 185, 129, 0.12)" />
              <text x="16" y="26" fill="#34d399" fontSize="12" fontWeight="800" fontFamily="var(--font-mono)" letterSpacing="0.05em">
                🧠 MODEL INFERENCE (LLMS)
              </text>
            </g>
          </g>

          {/* Workflow Edges with Action Badges */}
          <g>
            {filteredEdges.map(e => {
              const src = nodes.find(n => n.id === e.source);
              const dst = nodes.find(n => n.id === e.target);
              if (!src || !dst) return null;

              const isSelected = selectedEdge?.id === e.id;
              const isHighlight = isEdgeConnected(e);
              const color = e.errors > 0 ? '#f87171' : getEdgeColor(e.protocol);
              const opacity = activeFocusId ? (isHighlight ? 1 : 0.15) : 0.75;

              // Compute smooth bezier trajectory
              const dx = dst.x - src.x;
              const cx1 = src.x + dx * 0.45;
              const cy1 = src.y;
              const cx2 = src.x + dx * 0.55;
              const cy2 = dst.y;
              const pathData = `M ${src.x + 110} ${src.y + 45} C ${cx1} ${cy1 + 45}, ${cx2} ${cy2 + 45}, ${dst.x - 110} ${dst.y + 45}`;

              const midX = (src.x + dst.x) / 2;
              const midY = (src.y + dst.y) / 2 + 45;

              // Format clean short action name
              const cleanOp = e.operation ? e.operation.split(':').pop() || e.operation : e.protocol;

              return (
                <g
                  key={e.id}
                  onClick={() => { setSelectedEdge(e); setSelectedNode(null); }}
                  style={{ cursor: 'pointer', transition: 'opacity 0.2s ease' }}
                  opacity={opacity}
                >
                  {/* Glowing Outline when highlighted */}
                  {isHighlight && activeFocusId && (
                    <path
                      d={pathData}
                      fill="none"
                      stroke={color}
                      strokeWidth="6"
                      strokeOpacity="0.25"
                    />
                  )}

                  {/* Main Edge Wire */}
                  <path
                    d={pathData}
                    fill="none"
                    stroke={color}
                    strokeWidth={isSelected ? 3.5 : 2}
                    strokeDasharray={e.protocol === 'A2A' ? '6 4' : 'none'}
                    markerEnd={`url(#arrow-${e.protocol.toLowerCase()})`}
                  />

                  {/* Live Packet Animation Particle */}
                  <circle r="4" fill={color}>
                    <animateMotion path={pathData} dur={`${Math.max(1.5, 3 - e.calls * 0.2)}s`} repeatCount="indefinite" />
                  </circle>

                  {/* Edge Action Pill Capsule (Shows exact workflow action on canvas) */}
                  <g transform={`translate(${midX}, ${midY})`}>
                    <rect
                      x="-65"
                      y="-14"
                      width="130"
                      height="26"
                      rx="13"
                      fill="#0d1424"
                      stroke={color}
                      strokeWidth={isSelected ? "2" : "1.2"}
                      style={{ filter: 'drop-shadow(0 4px 10px rgba(0,0,0,0.5))' }}
                    />
                    <text
                      x="0"
                      y="4"
                      textAnchor="middle"
                      fill="#ffffff"
                      fontSize="10"
                      fontFamily="var(--font-mono)"
                      fontWeight="700"
                    >
                      {e.protocol} • {cleanOp.length > 10 ? cleanOp.slice(0, 9) + '…' : cleanOp} ({e.calls}x)
                    </text>
                  </g>
                </g>
              );
            })}
          </g>

          {/* Large, Super-Clear Component Cards */}
          <g>
            {nodes.map(n => {
              const isSelected = selectedNode?.id === n.id;
              const isConnectedNode = isConnected(n.id);
              const meta = getNodeMeta(n.kind);
              const opacity = activeFocusId ? (isConnectedNode ? 1 : 0.2) : 1;

              return (
                <g
                  key={n.id}
                  transform={`translate(${n.x - 110}, ${n.y})`}
                  onClick={() => { setSelectedNode(n); setSelectedEdge(null); }}
                  onMouseEnter={() => setHoveredNodeId(n.id)}
                  onMouseLeave={() => setHoveredNodeId(null)}
                  style={{ cursor: 'pointer', transition: 'all 0.2s ease' }}
                  opacity={opacity}
                >
                  {/* Outer Selection Glow */}
                  {isSelected && (
                    <rect
                      x="-6"
                      y="-6"
                      width="232"
                      height="102"
                      rx="16"
                      fill="none"
                      stroke={meta.color}
                      strokeWidth="2.5"
                      filter="url(#card-glow)"
                    />
                  )}

                  {/* Main Component Card Box */}
                  <rect
                    x="0"
                    y="0"
                    width="220"
                    height="90"
                    rx="12"
                    fill={meta.bg}
                    stroke={isSelected ? meta.color : meta.border}
                    strokeWidth={isSelected ? "2" : "1.2"}
                    style={{
                      boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
                    }}
                  />

                  {/* Left Accent Stripe */}
                  <rect
                    x="0"
                    y="0"
                    width="6"
                    height="90"
                    rx="3"
                    fill={meta.color}
                  />

                  {/* Component Icon Box */}
                  <g transform="translate(14, 14)">
                    <rect width="28" height="28" rx="8" fill="rgba(255,255,255,0.06)" />
                    <text x="14" y="20" fontSize="14" textAnchor="middle">{meta.icon}</text>
                  </g>

                  {/* Component Name Header */}
                  <text
                    x="50"
                    y="27"
                    fill="#f8fafc"
                    fontSize="13"
                    fontWeight="800"
                    fontFamily="var(--font-sans)"
                  >
                    {n.name.length > 18 ? n.name.slice(0, 17) + '…' : n.name}
                  </text>

                  {/* Category / Kind Badge */}
                  <g transform="translate(50, 34)">
                    <rect width="90" height="15" rx="3" fill="rgba(255,255,255,0.08)" />
                    <text x="45" y="11" fill={meta.color} fontSize="8" fontWeight="800" fontFamily="var(--font-mono)" textAnchor="middle" letterSpacing="0.05em">
                      {meta.label}
                    </text>
                  </g>

                  {/* Error Indicator Badge */}
                  {n.errorCount > 0 ? (
                    <g transform="translate(186, 12)">
                      <circle r="9" fill="#ef4444" />
                      <text x="0" y="3" textAnchor="middle" fill="#ffffff" fontSize="10" fontWeight="900">
                        {n.errorCount}
                      </text>
                    </g>
                  ) : (
                    <g transform="translate(196, 20)">
                      <circle r="4" fill="#22c55e" />
                    </g>
                  )}

                  {/* Divider Line */}
                  <line x1="12" y1="56" x2="208" y2="56" stroke="rgba(255,255,255,0.08)" strokeWidth="1" />

                  {/* Bottom Metric Pills */}
                  <g transform="translate(14, 72)">
                    <text fill="#94a3b8" fontSize="10" fontFamily="var(--font-mono)" fontWeight="600">
                      ⚡ <tspan fill="#f1f5f9">{n.callCount} calls</tspan>
                    </text>
                    <text x="75" fill="#94a3b8" fontSize="10" fontFamily="var(--font-mono)" fontWeight="600">
                      ⏱ <tspan fill="#f1f5f9">{n.totalDurationMs.toFixed(0)}ms</tspan>
                    </text>
                    {n.totalTokens > 0 && (
                      <text x="145" fill="#94a3b8" fontSize="10" fontFamily="var(--font-mono)" fontWeight="600">
                        🪙 <tspan fill="#38bdf8">{(n.totalTokens / 1000).toFixed(1)}k</tspan>
                      </text>
                    )}
                  </g>
                </g>
              );
            })}
          </g>
        </svg>

        {/* Legend Overlay at Bottom Left */}
        <div style={{
          position: 'absolute',
          bottom: 16,
          left: 20,
          backgroundColor: 'rgba(13, 19, 31, 0.92)',
          backdropFilter: 'blur(10px)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 8,
          padding: '8px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: 20,
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
          boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, backgroundColor: '#38bdf8' }} />
            <span style={{ color: '#f8fafc', fontWeight: 600 }}>A2A Delegation</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, backgroundColor: '#fbbf24' }} />
            <span style={{ color: '#f8fafc', fontWeight: 600 }}>MCP JSON-RPC</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, backgroundColor: '#34d399' }} />
            <span style={{ color: '#f8fafc', fontWeight: 600 }}>Model Inference</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, backgroundColor: '#c084fc' }} />
            <span style={{ color: '#f8fafc', fontWeight: 600 }}>System Tool</span>
          </div>
        </div>
      </div>

      {/* Inspector Side Drawer */}
      {(selectedNode || selectedEdge) && (
        <aside style={{
          width: 360,
          borderLeft: '1px solid var(--border-subtle)',
          backgroundColor: 'var(--bg-card)',
          padding: 24,
          display: 'flex',
          flexDirection: 'column',
          gap: 18,
          overflowY: 'auto',
          boxShadow: '-10px 0 30px rgba(0,0,0,0.5)',
          zIndex: 20,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 11, fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#38bdf8', letterSpacing: '0.08em' }}>
              {selectedNode ? 'COMPONENT TELEMETRY' : 'WORKFLOW EDGE DETAILS'}
            </span>
            <button
              onClick={() => { setSelectedNode(null); setSelectedEdge(null); }}
              style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16 }}
            >
              ✕
            </button>
          </div>

          {selectedNode && (
            <>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <span style={{ fontSize: 24 }}>{getNodeMeta(selectedNode.kind).icon}</span>
                  <h3 style={{ fontSize: 18, color: '#f8fafc', fontWeight: 800, margin: 0 }}>{selectedNode.name}</h3>
                </div>
                <span className={`badge badge-${selectedNode.kind === 'agent' ? 'a2a' : selectedNode.kind === 'model' ? 'model' : 'tool'}`}>
                  {getNodeMeta(selectedNode.kind).label}
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13, fontFamily: 'var(--font-mono)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 8 }}>
                  <span style={{ color: 'var(--text-dim)' }}>Total Calls</span>
                  <span style={{ color: 'var(--text-main)', fontWeight: 700 }}>{selectedNode.callCount}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 8 }}>
                  <span style={{ color: 'var(--text-dim)' }}>Total Wall Time</span>
                  <span style={{ color: 'var(--text-main)', fontWeight: 700 }}>{selectedNode.totalDurationMs.toFixed(1)} ms</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 8 }}>
                  <span style={{ color: 'var(--text-dim)' }}>Tokens Consumed</span>
                  <span style={{ color: '#38bdf8', fontWeight: 700 }}>{selectedNode.totalTokens.toLocaleString()}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 8 }}>
                  <span style={{ color: 'var(--text-dim)' }}>Estimated Cost</span>
                  <span style={{ color: '#34d399', fontWeight: 700 }}>${selectedNode.totalCost.toFixed(4)} USD</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 8 }}>
                  <span style={{ color: 'var(--text-dim)' }}>Error Count</span>
                  <span style={{ color: selectedNode.errorCount > 0 ? '#f87171' : '#34d399', fontWeight: 700 }}>
                    {selectedNode.errorCount}
                  </span>
                </div>
              </div>

              {selectedNode.operations.length > 0 && (
                <div>
                  <h4 style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 8, fontFamily: 'var(--font-mono)' }}>
                    ACTIVE OPERATIONS ({selectedNode.operations.length})
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {selectedNode.operations.map(op => (
                      <div key={op} style={{ padding: '6px 10px', backgroundColor: 'rgba(255,255,255,0.04)', borderRadius: 6, fontSize: 11, fontFamily: 'var(--font-mono)', color: '#f1f5f9' }}>
                        {op}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <button
                className="btn btn-primary"
                style={{ marginTop: 8, justifyContent: 'center', padding: '10px 16px', fontSize: 13, fontWeight: 700 }}
                onClick={() => {
                  const match = events.find(e => e.source.name === selectedNode.name || e.destination.name === selectedNode.name);
                  if (match) onSelectEvent(match);
                }}
              >
                Inspect Raw Packets
              </button>
            </>
          )}

          {selectedEdge && (
            <>
              <div>
                <span className="badge badge-mcp" style={{ marginBottom: 8 }}>
                  {selectedEdge.protocol} PROTOCOL
                </span>
                <h4 style={{ fontSize: 16, color: '#f8fafc', margin: '4px 0 0 0', fontWeight: 700 }}>
                  {selectedEdge.source} ➔ {selectedEdge.target}
                </h4>
                {selectedEdge.operation && (
                  <p style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 6 }}>
                    Op: {selectedEdge.operation}
                  </p>
                )}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13, fontFamily: 'var(--font-mono)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 8 }}>
                  <span style={{ color: 'var(--text-dim)' }}>Invocations</span>
                  <span style={{ color: 'var(--text-main)', fontWeight: 700 }}>{selectedEdge.calls}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 8 }}>
                  <span style={{ color: 'var(--text-dim)' }}>Last Duration</span>
                  <span style={{ color: 'var(--text-main)', fontWeight: 700 }}>{selectedEdge.lastDurationMs.toFixed(1)} ms</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 8 }}>
                  <span style={{ color: 'var(--text-dim)' }}>Errors</span>
                  <span style={{ color: selectedEdge.errors > 0 ? '#f87171' : '#34d399', fontWeight: 700 }}>
                    {selectedEdge.errors}
                  </span>
                </div>
              </div>

              <button
                className="btn btn-primary"
                style={{ marginTop: 8, justifyContent: 'center', padding: '10px 16px', fontSize: 13, fontWeight: 700 }}
                onClick={() => {
                  const match = events.find(e => e.source.name === selectedEdge.source && e.destination.name === selectedEdge.target);
                  if (match) onSelectEvent(match);
                }}
              >
                Inspect Edge Packets
              </button>
            </>
          )}
        </aside>
      )}
    </div>
  );
};
