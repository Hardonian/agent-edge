export type Protocol = 'A2A' | 'MCP' | 'MODEL' | 'TOOL' | 'HTTP' | 'POLICY' | 'OTLP' | 'CUSTOM';
export type Status = 'OK' | 'ERROR' | 'TIMEOUT' | 'CANCELLED' | 'UNKNOWN';

export interface Endpoint {
  name: string;
  kind: string;
  host?: string;
  port?: number;
}

export interface TokenUsage {
  input_tokens: number;
  output_tokens: number;
  cached_tokens?: number;
  total_tokens: number;
}

export interface Money {
  amount: number;
  currency: string;
  status: string;
  source?: string;
}

export interface PayloadRef {
  length: number;
  content_type?: string;
  attachment_path?: string;
  truncated: boolean;
  redacted: boolean;
  preview?: string;
}

export interface APCAPEvent {
  id: string;
  trace_id: string;
  parent_id?: string;
  timestamp: string;
  duration_ms: number;
  type: string;
  protocol: Protocol;
  operation: string;
  source: Endpoint;
  destination: Endpoint;
  status: Status;
  attributes?: Record<string, any>;
  tokens?: TokenUsage;
  cost?: Money;
  payload?: PayloadRef;
  provenance: string;
}

export interface Manifest {
  format: string;
  format_version: string;
  capture_id: string;
  created_at: string;
  completed_at?: string;
  agentpcap_version: string;
  host_metadata: {
    os: string;
    arch: string;
    go_version?: string;
  };
  capture_mode: string;
  redaction_mode: string;
  protocols_seen: Protocol[];
  event_count: number;
  hashes: Record<string, string>;
}

export interface CaptureMetadata {
  title?: string;
  description?: string;
  total_duration_ms: number;
  total_tokens: TokenUsage;
  total_cost: number;
  currency: string;
  agent_count: number;
  model_count: number;
  tool_count: number;
  error_count: number;
  custom_labels?: Record<string, string>;
}

export interface Finding {
  type: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  explanation: string;
  evidence?: Record<string, any>;
  event_ids: string[];
  suggested_fix: string;
  analyzer_version: string;
}

export interface CriticalPathStep {
  event_id: string;
  operation: string;
  protocol: string;
  duration_ms: number;
  percent_of_total: number;
  status: string;
}

export interface CriticalPathReport {
  total_wall_clock_ms: number;
  dominant_event: CriticalPathStep;
  steps: CriticalPathStep[];
  bottleneck_type: string;
  summary: string;
}

export interface FlameNode {
  name: string;
  value: number;
  category: string;
  count: number;
  children?: FlameNode[];
}

export interface DiffResult {
  before_id: string;
  after_id: string;
  latency_ms: { before: number; after: number; delta: number; pct: number };
  tokens: { before: number; after: number; delta: number; pct: number };
  cost: { before: number; after: number; delta: number; pct: number };
  errors: { before: number; after: number; delta: number; pct: number };
  model_calls: { before: number; after: number; delta: number };
  tool_calls: { before: number; after: number; delta: number };
  delegations: { before: number; after: number; delta: number };
  changed_ops?: { operation: string; before: number; after: number; delta: number }[];
  resolved_pathologies?: string[];
  introduced_pathologies?: string[];
}
