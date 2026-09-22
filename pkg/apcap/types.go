package apcap

import (
	"encoding/json"
	"time"
)

// CurrentFormatVersion is the semantic version of the APCAP specification implemented by this package.
const CurrentFormatVersion = "1.0.0"

// FormatIdentifier is the magic string used in manifests.
const FormatIdentifier = "apcap"

// Protocol identifies the application or transport protocol observed.
type Protocol string

const (
	ProtocolA2A    Protocol = "A2A"
	ProtocolMCP    Protocol = "MCP"
	ProtocolModel  Protocol = "MODEL"
	ProtocolTool   Protocol = "TOOL"
	ProtocolHTTP   Protocol = "HTTP"
	ProtocolPolicy Protocol = "POLICY"
	ProtocolOTLP   Protocol = "OTLP"
	ProtocolCustom Protocol = "CUSTOM"
)

// EventType classifies the semantic nature of an event.
type EventType string

const (
	EventAgentStart    EventType = "AGENT_START"
	EventAgentEnd      EventType = "AGENT_END"
	EventAgentInvoke   EventType = "AGENT_INVOKE"
	EventAgentResponse EventType = "AGENT_RESPONSE"
	EventDelegation    EventType = "DELEGATION"

	EventA2ARequest  EventType = "A2A_REQUEST"
	EventA2AResponse EventType = "A2A_RESPONSE"
	EventA2AStream   EventType = "A2A_STREAM"
	EventA2AError    EventType = "A2A_ERROR"

	EventMCPDiscover   EventType = "MCP_DISCOVER"
	EventMCPToolsList  EventType = "MCP_TOOLS_LIST"
	EventMCPToolCall   EventType = "MCP_TOOL_CALL"
	EventMCPToolResult EventType = "MCP_TOOL_RESULT"
	EventMCPError      EventType = "MCP_ERROR"

	EventModelRequest  EventType = "MODEL_REQUEST"
	EventModelStream   EventType = "MODEL_STREAM"
	EventModelResponse EventType = "MODEL_RESPONSE"
	EventModelError    EventType = "MODEL_ERROR"

	EventToolCall   EventType = "TOOL_CALL"
	EventToolResult EventType = "TOOL_RESULT"

	EventHTTPRequest  EventType = "HTTP_REQUEST"
	EventHTTPResponse EventType = "HTTP_RESPONSE"

	EventPolicyDecision EventType = "POLICY_DECISION"

	EventRetry       EventType = "RETRY"
	EventTimeout     EventType = "TIMEOUT"
	EventCircuitOpen EventType = "CIRCUIT_OPEN"

	EventError   EventType = "ERROR"
	EventWarning EventType = "WARNING"
	EventCustom  EventType = "CUSTOM"
)

// Status represents the outcome of an operation.
type Status string

const (
	StatusOK        Status = "OK"
	StatusError     Status = "ERROR"
	StatusTimeout   Status = "TIMEOUT"
	StatusCancelled Status = "CANCELLED"
	StatusUnknown   Status = "UNKNOWN"
)

// Provenance represents the source or derivation method of captured data.
type Provenance string

const (
	ProvenanceObserved       Provenance = "OBSERVED"
	ProvenanceProtocolParsed Provenance = "PROTOCOL_PARSED"
	ProvenanceOTel           Provenance = "OTEL"
	ProvenanceSDK            Provenance = "SDK"
	ProvenanceDerived        Provenance = "DERIVED"
	ProvenanceEstimated      Provenance = "ESTIMATED"
	ProvenanceUnknown        Provenance = "UNKNOWN"
)

// Endpoint represents a logical node in the agent graph.
type Endpoint struct {
	Name     string            `json:"name"`
	Kind     string            `json:"kind"` // "agent", "model", "tool", "mcp_server", "service", "client"
	Host     string            `json:"host,omitempty"`
	Port     int               `json:"port,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// TokenUsage captures granular token counts.
type TokenUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	CachedTokens int64 `json:"cached_tokens,omitempty"`
	TotalTokens  int64 `json:"total_tokens"`
}

// CostStatus indicates whether a cost is exact or estimated.
type CostStatus string

const (
	CostStatusMeasured         CostStatus = "MEASURED"
	CostStatusProviderReported CostStatus = "PROVIDER_REPORTED"
	CostStatusEstimated        CostStatus = "ESTIMATED"
	CostStatusUnknown          CostStatus = "UNKNOWN"
)

// Money represents monetary cost.
type Money struct {
	Amount   float64    `json:"amount"` // in units of Currency (e.g. 0.0015 USD)
	Currency string     `json:"currency"`
	Status   CostStatus `json:"status"`
	Source   string     `json:"source,omitempty"` // e.g. "pricing-v1-snapshot", "anthropic-header"
}

// PayloadRef references captured payload or sanitized preview.
type PayloadRef struct {
	Length         int64  `json:"length"`
	ContentType    string `json:"content_type,omitempty"`
	AttachmentPath string `json:"attachment_path,omitempty"`
	Truncated      bool   `json:"truncated"`
	Redacted       bool   `json:"redacted"`
	Preview        string `json:"preview,omitempty"` // sanitized short snippet for inspector
}

// Event represents a single normalized packet or trace event in AgentPCAP.
type Event struct {
	ID          string         `json:"id"`
	TraceID     string         `json:"trace_id"`
	ParentID    string         `json:"parent_id,omitempty"`
	Timestamp   time.Time      `json:"timestamp"`
	DurationMs  float64        `json:"duration_ms"`
	Type        EventType      `json:"type"`
	Protocol    Protocol       `json:"protocol"`
	Operation   string         `json:"operation"`
	Source      Endpoint       `json:"source"`
	Destination Endpoint       `json:"destination"`
	Status      Status         `json:"status"`
	Attributes  map[string]any `json:"attributes,omitempty"`
	Tokens      *TokenUsage    `json:"tokens,omitempty"`
	Cost        *Money         `json:"cost,omitempty"`
	Payload     *PayloadRef    `json:"payload,omitempty"`
	Provenance  Provenance     `json:"provenance"`
}

// HostMetadata contains non-sensitive runtime environment metadata.
type HostMetadata struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	GoVersion string `json:"go_version,omitempty"`
}

// Manifest defines the top-level metadata of an .apcap capture file.
type Manifest struct {
	Format           string            `json:"format"`
	FormatVersion    string            `json:"format_version"`
	CaptureID        string            `json:"capture_id"`
	CreatedAt        time.Time         `json:"created_at"`
	CompletedAt      time.Time         `json:"completed_at"`
	AgentpcapVersion string            `json:"agentpcap_version"`
	HostMetadata     HostMetadata      `json:"host_metadata"`
	CaptureMode      string            `json:"capture_mode"`   // "proxy", "otlp", "sdk", "child_process", "simulation"
	RedactionMode    string            `json:"redaction_mode"` // "metadata_only", "sanitized_content", "full_content"
	ProtocolsSeen    []Protocol        `json:"protocols_seen"`
	EventCount       int               `json:"event_count"`
	AttachmentCount  int               `json:"attachment_count"`
	Hashes           map[string]string `json:"hashes"` // SHA-256 hashes of bundle contents
	Extensions       map[string]any    `json:"extensions,omitempty"`
}

// CaptureMetadata contains additional human-readable summary stats.
type CaptureMetadata struct {
	Title           string            `json:"title,omitempty"`
	Description     string            `json:"description,omitempty"`
	TotalDurationMs float64           `json:"total_duration_ms"`
	TotalTokens     TokenUsage        `json:"total_tokens"`
	TotalCost       float64           `json:"total_cost"`
	Currency        string            `json:"currency"`
	AgentCount      int               `json:"agent_count"`
	ModelCount      int               `json:"model_count"`
	ToolCount       int               `json:"tool_count"`
	ErrorCount      int               `json:"error_count"`
	CustomLabels    map[string]string `json:"custom_labels,omitempty"`
}

// Clone creates a deep copy of an Event.
func (e *Event) Clone() *Event {
	b, err := json.Marshal(e)
	if err != nil {
		return e
	}
	var clone Event
	_ = json.Unmarshal(b, &clone)
	return &clone
}
