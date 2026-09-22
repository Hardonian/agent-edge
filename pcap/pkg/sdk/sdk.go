package sdk

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

type contextKey struct{}

// Client provides programmatic instrumentation for Go agent runtimes.
type Client struct {
	agentName string
	sink      EventSink
}

// EventSink handles received events.
type EventSink interface {
	Ingest(ev apcap.Event)
}

// Options configures SDK client.
type Options struct {
	AgentName string
	Sink      EventSink
}

// NewClient initializes a client for agent instrumentation.
func NewClient(opts Options) *Client {
	if opts.AgentName == "" {
		opts.AgentName = "agent"
	}
	return &Client{
		agentName: opts.AgentName,
		sink:      opts.Sink,
	}
}

// Span represents an ongoing agent or tool operation.
type Span struct {
	client    *Client
	id        string
	traceID   string
	parentID  string
	name      string
	startTime time.Time
	status    apcap.Status
	attrs     map[string]any
}

// StartSpan begins an agent execution span.
func (c *Client) StartSpan(ctx context.Context, operation string) (*Span, context.Context) {
	parent, _ := ctx.Value(contextKey{}).(*Span)

	id := fmt.Sprintf("span_%d", time.Now().UnixNano())
	traceID := fmt.Sprintf("trace_%d", time.Now().UnixNano())
	parentID := ""
	if parent != nil {
		traceID = parent.traceID
		parentID = parent.id
	}

	s := &Span{
		client:    c,
		id:        id,
		traceID:   traceID,
		parentID:  parentID,
		name:      operation,
		startTime: time.Now().UTC(),
		status:    apcap.StatusOK,
		attrs:     make(map[string]any),
	}

	return s, context.WithValue(ctx, contextKey{}, s)
}

// End finishes the span and records an APCAP event.
func (s *Span) End() {
	durationMs := float64(time.Since(s.startTime).Microseconds()) / 1000.0

	ev := apcap.Event{
		ID:         s.id,
		TraceID:    s.traceID,
		ParentID:   s.parentID,
		Timestamp:  s.startTime,
		DurationMs: durationMs,
		Type:       apcap.EventAgentInvoke,
		Protocol:   apcap.ProtocolA2A,
		Operation:  s.name,
		Source: apcap.Endpoint{
			Name: s.client.agentName,
			Kind: "agent",
		},
		Destination: apcap.Endpoint{
			Name: s.name,
			Kind: "agent",
		},
		Status:     s.status,
		Attributes: s.attrs,
		Provenance: apcap.ProvenanceSDK,
	}

	if s.client.sink != nil {
		s.client.sink.Ingest(ev)
	}
}

// RecordToolCall records a tool execution under this span.
func (s *Span) RecordToolCall(toolName string, durationMs float64, isErr bool) {
	status := apcap.StatusOK
	if isErr {
		status = apcap.StatusError
	}
	ev := apcap.Event{
		ID:          fmt.Sprintf("tool_%d", time.Now().UnixNano()),
		TraceID:     s.traceID,
		ParentID:    s.id,
		Timestamp:   time.Now().UTC(),
		DurationMs:  durationMs,
		Type:        apcap.EventToolCall,
		Protocol:    apcap.ProtocolTool,
		Operation:   fmt.Sprintf("tool:%s", toolName),
		Source:      apcap.Endpoint{Name: s.client.agentName, Kind: "agent"},
		Destination: apcap.Endpoint{Name: toolName, Kind: "tool"},
		Status:      status,
		Provenance:  apcap.ProvenanceSDK,
	}
	if s.client.sink != nil {
		s.client.sink.Ingest(ev)
	}
}

// IsActive returns true if the current environment was launched by `agentpcap run`.
func IsActive() bool {
	return os.Getenv("AGENTPCAP_ACTIVE") == "1"
}
