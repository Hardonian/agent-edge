package a2a

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// TaskRequest represents an A2A task invocation payload.
type TaskRequest struct {
	TaskID      string          `json:"taskId,omitempty"`
	SourceAgent string          `json:"sourceAgent,omitempty"`
	TargetAgent string          `json:"targetAgent,omitempty"`
	Instruction string          `json:"instruction,omitempty"`
	Context     map[string]any  `json:"context,omitempty"`
	Delegation  *DelegationInfo `json:"delegation,omitempty"`
}

// DelegationInfo tracks delegation chains.
type DelegationInfo struct {
	Depth      int      `json:"depth"`
	Initiator  string   `json:"initiator"`
	ParentTask string   `json:"parentTask,omitempty"`
	Chain      []string `json:"chain,omitempty"`
}

// TaskResponse represents an A2A task response.
type TaskResponse struct {
	TaskID    string `json:"taskId"`
	Status    string `json:"status"` // "completed", "failed", "working"
	Artifacts int    `json:"artifactsCount,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Parser normalizes Agent-to-Agent communication patterns.
type Parser struct{}

// NewParser initializes an A2A parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseTaskRequest normalizes an A2A task dispatch or delegation.
func (p *Parser) ParseTaskRequest(raw []byte, sourceName, targetName string, durationMs float64) (*apcap.Event, error) {
	var req TaskRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("invalid a2a task request: %w", err)
	}

	fromAgent := sourceName
	if req.SourceAgent != "" {
		fromAgent = req.SourceAgent
	}
	toAgent := targetName
	if req.TargetAgent != "" {
		toAgent = req.TargetAgent
	}

	ev := &apcap.Event{
		ID:         fmt.Sprintf("a2a_%d", time.Now().UnixNano()),
		TraceID:    fmt.Sprintf("trace_a2a_%s", req.TaskID),
		Timestamp:  time.Now().UTC(),
		DurationMs: durationMs,
		Type:       apcap.EventA2ARequest,
		Protocol:   apcap.ProtocolA2A,
		Operation:  "task/dispatch",
		Source: apcap.Endpoint{
			Name: fromAgent,
			Kind: "agent",
		},
		Destination: apcap.Endpoint{
			Name: toAgent,
			Kind: "agent",
		},
		Status:     apcap.StatusOK,
		Attributes: make(map[string]any),
		Provenance: apcap.ProvenanceProtocolParsed,
	}

	if req.TaskID != "" {
		ev.Attributes["a2a.task_id"] = req.TaskID
	}

	if req.Delegation != nil {
		ev.Type = apcap.EventDelegation
		ev.Operation = "task/delegate"
		ev.Attributes["a2a.delegation_depth"] = req.Delegation.Depth
		ev.Attributes["a2a.initiator"] = req.Delegation.Initiator
		if len(req.Delegation.Chain) > 0 {
			ev.Attributes["a2a.delegation_chain"] = strings.Join(req.Delegation.Chain, " -> ")
		}
	}

	return ev, nil
}

// ParseTaskResponse normalizes an A2A task completion or status update.
func (p *Parser) ParseTaskResponse(raw []byte, fromAgent, toAgent string, durationMs float64) (*apcap.Event, error) {
	var resp TaskResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("invalid a2a task response: %w", err)
	}

	ev := &apcap.Event{
		ID:         fmt.Sprintf("a2a_resp_%d", time.Now().UnixNano()),
		TraceID:    fmt.Sprintf("trace_a2a_%s", resp.TaskID),
		Timestamp:  time.Now().UTC(),
		DurationMs: durationMs,
		Type:       apcap.EventA2AResponse,
		Protocol:   apcap.ProtocolA2A,
		Operation:  "task/result",
		Source: apcap.Endpoint{
			Name: fromAgent,
			Kind: "agent",
		},
		Destination: apcap.Endpoint{
			Name: toAgent,
			Kind: "agent",
		},
		Status:     apcap.StatusOK,
		Attributes: make(map[string]any),
		Provenance: apcap.ProvenanceProtocolParsed,
	}

	if resp.TaskID != "" {
		ev.Attributes["a2a.task_id"] = resp.TaskID
	}
	ev.Attributes["a2a.status"] = resp.Status

	if strings.EqualFold(resp.Status, "failed") || resp.Error != "" {
		ev.Status = apcap.StatusError
		ev.Type = apcap.EventA2AError
		ev.Attributes["a2a.error"] = resp.Error
	}

	return ev, nil
}
