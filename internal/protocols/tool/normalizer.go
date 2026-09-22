package tool

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// Normalizer standardizes tool invocations from MCP, OpenAI function calling, LangChain, or custom frameworks.
type Normalizer struct{}

// NewNormalizer creates a tool normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// NormalizeToolCall creates an APCAP Event for a tool execution.
func (n *Normalizer) NormalizeToolCall(
	toolName string,
	callerName string,
	args map[string]any,
	isError bool,
	durationMs float64,
) *apcap.Event {
	status := apcap.StatusOK
	if isError {
		status = apcap.StatusError
	}

	ev := &apcap.Event{
		ID:         fmt.Sprintf("tool_%d", time.Now().UnixNano()),
		Timestamp:  time.Now().UTC(),
		DurationMs: durationMs,
		Type:       apcap.EventToolCall,
		Protocol:   apcap.ProtocolTool,
		Operation:  fmt.Sprintf("tool:%s", toolName),
		Source: apcap.Endpoint{
			Name: callerName,
			Kind: "agent",
		},
		Destination: apcap.Endpoint{
			Name: toolName,
			Kind: "tool",
		},
		Status:     status,
		Attributes: make(map[string]any),
		Provenance: apcap.ProvenanceObserved,
	}

	ev.Attributes["tool.name"] = toolName

	// Fingerprint arguments safely for duplicate detection without leaking content
	if args != nil {
		argsBytes, err := json.Marshal(args)
		if err == nil {
			h := sha256.Sum256(argsBytes)
			ev.Attributes["tool.args_hash"] = hex.EncodeToString(h[:8])
		}
	}

	return ev
}
