package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// Supported and observed protocol versions.
const (
	VersionCurrent = "2024-11-05"
	VersionLegacy  = "2024-10-07"
)

// JSONRPCMessage represents an MCP JSON-RPC 2.0 packet.
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError represents an error response.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// InitializeParams contains client handshake details.
type InitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      map[string]any `json:"clientInfo"`
}

// ToolCallParams contains tool invocation parameters.
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// Parser parses and normalizes MCP JSON-RPC messages into AgentPCAP events.
type Parser struct{}

// NewParser creates an MCP protocol normalizer.
func NewParser() *Parser {
	return &Parser{}
}

// Parse converts a raw JSON-RPC 2.0 payload into a normalized APCAP Event.
func (p *Parser) Parse(raw []byte, client, server apcap.Endpoint, durationMs float64) (*apcap.Event, error) {
	var msg JSONRPCMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, fmt.Errorf("invalid json-rpc message: %w", err)
	}

	if msg.JSONRPC != "2.0" {
		return nil, fmt.Errorf("unsupported json-rpc version: %s", msg.JSONRPC)
	}

	ev := &apcap.Event{
		ID:          fmt.Sprintf("mcp_%d", time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		DurationMs:  durationMs,
		Protocol:    apcap.ProtocolMCP,
		Source:      client,
		Destination: server,
		Status:      apcap.StatusOK,
		Attributes:  make(map[string]any),
		Provenance:  apcap.ProvenanceProtocolParsed,
	}

	if client.Kind == "" {
		ev.Source.Kind = "agent"
	}
	if server.Kind == "" {
		ev.Destination.Kind = "mcp_server"
	}

	// Correlation ID
	if msg.ID != nil {
		ev.Attributes["mcp.id"] = msg.ID
		ev.TraceID = fmt.Sprintf("trace_mcp_%v", msg.ID)
	}

	// Handle Error Response
	if msg.Error != nil {
		ev.Type = apcap.EventMCPError
		ev.Status = apcap.StatusError
		ev.Operation = "error"
		ev.Attributes["mcp.error_code"] = msg.Error.Code
		ev.Attributes["mcp.error_message"] = msg.Error.Message
		return ev, nil
	}

	// Handle Method Request / Notification
	if msg.Method != "" {
		ev.Operation = msg.Method
		switch msg.Method {
		case "initialize":
			ev.Type = apcap.EventMCPDiscover
			var initParams InitializeParams
			if err := json.Unmarshal(msg.Params, &initParams); err == nil {
				ev.Attributes["mcp.version"] = initParams.ProtocolVersion
				if clientName, ok := initParams.ClientInfo["name"].(string); ok {
					ev.Source.Name = clientName
					ev.Attributes["mcp.client_name"] = clientName
				}
			}
		case "tools/list":
			ev.Type = apcap.EventMCPToolsList
		case "tools/call":
			ev.Type = apcap.EventMCPToolCall
			var callParams ToolCallParams
			if err := json.Unmarshal(msg.Params, &callParams); err == nil {
				ev.Attributes["tool.name"] = callParams.Name
				argKeys := make([]string, 0, len(callParams.Arguments))
				for k := range callParams.Arguments {
					argKeys = append(argKeys, k)
				}
				ev.Attributes["tool.arguments_keys"] = strings.Join(argKeys, ",")
			}
		default:
			ev.Type = apcap.EventCustom
		}
		return ev, nil
	}

	// Handle Result Response
	if msg.Result != nil {
		ev.Type = apcap.EventMCPToolResult
		ev.Operation = "tools/result"
		var resMap map[string]any
		if err := json.Unmarshal(msg.Result, &resMap); err == nil {
			if isErr, ok := resMap["isError"].(bool); ok && isErr {
				ev.Status = apcap.StatusError
			}
			if tools, ok := resMap["tools"].([]any); ok {
				ev.Type = apcap.EventMCPToolsList
				ev.Operation = "tools/list_result"
				ev.Attributes["mcp.tool_count"] = len(tools)
			}
		}
		return ev, nil
	}

	return ev, nil
}
