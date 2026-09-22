package mcp_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentpcap/agentpcap/internal/protocols/mcp"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestMCPParser_ValidInitialize(t *testing.T) {
	p := mcp.NewParser()
	raw := []byte(`{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "initialize",
		"params": {
			"protocolVersion": "2024-11-05",
			"capabilities": {"tools": {}},
			"clientInfo": {"name": "test-agent", "version": "1.0.0"}
		}
	}`)

	client := apcap.Endpoint{Name: "agent-1", Kind: "agent"}
	server := apcap.Endpoint{Name: "analytics-mcp", Kind: "mcp_server"}

	ev, err := p.Parse(raw, client, server, 12.5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.Type != apcap.EventMCPDiscover {
		t.Errorf("expected EventMCPDiscover, got %v", ev.Type)
	}
	if ev.Protocol != apcap.ProtocolMCP {
		t.Errorf("expected ProtocolMCP, got %v", ev.Protocol)
	}
	if ev.Source.Name != "test-agent" {
		t.Errorf("expected clientInfo name override, got %s", ev.Source.Name)
	}
	if ev.Attributes["mcp.version"] != "2024-11-05" {
		t.Errorf("expected version 2024-11-05, got %v", ev.Attributes["mcp.version"])
	}
}

func TestMCPParser_ToolsListAndCall(t *testing.T) {
	p := mcp.NewParser()
	client := apcap.Endpoint{Name: "agent", Kind: "agent"}
	server := apcap.Endpoint{Name: "mcp-server", Kind: "mcp_server"}

	// tools/list request
	rawList := []byte(`{"jsonrpc": "2.0", "id": "req-1", "method": "tools/list", "params": {}}`)
	evList, err := p.Parse(rawList, client, server, 5.0)
	if err != nil {
		t.Fatalf("tools/list parse failed: %v", err)
	}
	if evList.Type != apcap.EventMCPToolsList {
		t.Errorf("expected EventMCPToolsList, got %s", evList.Type)
	}

	// tools/call request
	rawCall := []byte(`{
		"jsonrpc": "2.0",
		"id": "req-2",
		"method": "tools/call",
		"params": {
			"name": "calculate_tax",
			"arguments": {"amount": 100, "region": "US"}
		}
	}`)
	evCall, err := p.Parse(rawCall, client, server, 18.0)
	if err != nil {
		t.Fatalf("tools/call parse failed: %v", err)
	}
	if evCall.Type != apcap.EventMCPToolCall {
		t.Errorf("expected EventMCPToolCall, got %s", evCall.Type)
	}
	if evCall.Attributes["tool.name"] != "calculate_tax" {
		t.Errorf("expected calculate_tax tool, got %v", evCall.Attributes["tool.name"])
	}

	// tools/call response
	rawResult := []byte(`{
		"jsonrpc": "2.0",
		"id": "req-2",
		"result": {
			"content": [{"type": "text", "text": "Tax: 8.50"}],
			"isError": false
		}
	}`)
	evRes, err := p.Parse(rawResult, client, server, 25.0)
	if err != nil {
		t.Fatalf("tools/result parse failed: %v", err)
	}
	if evRes.Type != apcap.EventMCPToolResult {
		t.Errorf("expected EventMCPToolResult, got %s", evRes.Type)
	}
	if evRes.Status != apcap.StatusOK {
		t.Errorf("expected StatusOK, got %s", evRes.Status)
	}
}

func TestMCPParser_ErrorResponse(t *testing.T) {
	p := mcp.NewParser()
	raw := []byte(`{
		"jsonrpc": "2.0",
		"id": 42,
		"error": {
			"code": -32601,
			"message": "Method not found",
			"data": {"requested": "unknown_tool"}
		}
	}`)

	ev, err := p.Parse(raw, apcap.Endpoint{}, apcap.Endpoint{}, 10.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Type != apcap.EventMCPError {
		t.Errorf("expected EventMCPError, got %s", ev.Type)
	}
	if ev.Status != apcap.StatusError {
		t.Errorf("expected StatusError, got %s", ev.Status)
	}
	if ev.Attributes["mcp.error_code"] != -32601 {
		t.Errorf("expected error code -32601, got %v", ev.Attributes["mcp.error_code"])
	}
}

func TestMCPParser_TortureInputs(t *testing.T) {
	p := mcp.NewParser()
	client := apcap.Endpoint{Name: "agent", Kind: "agent"}
	server := apcap.Endpoint{Name: "mcp-server", Kind: "mcp_server"}

	tortureCases := []struct {
		name        string
		payload     []byte
		expectError bool
	}{
		{"Empty slice", []byte{}, true},
		{"Not JSON", []byte("foobar"), true},
		{"Truncated JSON", []byte(`{"jsonrpc": "2.0", "id": `), true},
		{"Invalid Version 1.0", []byte(`{"jsonrpc": "1.0", "id": 1, "method": "tools/list"}`), true},
		{"Null byte in string", []byte("{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"test\x00\"}"), true},
		{"Huge string field", []byte(`{"jsonrpc": "2.0", "id": 1, "method": "huge", "params": {"data": "` + strings.Repeat("A", 100000) + `"}}`), false},
		{"Deeply nested params", []byte(`{"jsonrpc": "2.0", "id": 1, "method": "nested", "params": {"a":{"b":{"c":{"d":{"e":{"f":1}}}}}}}`), false},
		{"Huge tool list result", func() []byte {
			type toolItem struct {
				Name string `json:"name"`
			}
			tools := make([]toolItem, 5000)
			for i := range tools {
				tools[i] = toolItem{Name: "tool_item"}
			}
			b, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"result":  map[string]any{"tools": tools},
			})
			return b
		}(), false},
		{"Result with isError true", []byte(`{"jsonrpc": "2.0", "id": 1, "result": {"isError": true}}`), false},
		{"Unknown method", []byte(`{"jsonrpc": "2.0", "id": "custom", "method": "custom/unknown_action"}`), false},
		{"Negative ID", []byte(`{"jsonrpc": "2.0", "id": -999, "method": "tools/list"}`), false},
		{"String ID with special characters", []byte(`{"jsonrpc": "2.0", "id": "<script>alert(1)</script>", "method": "tools/list"}`), false},
	}

	for _, tc := range tortureCases {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := p.Parse(tc.payload, client, server, 10.0)
			if tc.expectError && err == nil {
				t.Errorf("expected error for case %q, got nil", tc.name)
			}
			if !tc.expectError && err != nil {
				t.Errorf("expected success for case %q, got err: %v", tc.name, err)
			}
			if !tc.expectError && ev == nil {
				t.Errorf("expected event for case %q, got nil", tc.name)
			}
		})
	}
}
