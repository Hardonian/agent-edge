package torture_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/agentpcap/agentpcap/internal/protocols/mcp"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestMCPTorture_Corpus(t *testing.T) {
	p := mcp.NewParser()
	client := apcap.Endpoint{Name: "torture-agent", Kind: "agent"}
	server := apcap.Endpoint{Name: "torture-mcp", Kind: "mcp_server"}

	cases := []struct {
		name     string
		raw      []byte
		mustFail bool
	}{
		// 1. Corrupt payloads
		{"null bytes", []byte("\x00\x00\x00\x00"), true},
		{"random binary garbage", []byte("\xff\xfe\xfd\xfc\x01\x02\x03"), true},
		{"unclosed string", []byte(`{"jsonrpc": "2.0", "id": "test`), true},
		{"array instead of object", []byte(`[1, 2, 3]`), true},
		{"naked string", []byte(`"hello world"`), true},
		{"numeric literal", []byte(`12345`), true},

		// 2. Protocol version anomalies
		{"wrong jsonrpc version 1.0", []byte(`{"jsonrpc": "1.0", "id": 1, "method": "tools/list"}`), true},
		{"wrong jsonrpc version 3.0", []byte(`{"jsonrpc": "3.0", "id": 1, "method": "tools/list"}`), true},
		{"missing jsonrpc field", []byte(`{"id": 1, "method": "tools/list"}`), true},

		// 3. Huge string and payload abuse
		{"100KB method name", fmt.Appendf(nil, `{"jsonrpc": "2.0", "id": 1, "method": "%s"}`, strings.Repeat("M", 100000)), false},
		{"1MB argument payload", fmt.Appendf(nil, `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "bulk", "arguments": {"blob": "%s"}}}`, strings.Repeat("Z", 1000000)), false},

		// 4. Duplicate and deeply nested schemas
		{"100 level nested arguments", func() []byte {
			prefix := `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "deep", "arguments": `
			suffix := `}}`
			var b strings.Builder
			b.WriteString(prefix)
			for i := 0; i < 100; i++ {
				b.WriteString(`{"n":`)
			}
			b.WriteString(`"bottom"`)
			for i := 0; i < 100; i++ {
				b.WriteString(`}`)
			}
			b.WriteString(suffix)
			return []byte(b.String())
		}(), false},

		// 5. Error edge cases
		{"error with negative code and null message", []byte(`{"jsonrpc": "2.0", "id": 1, "error": {"code": -32700}}`), false},
		{"error with massive data trace", fmt.Appendf(nil, `{"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": "panic", "data": {"trace": "%s"}}}`, strings.Repeat("E", 50000)), false},

		// 6. Discovery storms (repeated tool entries)
		{"tools/list response with 2000 tools", func() []byte {
			tools := make([]map[string]any, 2000)
			for i := 0; i < 2000; i++ {
				tools[i] = map[string]any{
					"name":        fmt.Sprintf("tool_%d", i),
					"description": "Simulated tool in torture suite",
				}
			}
			data, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      999,
				"result":  map[string]any{"tools": tools},
			})
			return data
		}(), false},

		// 7. Cancellation notification
		{"cancellation notification without id", []byte(`{"jsonrpc": "2.0", "method": "$/cancelRequest", "params": {"requestId": 42}}`), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Zero panic guarantee under all conditions
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC TRIGGERED on hostile input %q: %v", tc.name, r)
				}
			}()

			ev, err := p.Parse(tc.raw, client, server, 10.0)
			if tc.mustFail && err == nil {
				t.Errorf("expected rejection for %q, but parser succeeded", tc.name)
			}
			if !tc.mustFail && err != nil {
				t.Errorf("expected graceful acceptance for %q, got error: %v", tc.name, err)
			}
			if !tc.mustFail && ev == nil {
				t.Errorf("expected non-nil event for %q", tc.name)
			}
		})
	}
}
