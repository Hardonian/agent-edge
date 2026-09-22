package mcp_test

import (
	"testing"

	"github.com/agentpcap/agentpcap/internal/protocols/mcp"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func FuzzMCPParser(f *testing.F) {
	p := mcp.NewParser()
	client := apcap.Endpoint{Name: "fuzz-agent", Kind: "agent"}
	server := apcap.Endpoint{Name: "fuzz-server", Kind: "mcp_server"}

	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"limit":10}}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":4,"error":{"code":-32600,"message":"Invalid Request"}}`))
	f.Add([]byte(`{"jsonrpc":"1.0"}`))
	f.Add([]byte(`[1, 2, 3]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Invariant: Parser must never panic
		_, _ = p.Parse(data, client, server, 5.0)
	})
}
