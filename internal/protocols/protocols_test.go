package protocols_test

import (
	"testing"

	"github.com/agentpcap/agentpcap/internal/cost"
	"github.com/agentpcap/agentpcap/internal/protocols/a2a"
	"github.com/agentpcap/agentpcap/internal/protocols/mcp"
	"github.com/agentpcap/agentpcap/internal/protocols/model"
	"github.com/agentpcap/agentpcap/internal/protocols/otlp"
	"github.com/agentpcap/agentpcap/internal/protocols/tool"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestMCPParser(t *testing.T) {
	p := mcp.NewParser()

	// 1. tools/call
	raw := []byte(`{
		"jsonrpc": "2.0",
		"id": 42,
		"method": "tools/call",
		"params": {
			"name": "query_database",
			"arguments": {"sql": "SELECT 1"}
		}
	}`)

	ev, err := p.Parse(raw, apcap.Endpoint{Name: "research-agent"}, apcap.Endpoint{Name: "analytics-db"}, 12.5)
	if err != nil {
		t.Fatalf("mcp parse error: %v", err)
	}

	if ev.Type != apcap.EventMCPToolCall {
		t.Errorf("expected EventMCPToolCall, got %s", ev.Type)
	}
	if ev.Attributes["tool.name"] != "query_database" {
		t.Errorf("expected query_database, got %v", ev.Attributes["tool.name"])
	}
}

func TestA2AParser(t *testing.T) {
	p := a2a.NewParser()

	reqJSON := []byte(`{
		"taskId": "task-789",
		"sourceAgent": "agent-alpha",
		"targetAgent": "agent-beta",
		"delegation": {
			"depth": 2,
			"initiator": "agent-root",
			"chain": ["agent-root", "agent-alpha", "agent-beta"]
		}
	}`)

	ev, err := p.ParseTaskRequest(reqJSON, "agent-alpha", "agent-beta", 30.0)
	if err != nil {
		t.Fatalf("a2a parse error: %v", err)
	}

	if ev.Type != apcap.EventDelegation {
		t.Errorf("expected EventDelegation, got %s", ev.Type)
	}
	if ev.Attributes["a2a.delegation_depth"] != 2 {
		t.Errorf("expected depth 2, got %v", ev.Attributes["a2a.delegation_depth"])
	}
}

func TestModelAdapterGemini(t *testing.T) {
	ce := cost.NewEngine()
	ad := model.NewAdapter(ce)

	respJSON := []byte(`{
		"usageMetadata": {
			"promptTokenCount": 500,
			"candidatesTokenCount": 200,
			"totalTokenCount": 700
		}
	}`)

	ev := ad.ParseExchange(
		"POST",
		"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
		"generativelanguage.googleapis.com",
		"/v1beta/models/gemini-1.5-flash:generateContent",
		200,
		respJSON,
		"research-agent",
		120.0,
	)

	if ev.Protocol != apcap.ProtocolModel {
		t.Errorf("expected ProtocolModel, got %s", ev.Protocol)
	}
	if ev.Tokens == nil || ev.Tokens.TotalTokens != 700 {
		t.Errorf("expected 700 tokens, got %+v", ev.Tokens)
	}
	if ev.Cost == nil || ev.Cost.Amount <= 0 {
		t.Errorf("expected cost calculated, got %+v", ev.Cost)
	}
}

func TestToolNormalizer(t *testing.T) {
	tn := tool.NewNormalizer()
	ev := tn.NormalizeToolCall("calculator", "math-agent", map[string]any{"op": "add", "a": 1, "b": 2}, false, 5.0)

	if ev.Type != apcap.EventToolCall {
		t.Errorf("expected EventToolCall, got %s", ev.Type)
	}
	if ev.Attributes["tool.args_hash"] == "" {
		t.Error("expected tool.args_hash to be populated")
	}
}

func TestOTLPReceiver(t *testing.T) {
	rec := otlp.NewReceiver(cost.NewEngine())

	otlpJSON := []byte(`{
		"resourceSpans": [{
			"resource": {
				"attributes": [{"key": "service.name", "value": {"stringValue": "finance-worker"}}]
			},
			"scopeSpans": [{
				"spans": [{
					"traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
					"spanId": "00f067aa0ba902b7",
					"name": "chat",
					"kind": 1,
					"startTimeUnixNano": "1700000000000000000",
					"endTimeUnixNano": "1700000000500000000",
					"attributes": [
						{"key": "gen_ai.system", "value": {"stringValue": "openai"}},
						{"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4o"}},
						{"key": "gen_ai.usage.input_tokens", "value": {"intValue": "100"}},
						{"key": "gen_ai.usage.output_tokens", "value": {"intValue": "50"}}
					]
				}]
			}]
		}]
	}`)

	events, err := rec.ParseTracesJSON(otlpJSON)
	if err != nil {
		t.Fatalf("otlp parse error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Protocol != apcap.ProtocolModel {
		t.Errorf("expected ProtocolModel, got %s", events[0].Protocol)
	}
	if events[0].Tokens.TotalTokens != 150 {
		t.Errorf("expected 150 tokens, got %d", events[0].Tokens.TotalTokens)
	}
}
