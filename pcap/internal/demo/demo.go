package demo

import (
	"time"

	"github.com/agentpcap/agentpcap/internal/capture"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// GenerateSimulationEvents produces deterministic multi-agent simulation events demonstrating all AgentPCAP features.
func GenerateSimulationEvents(baseTime time.Time) []apcap.Event {
	traceID := "trace_demo_simulation_001"

	return []apcap.Event{
		// 1. Initial Agent Start / Task Request
		{
			ID:          "ev_demo_01",
			TraceID:     traceID,
			Timestamp:   baseTime,
			DurationMs:  12.0,
			Type:        apcap.EventA2ARequest,
			Protocol:    apcap.ProtocolA2A,
			Operation:   "task/dispatch:quarterly_analysis",
			Source:      apcap.Endpoint{Name: "finance-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Status:      apcap.StatusOK,
			Attributes: map[string]any{
				"a2a.task_id": "task_q3_report",
				"simulation":  true,
			},
			Provenance: apcap.ProvenanceObserved,
		},
		// 2. Delegation to Research Agent
		{
			ID:          "ev_demo_02",
			TraceID:     traceID,
			ParentID:    "ev_demo_01",
			Timestamp:   baseTime.Add(15 * time.Millisecond),
			DurationMs:  25.0,
			Type:        apcap.EventDelegation,
			Protocol:    apcap.ProtocolA2A,
			Operation:   "task/delegate:market_research",
			Source:      apcap.Endpoint{Name: "finance-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Status:      apcap.StatusOK,
			Attributes: map[string]any{
				"a2a.delegation_depth": 1,
				"a2a.initiator":        "finance-agent",
				"a2a.delegation_chain": "finance-agent -> research-agent",
			},
			Provenance: apcap.ProvenanceProtocolParsed,
		},
		// 3. MCP Discovery (Attempt 1)
		{
			ID:          "ev_demo_03",
			TraceID:     traceID,
			ParentID:    "ev_demo_02",
			Timestamp:   baseTime.Add(45 * time.Millisecond),
			DurationMs:  18.0,
			Type:        apcap.EventMCPToolsList,
			Protocol:    apcap.ProtocolMCP,
			Operation:   "tools/list",
			Source:      apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "analytics-mcp-server", Kind: "mcp_server"},
			Status:      apcap.StatusOK,
			Attributes: map[string]any{
				"mcp.tool_count": 5,
				"mcp.version":    "2024-11-05",
			},
			Provenance: apcap.ProvenanceProtocolParsed,
		},
		// 4. MCP Duplicate Discovery (Triggers DUPLICATE_DISCOVERY pathology)
		{
			ID:          "ev_demo_04",
			TraceID:     traceID,
			ParentID:    "ev_demo_02",
			Timestamp:   baseTime.Add(68 * time.Millisecond),
			DurationMs:  15.0,
			Type:        apcap.EventMCPToolsList,
			Protocol:    apcap.ProtocolMCP,
			Operation:   "tools/list",
			Source:      apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "analytics-mcp-server", Kind: "mcp_server"},
			Status:      apcap.StatusOK,
			Attributes: map[string]any{
				"mcp.tool_count": 5,
				"mcp.version":    "2024-11-05",
			},
			Provenance: apcap.ProvenanceProtocolParsed,
		},
		// 5. Model Inference Call: Gemini 1.5 Pro
		{
			ID:          "ev_demo_05",
			TraceID:     traceID,
			ParentID:    "ev_demo_02",
			Timestamp:   baseTime.Add(90 * time.Millisecond),
			DurationMs:  820.0,
			Type:        apcap.EventModelResponse,
			Protocol:    apcap.ProtocolModel,
			Operation:   "gemini:gemini-1.5-pro",
			Source:      apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "gemini-1.5-pro", Kind: "model"},
			Status:      apcap.StatusOK,
			Attributes: map[string]any{
				"model.provider": "google",
				"model.name":     "gemini-1.5-pro",
			},
			Tokens: &apcap.TokenUsage{
				InputTokens:  1850,
				OutputTokens: 640,
				CachedTokens: 256,
				TotalTokens:  2490,
			},
			Cost: &apcap.Money{
				Amount:   0.0055,
				Currency: "USD",
				Status:   apcap.CostStatusEstimated,
				Source:   "pricing-snapshot-v1",
			},
			Provenance: apcap.ProvenanceProtocolParsed,
		},
		// 6. MCP Tool Call (Attempt 1 - Network Glitch / Error)
		{
			ID:          "ev_demo_06",
			TraceID:     traceID,
			ParentID:    "ev_demo_02",
			Timestamp:   baseTime.Add(920 * time.Millisecond),
			DurationMs:  140.0,
			Type:        apcap.EventMCPToolCall,
			Protocol:    apcap.ProtocolMCP,
			Operation:   "tools/call:analytics_query",
			Source:      apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "analytics-mcp-server", Kind: "mcp_server"},
			Status:      apcap.StatusError,
			Attributes: map[string]any{
				"tool.name":         "analytics_query",
				"tool.args_hash":    "d8a4f912",
				"mcp.error_message": "Upstream database connection pool exhausted",
			},
			Provenance: apcap.ProvenanceProtocolParsed,
		},
		// 7. Retry Attempt 2 (Triggers RETRY_STORM pathology)
		{
			ID:          "ev_demo_07",
			TraceID:     traceID,
			ParentID:    "ev_demo_02",
			Timestamp:   baseTime.Add(1070 * time.Millisecond),
			DurationMs:  180.0,
			Type:        apcap.EventRetry,
			Protocol:    apcap.ProtocolMCP,
			Operation:   "tools/call:analytics_query",
			Source:      apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "analytics-mcp-server", Kind: "mcp_server"},
			Status:      apcap.StatusError,
			Attributes: map[string]any{
				"tool.name":         "analytics_query",
				"tool.args_hash":    "d8a4f912",
				"mcp.error_message": "Upstream database timeout",
			},
			Provenance: apcap.ProvenanceProtocolParsed,
		},
		// 8. Retry Attempt 3 (Succeeds)
		{
			ID:          "ev_demo_08",
			TraceID:     traceID,
			ParentID:    "ev_demo_02",
			Timestamp:   baseTime.Add(1260 * time.Millisecond),
			DurationMs:  95.0,
			Type:        apcap.EventMCPToolResult,
			Protocol:    apcap.ProtocolMCP,
			Operation:   "tools/call:analytics_query",
			Source:      apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "analytics-mcp-server", Kind: "mcp_server"},
			Status:      apcap.StatusOK,
			Attributes: map[string]any{
				"tool.name":      "analytics_query",
				"tool.args_hash": "d8a4f912",
				"query_rows":     142,
			},
			Provenance: apcap.ProvenanceProtocolParsed,
		},
		// 9. A2A Response from Research Agent back to Finance Agent
		{
			ID:          "ev_demo_09",
			TraceID:     traceID,
			ParentID:    "ev_demo_01",
			Timestamp:   baseTime.Add(1360 * time.Millisecond),
			DurationMs:  20.0,
			Type:        apcap.EventA2AResponse,
			Protocol:    apcap.ProtocolA2A,
			Operation:   "task/result:market_research",
			Source:      apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "finance-agent", Kind: "agent"},
			Status:      apcap.StatusOK,
			Attributes: map[string]any{
				"a2a.status":          "completed",
				"artifacts_generated": 1,
			},
			Provenance: apcap.ProvenanceProtocolParsed,
		},
		// 10. Policy Governance Decision
		{
			ID:          "ev_demo_10",
			TraceID:     traceID,
			ParentID:    "ev_demo_01",
			Timestamp:   baseTime.Add(1390 * time.Millisecond),
			DurationMs:  8.0,
			Type:        apcap.EventPolicyDecision,
			Protocol:    apcap.ProtocolPolicy,
			Operation:   "policy/evaluate:spending_limit",
			Source:      apcap.Endpoint{Name: "finance-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "policy-engine", Kind: "service"},
			Status:      apcap.StatusOK,
			Attributes: map[string]any{
				"policy.rule":    "max_order_spend <= 5000",
				"policy.outcome": "APPROVED",
			},
			Provenance: apcap.ProvenanceObserved,
		},
		// 11. Delegation to Procurement Agent
		{
			ID:          "ev_demo_11",
			TraceID:     traceID,
			ParentID:    "ev_demo_01",
			Timestamp:   baseTime.Add(1405 * time.Millisecond),
			DurationMs:  15.0,
			Type:        apcap.EventDelegation,
			Protocol:    apcap.ProtocolA2A,
			Operation:   "task/delegate:execute_order",
			Source:      apcap.Endpoint{Name: "finance-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "procurement-agent", Kind: "agent"},
			Status:      apcap.StatusOK,
			Attributes: map[string]any{
				"a2a.delegation_depth": 1,
				"a2a.initiator":        "finance-agent",
			},
			Provenance: apcap.ProvenanceProtocolParsed,
		},
		// 12. Final Execution Tool Call
		{
			ID:          "ev_demo_12",
			TraceID:     traceID,
			ParentID:    "ev_demo_11",
			Timestamp:   baseTime.Add(1425 * time.Millisecond),
			DurationMs:  110.0,
			Type:        apcap.EventToolCall,
			Protocol:    apcap.ProtocolTool,
			Operation:   "tool:execute_purchase_order",
			Source:      apcap.Endpoint{Name: "procurement-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "procurement-system", Kind: "tool"},
			Status:      apcap.StatusOK,
			Attributes: map[string]any{
				"tool.name":   "execute_purchase_order",
				"order_id":    "PO-88219",
				"order_value": 4200.0,
			},
			Provenance: apcap.ProvenanceObserved,
		},
	}
}

// RunDemo populates a session with the simulated multi-agent execution events.
func RunDemo(session *capture.Session) {
	events := GenerateSimulationEvents(time.Now().UTC())
	for _, ev := range events {
		session.Ingest(ev)
	}
}

// RunDemoLive streams simulated events into the session with real-time delays for live browser demonstration.
func RunDemoLive(session *capture.Session) {
	session.Reset()
	baseTime := time.Now().UTC()
	events := GenerateSimulationEvents(baseTime)

	for i, ev := range events {
		// Stagger events with realistic visual delays between 100ms and 250ms
		time.Sleep(120 * time.Millisecond)
		ev.Timestamp = baseTime.Add(time.Duration(i*120) * time.Millisecond)
		session.Ingest(ev)
	}
}
