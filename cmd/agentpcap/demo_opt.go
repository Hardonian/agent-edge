package main

import (
	"time"

	"github.com/agentpcap/agentpcap/internal/capture"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func createOptimizedCapture(outputPath string) error {
	session := capture.NewSession(capture.SessionConfig{
		CaptureID:   "cap_demo_optimized",
		Title:       "Quarterly Market Research (Optimized)",
		CaptureMode: "simulation",
		OutputPath:  outputPath,
	})

	baseTime := time.Now().UTC()
	traceID := "trace_demo_simulation_opt"

	events := []apcap.Event{
		{
			ID:          "ev_opt_01",
			TraceID:     traceID,
			Timestamp:   baseTime,
			DurationMs:  10.0,
			Type:        apcap.EventA2ARequest,
			Protocol:    apcap.ProtocolA2A,
			Operation:   "task/dispatch:quarterly_analysis",
			Source:      apcap.Endpoint{Name: "finance-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Status:      apcap.StatusOK,
			Provenance:  apcap.ProvenanceObserved,
		},
		{
			ID:          "ev_opt_02",
			TraceID:     traceID,
			ParentID:    "ev_opt_01",
			Timestamp:   baseTime.Add(12 * time.Millisecond),
			DurationMs:  20.0,
			Type:        apcap.EventDelegation,
			Protocol:    apcap.ProtocolA2A,
			Operation:   "task/delegate:market_research",
			Source:      apcap.Endpoint{Name: "finance-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Status:      apcap.StatusOK,
			Provenance:  apcap.ProvenanceProtocolParsed,
		},
		// Single cached MCP discovery
		{
			ID:          "ev_opt_03",
			TraceID:     traceID,
			ParentID:    "ev_opt_02",
			Timestamp:   baseTime.Add(35 * time.Millisecond),
			DurationMs:  15.0,
			Type:        apcap.EventMCPToolsList,
			Protocol:    apcap.ProtocolMCP,
			Operation:   "tools/list",
			Source:      apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "analytics-mcp-server", Kind: "mcp_server"},
			Status:      apcap.StatusOK,
			Provenance:  apcap.ProvenanceProtocolParsed,
		},
		// Model call
		{
			ID:          "ev_opt_04",
			TraceID:     traceID,
			ParentID:    "ev_opt_02",
			Timestamp:   baseTime.Add(55 * time.Millisecond),
			DurationMs:  650.0,
			Type:        apcap.EventModelResponse,
			Protocol:    apcap.ProtocolModel,
			Operation:   "gemini:gemini-1.5-pro",
			Source:      apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "gemini-1.5-pro", Kind: "model"},
			Status:      apcap.StatusOK,
			Tokens: &apcap.TokenUsage{
				InputTokens:  1200,
				OutputTokens: 450,
				TotalTokens:  1650,
			},
			Cost: &apcap.Money{
				Amount:   0.0037,
				Currency: "USD",
				Status:   apcap.CostStatusEstimated,
			},
			Provenance: apcap.ProvenanceProtocolParsed,
		},
		// Tool call succeeds immediately (no retry storm)
		{
			ID:          "ev_opt_05",
			TraceID:     traceID,
			ParentID:    "ev_opt_02",
			Timestamp:   baseTime.Add(710 * time.Millisecond),
			DurationMs:  80.0,
			Type:        apcap.EventMCPToolResult,
			Protocol:    apcap.ProtocolMCP,
			Operation:   "tools/call:analytics_query",
			Source:      apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "analytics-mcp-server", Kind: "mcp_server"},
			Status:      apcap.StatusOK,
			Provenance:  apcap.ProvenanceProtocolParsed,
		},
		{
			ID:          "ev_opt_06",
			TraceID:     traceID,
			ParentID:    "ev_opt_01",
			Timestamp:   baseTime.Add(800 * time.Millisecond),
			DurationMs:  15.0,
			Type:        apcap.EventA2AResponse,
			Protocol:    apcap.ProtocolA2A,
			Operation:   "task/result:market_research",
			Source:      apcap.Endpoint{Name: "research-agent", Kind: "agent"},
			Destination: apcap.Endpoint{Name: "finance-agent", Kind: "agent"},
			Status:      apcap.StatusOK,
			Provenance:  apcap.ProvenanceProtocolParsed,
		},
	}

	for _, ev := range events {
		session.Ingest(ev)
	}

	return session.Close()
}
