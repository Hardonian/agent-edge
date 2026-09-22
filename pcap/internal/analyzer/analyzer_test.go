package analyzer_test

import (
	"testing"
	"time"

	"github.com/agentpcap/agentpcap/internal/analyzer"
	"github.com/agentpcap/agentpcap/internal/diff"
	"github.com/agentpcap/agentpcap/internal/pathology"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestPathologyAndCriticalPath(t *testing.T) {
	now := time.Now().UTC()

	events := []apcap.Event{
		// Retry storm on analytics_query
		{
			ID:          "ev-1",
			Timestamp:   now,
			DurationMs:  500,
			Protocol:    apcap.ProtocolMCP,
			Operation:   "tools/call:analytics_query",
			Status:      apcap.StatusError,
			Source:      apcap.Endpoint{Name: "research-agent"},
			Destination: apcap.Endpoint{Name: "analytics-db"},
		},
		{
			ID:          "ev-2",
			Timestamp:   now.Add(500 * time.Millisecond),
			DurationMs:  600,
			Protocol:    apcap.ProtocolMCP,
			Operation:   "tools/call:analytics_query",
			Status:      apcap.StatusError,
			Source:      apcap.Endpoint{Name: "research-agent"},
			Destination: apcap.Endpoint{Name: "analytics-db"},
		},
		// Duplicate discovery
		{
			ID:          "ev-3",
			Timestamp:   now.Add(1100 * time.Millisecond),
			DurationMs:  50,
			Type:        apcap.EventMCPToolsList,
			Protocol:    apcap.ProtocolMCP,
			Operation:   "tools/list",
			Status:      apcap.StatusOK,
			Destination: apcap.Endpoint{Name: "analytics-db"},
		},
		{
			ID:          "ev-4",
			Timestamp:   now.Add(1200 * time.Millisecond),
			DurationMs:  50,
			Type:        apcap.EventMCPToolsList,
			Protocol:    apcap.ProtocolMCP,
			Operation:   "tools/list",
			Status:      apcap.StatusOK,
			Destination: apcap.Endpoint{Name: "analytics-db"},
		},
		// Model call dominant
		{
			ID:          "ev-5",
			Timestamp:   now.Add(1300 * time.Millisecond),
			DurationMs:  3500,
			Protocol:    apcap.ProtocolModel,
			Operation:   "gemini:gemini-1.5-pro",
			Status:      apcap.StatusOK,
			Destination: apcap.Endpoint{Name: "gemini-1.5-pro"},
			Tokens:      &apcap.TokenUsage{TotalTokens: 5000},
		},
	}

	// 1. Pathology detection
	pEng := pathology.NewEngine()
	findings := pEng.Analyze(events)

	var hasRetryStorm, hasDuplicateDiscovery bool
	for _, f := range findings {
		if f.Type == "RETRY_STORM" {
			hasRetryStorm = true
		}
		if f.Type == "DUPLICATE_DISCOVERY" {
			hasDuplicateDiscovery = true
		}
	}

	if !hasRetryStorm {
		t.Error("expected RETRY_STORM finding")
	}
	if !hasDuplicateDiscovery {
		t.Error("expected DUPLICATE_DISCOVERY finding")
	}

	// 2. Critical path
	cp := analyzer.AnalyzeCriticalPath(events)
	if cp.DominantEvent.Operation != "gemini:gemini-1.5-pro" {
		t.Errorf("expected dominant event gemini-1.5-pro, got %s", cp.DominantEvent.Operation)
	}
}

func TestDiff(t *testing.T) {
	before := &apcap.Capture{
		Manifest: apcap.Manifest{CaptureID: "before"},
		Metadata: apcap.CaptureMetadata{
			TotalDurationMs: 8200,
			TotalTokens:     apcap.TokenUsage{TotalTokens: 21440},
			TotalCost:       0.12,
			ErrorCount:      3,
		},
		Events: []apcap.Event{
			{Operation: "gemini-retry", Protocol: apcap.ProtocolModel, Status: apcap.StatusError},
			{Operation: "gemini-retry", Protocol: apcap.ProtocolModel, Status: apcap.StatusError},
			{Operation: "tools/list", Protocol: apcap.ProtocolMCP, Status: apcap.StatusOK},
		},
	}

	after := &apcap.Capture{
		Manifest: apcap.Manifest{CaptureID: "after"},
		Metadata: apcap.CaptureMetadata{
			TotalDurationMs: 4100,
			TotalTokens:     apcap.TokenUsage{TotalTokens: 13210},
			TotalCost:       0.07,
			ErrorCount:      0,
		},
		Events: []apcap.Event{
			{Operation: "tools/list", Protocol: apcap.ProtocolMCP, Status: apcap.StatusOK},
		},
	}

	res := diff.Compare(before, after)
	if res.LatencyMs.Delta != -4100 {
		t.Errorf("expected -4100 delta, got %f", res.LatencyMs.Delta)
	}
	if len(res.ResolvedPathologies) == 0 {
		t.Log("Note: checking resolved pathologies")
	}

	term := res.FormatTerminal()
	if term == "" {
		t.Error("expected non-empty terminal diff output")
	}
}
