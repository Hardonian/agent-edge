package pathology_test

import (
	"strings"
	"testing"

	"github.com/agentpcap/agentpcap/internal/pathology"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestPathology_PositiveDetections(t *testing.T) {
	eng := pathology.NewEngine()

	// 1. RETRY_STORM
	retryEvents := []apcap.Event{
		{ID: "e1", Operation: "fetch_quote", Status: apcap.StatusError},
		{ID: "e2", Operation: "fetch_quote", Status: apcap.StatusError},
	}
	findings := eng.Analyze(retryEvents)
	assertHasFinding(t, findings, "RETRY_STORM")

	// 2. LOOP (agent_a -> agent_b -> agent_a)
	loopEvents := []apcap.Event{
		{
			ID:          "e1",
			Type:        apcap.EventA2ARequest,
			Source:      apcap.Endpoint{Name: "agent_a"},
			Destination: apcap.Endpoint{Name: "agent_b"},
		},
		{
			ID:          "e2",
			Type:        apcap.EventA2ARequest,
			Source:      apcap.Endpoint{Name: "agent_b"},
			Destination: apcap.Endpoint{Name: "agent_a"},
		},
	}
	findings = eng.Analyze(loopEvents)
	assertHasFinding(t, findings, "LOOP")

	// 3. REPEATED_IDENTICAL_TOOL_CALL (>=3 times)
	dupToolEvents := []apcap.Event{
		{ID: "t1", Protocol: apcap.ProtocolTool, Attributes: map[string]any{"tool.name": "search", "tool.args_hash": "h1"}},
		{ID: "t2", Protocol: apcap.ProtocolTool, Attributes: map[string]any{"tool.name": "search", "tool.args_hash": "h1"}},
		{ID: "t3", Protocol: apcap.ProtocolTool, Attributes: map[string]any{"tool.name": "search", "tool.args_hash": "h1"}},
	}
	findings = eng.Analyze(dupToolEvents)
	assertHasFinding(t, findings, "REPEATED_IDENTICAL_TOOL_CALL")

	// 4. DUPLICATE_DISCOVERY (>=2 times)
	dupDiscEvents := []apcap.Event{
		{ID: "d1", Type: apcap.EventMCPToolsList, Destination: apcap.Endpoint{Name: "mcp-server"}},
		{ID: "d2", Type: apcap.EventMCPToolsList, Destination: apcap.Endpoint{Name: "mcp-server"}},
	}
	findings = eng.Analyze(dupDiscEvents)
	assertHasFinding(t, findings, "DUPLICATE_DISCOVERY")

	// 5. UNBOUNDED_OR_DEEP_DELEGATION (depth >= 3)
	deepDelegEvents := []apcap.Event{
		{ID: "dd1", Type: apcap.EventDelegation, Attributes: map[string]any{"a2a.delegation_depth": 4}},
	}
	findings = eng.Analyze(deepDelegEvents)
	assertHasFinding(t, findings, "UNBOUNDED_OR_DEEP_DELEGATION")

	// 6. TOKEN_SPIKE (single op > 65% of total when total >= 1000)
	tokenSpikeEvents := []apcap.Event{
		{ID: "sp1", Protocol: apcap.ProtocolModel, Operation: "chat_giant", Destination: apcap.Endpoint{Name: "gpt-4"}, Tokens: &apcap.TokenUsage{TotalTokens: 10000}},
		{ID: "sp2", Protocol: apcap.ProtocolModel, Operation: "chat_tiny", Destination: apcap.Endpoint{Name: "gpt-4"}, Tokens: &apcap.TokenUsage{TotalTokens: 500}},
	}
	findings = eng.Analyze(tokenSpikeEvents)
	assertHasFinding(t, findings, "TOKEN_SPIKE")

	// 7. SLOW_TOOL (duration > 4000ms)
	slowToolEvents := []apcap.Event{
		{ID: "st1", Protocol: apcap.ProtocolTool, Destination: apcap.Endpoint{Name: "scraper"}, DurationMs: 4500.0},
	}
	findings = eng.Analyze(slowToolEvents)
	assertHasFinding(t, findings, "SLOW_TOOL")

	// 8. MODEL_FALLBACK
	fallbackEvents := []apcap.Event{
		{ID: "m1", Protocol: apcap.ProtocolModel, Destination: apcap.Endpoint{Name: "primary-model"}, Status: apcap.StatusError},
		{ID: "m2", Protocol: apcap.ProtocolModel, Destination: apcap.Endpoint{Name: "backup-model"}, Status: apcap.StatusOK},
	}
	findings = eng.Analyze(fallbackEvents)
	assertHasFinding(t, findings, "MODEL_FALLBACK")
}

func TestPathology_FalsePositiveResistance(t *testing.T) {
	eng := pathology.NewEngine()

	// Normal healthy multi-agent execution
	cleanEvents := []apcap.Event{
		// Distinct tool calls with different arguments (under 4000ms, not identical)
		{ID: "c1", Protocol: apcap.ProtocolTool, Destination: apcap.Endpoint{Name: "tool-a"}, Attributes: map[string]any{"tool.name": "search", "tool.args_hash": "query_1"}, DurationMs: 150.0},
		// Model call in between (breaks consecutive tool run)
		{ID: "c2", Protocol: apcap.ProtocolModel, Operation: "gen1", Destination: apcap.Endpoint{Name: "gemini"}, Tokens: &apcap.TokenUsage{TotalTokens: 400}, DurationMs: 650.0},
		// Second tool call
		{ID: "c3", Protocol: apcap.ProtocolTool, Destination: apcap.Endpoint{Name: "tool-b"}, Attributes: map[string]any{"tool.name": "search", "tool.args_hash": "query_2"}, DurationMs: 180.0},
		// Single error followed by immediate success on different op (no storm)
		{ID: "c4", Operation: "fetch_rate", Status: apcap.StatusError, DurationMs: 50.0},
		{ID: "c5", Operation: "fetch_cached_rate", Status: apcap.StatusOK, DurationMs: 20.0},
		// Hierarchical delegation A -> B -> C (depth under 3)
		{ID: "c6", Type: apcap.EventDelegation, Source: apcap.Endpoint{Name: "orch"}, Destination: apcap.Endpoint{Name: "worker_1"}, Attributes: map[string]any{"a2a.delegation_depth": 1}},
		{ID: "c7", Type: apcap.EventDelegation, Source: apcap.Endpoint{Name: "worker_1"}, Destination: apcap.Endpoint{Name: "sub_worker"}, Attributes: map[string]any{"a2a.delegation_depth": 2}},
		// Balanced token usage: 400 + 400 + 400 = 1200 (no single op > 65%)
		{ID: "c8", Protocol: apcap.ProtocolModel, Operation: "gen2", Destination: apcap.Endpoint{Name: "gemini"}, Tokens: &apcap.TokenUsage{TotalTokens: 400}, DurationMs: 600.0},
		{ID: "c9", Protocol: apcap.ProtocolModel, Operation: "gen3", Destination: apcap.Endpoint{Name: "gemini"}, Tokens: &apcap.TokenUsage{TotalTokens: 400}, DurationMs: 580.0},
		// Single discovery per server
		{ID: "c10", Type: apcap.EventMCPToolsList, Destination: apcap.Endpoint{Name: "server-1"}},
		{ID: "c11", Type: apcap.EventMCPToolsList, Destination: apcap.Endpoint{Name: "server-2"}},
	}

	findings := eng.Analyze(cleanEvents)
	if len(findings) != 0 {
		var types []string
		for _, f := range findings {
			types = append(types, f.Type)
		}
		t.Fatalf("expected 0 findings for normal healthy workflow, got %d: %v", len(findings), types)
	}
}

func TestPathology_FormatTerminal(t *testing.T) {
	findings := []pathology.Finding{
		{
			Type:         "RETRY_STORM",
			Severity:     pathology.SeverityHigh,
			Confidence:   pathology.ConfidenceHigh,
			Title:        "Retry storm on query",
			Explanation:  "3 failures observed",
			EventIDs:     []string{"e1", "e2"},
			SuggestedFix: "Add backoff",
		},
	}

	out := pathology.FormatTerminal(findings)
	if !strings.Contains(out, "RUNTIME PATHOLOGIES DETECTED") {
		t.Errorf("expected header in terminal output: %s", out)
	}
	if !strings.Contains(out, "Retry storm on query") {
		t.Errorf("expected title in terminal output: %s", out)
	}
}

func assertHasFinding(t *testing.T, findings []pathology.Finding, findingType string) {
	t.Helper()
	for _, f := range findings {
		if f.Type == findingType {
			return
		}
	}
	t.Errorf("expected finding of type %q, got findings: %+v", findingType, findings)
}
