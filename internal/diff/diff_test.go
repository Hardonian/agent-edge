package diff_test

import (
	"strings"
	"testing"
	"time"

	"github.com/agentpcap/agentpcap/internal/diff"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

func TestDiff_IdenticalCaptures(t *testing.T) {
	now := time.Now().UTC()
	capA := &apcap.Capture{
		Manifest: apcap.Manifest{CaptureID: "cap_a"},
		Metadata: apcap.CaptureMetadata{
			TotalDurationMs: 1000.0,
			TotalTokens:     apcap.TokenUsage{TotalTokens: 500},
			TotalCost:       0.015,
			ErrorCount:      0,
		},
		Events: []apcap.Event{
			{
				ID:         "e1",
				Timestamp:  now,
				DurationMs: 100.0,
				Protocol:   apcap.ProtocolModel,
				Operation:  "chat",
				Status:     apcap.StatusOK,
			},
		},
	}

	capB := &apcap.Capture{
		Manifest: apcap.Manifest{CaptureID: "cap_b"},
		Metadata: apcap.CaptureMetadata{
			TotalDurationMs: 1000.0,
			TotalTokens:     apcap.TokenUsage{TotalTokens: 500},
			TotalCost:       0.015,
			ErrorCount:      0,
		},
		Events: []apcap.Event{
			{
				ID:         "e1",
				Timestamp:  now,
				DurationMs: 100.0,
				Protocol:   apcap.ProtocolModel,
				Operation:  "chat",
				Status:     apcap.StatusOK,
			},
		},
	}

	res := diff.Compare(capA, capB)
	if res.LatencyMs.Delta != 0 || res.LatencyMs.Pct != 0 {
		t.Errorf("expected zero latency delta, got delta=%f pct=%f", res.LatencyMs.Delta, res.LatencyMs.Pct)
	}
	if res.Tokens.Delta != 0 || res.Cost.Delta != 0 {
		t.Errorf("expected zero token/cost delta")
	}
	if len(res.ResolvedPathologies) != 0 || len(res.IntroducedPathologies) != 0 {
		t.Errorf("expected zero pathology deltas")
	}
	if len(res.ChangedOps) != 0 {
		t.Errorf("expected zero changed operations")
	}
}

func TestDiff_ImprovementAndRegression(t *testing.T) {
	now := time.Now().UTC()

	// Capture A had retry storm and 3 errors
	capA := &apcap.Capture{
		Manifest: apcap.Manifest{CaptureID: "baseline"},
		Metadata: apcap.CaptureMetadata{
			TotalDurationMs: 5000.0,
			TotalTokens:     apcap.TokenUsage{TotalTokens: 2000},
			TotalCost:       0.05,
			ErrorCount:      2,
		},
		Events: []apcap.Event{
			{
				ID:        "e1",
				Operation: "tools/call",
				Protocol:  apcap.ProtocolMCP,
				Status:    apcap.StatusError,
				Timestamp: now,
			},
			{
				ID:        "e2",
				Operation: "tools/call",
				Protocol:  apcap.ProtocolMCP,
				Type:      apcap.EventRetry,
				Status:    apcap.StatusError,
				Timestamp: now.Add(100 * time.Millisecond),
			},
			{
				ID:        "e3",
				Operation: "chat",
				Protocol:  apcap.ProtocolModel,
				Status:    apcap.StatusOK,
				Timestamp: now.Add(200 * time.Millisecond),
			},
		},
	}

	// Capture B eliminated retries, reduced duration and tokens
	capB := &apcap.Capture{
		Manifest: apcap.Manifest{CaptureID: "candidate"},
		Metadata: apcap.CaptureMetadata{
			TotalDurationMs: 2500.0,
			TotalTokens:     apcap.TokenUsage{TotalTokens: 1000},
			TotalCost:       0.025,
			ErrorCount:      0,
		},
		Events: []apcap.Event{
			{
				ID:        "e1_opt",
				Operation: "tools/call",
				Protocol:  apcap.ProtocolMCP,
				Status:    apcap.StatusOK,
				Timestamp: now,
			},
			{
				ID:        "e2_opt",
				Operation: "chat",
				Protocol:  apcap.ProtocolModel,
				Status:    apcap.StatusOK,
				Timestamp: now.Add(50 * time.Millisecond),
			},
		},
	}

	res := diff.Compare(capA, capB)

	// Verify duration reduced by 50%
	if res.LatencyMs.Delta != -2500.0 || res.LatencyMs.Pct != -50.0 {
		t.Errorf("expected -50%% duration delta, got delta=%f pct=%f", res.LatencyMs.Delta, res.LatencyMs.Pct)
	}
	// Verify tokens halved
	if res.Tokens.Delta != -1000.0 || res.Tokens.Pct != -50.0 {
		t.Errorf("expected -50%% tokens delta, got delta=%f pct=%f", res.Tokens.Delta, res.Tokens.Pct)
	}
	// Verify cost halved
	if res.Cost.Pct != -50.0 {
		t.Errorf("expected -50%% cost delta, got pct=%f", res.Cost.Pct)
	}
	// Verify RETRY_STORM resolved
	foundResolved := false
	for _, p := range res.ResolvedPathologies {
		if p == "RETRY_STORM" {
			foundResolved = true
			break
		}
	}
	if !foundResolved {
		t.Errorf("expected RETRY_STORM in resolved pathologies, got %v", res.ResolvedPathologies)
	}

	// Verify terminal formatting
	termOut := res.FormatTerminal()
	if !strings.Contains(termOut, "AGENT RUN DIFF") {
		t.Errorf("expected AGENT RUN DIFF in terminal output: %s", termOut)
	}
	if !strings.Contains(termOut, "-50.0%") {
		t.Errorf("expected -50.0%% in terminal output: %s", termOut)
	}

	// Verify JSON export
	jsonBytes, err := res.ToJSON()
	if err != nil {
		t.Fatalf("JSON export failed: %v", err)
	}
	if len(jsonBytes) == 0 {
		t.Fatal("empty JSON bytes")
	}
}
